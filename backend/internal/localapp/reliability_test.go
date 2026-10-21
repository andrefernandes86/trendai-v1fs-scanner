package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesAndChecksums(t *testing.T) {
	p := Profile{Rules: []FileRule{{ID: "skip", Pattern: "**/*.png", Action: "exclude"}, {ID: "blocked", Pattern: "private/**", Action: "hold"}}, IgnorePatterns: "*.part"}
	for _, tc := range []struct{ key, action string }{{"images/a.png", "exclude"}, {"private/a.png", "hold"}, {"upload.part", "ignore"}, {"photo.PNG", "scan"}} {
		a, _ := p.FilePolicy(tc.key, 100)
		if a != tc.action {
			t.Fatalf("%s -> %s", tc.key, a)
		}
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, []byte("123456789"), 0600)
	_, crc, n, e := checksums(f)
	if e != nil || crc != "e3069283" || n != 9 {
		t.Fatalf("CRC32C %s %d %v", crc, n, e)
	}
	p.Rules = append(p.Rules, FileRule{ID: "skip", Pattern: "*", Action: "exclude"})
	if p.ReliabilityValidate() == nil {
		t.Fatal("duplicate rule ID accepted")
	}
}
func reliabilityFixture(t *testing.T) (*App, Snapshot, map[string]*diskShare) {
	a := testApp(t)
	stores := map[string]*diskShare{}
	for _, id := range []string{"source", "good", "bad", "failed"} {
		stores[id] = &diskShare{root: t.TempDir()}
	}
	original := remoteOpen
	remoteOpen = func(_ context.Context, m Mount) (remoteFS, error) {
		f := stores[m.ID]
		if f == nil {
			return nil, errors.New("unexpected root")
		}
		return f, nil
	}
	t.Cleanup(func() { remoteOpen = original })
	s := Snapshot{Source: Mount{ID: "source", Kind: "smb", Server: "nas", Share: "source"}, Good: Mount{ID: "good", Kind: "smb", Server: "nas", Share: "good"}, Bad: Mount{ID: "bad", Kind: "smb", Server: "nas", Share: "bad"}, Failed: Mount{ID: "failed", Kind: "smb", Server: "nas", Share: "failed"}, Profile: Profile{ID: "p", Name: "Policy", ControlledWriter: true, ScanAttempts: 1}, Key: "photo.png", Size: 9}
	os.WriteFile(stores["source"].p(s.Key), []byte("123456789"), 0600)
	v, _ := stores["source"].Stat(s.Key)
	s.ETag = infoTag(v)
	return a, s, stores
}
func TestExcludedFileStillRequiresVerifiedMove(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.Rules = []FileRule{{ID: "images", Pattern: "*.png", Action: "exclude"}}
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		t.Fatal("exclusion called scanner")
		return nil, nil
	}
	id, e := a.insertJob(s)
	if e != nil {
		t.Fatal(e)
	}
	_, snap, n, _ := a.claim()
	a.process(context.Background(), id, snap, n)
	var state, verdict, destination string
	a.DB.QueryRow("SELECT state,verdict,destination FROM jobs WHERE id=?", id).Scan(&state, &verdict, &destination)
	if state != "COMPLETED" || verdict != "EXCLUDED" || !strings.Contains(destination, "good") {
		t.Fatalf("%s %s %s", state, verdict, destination)
	}
	m, e := a.loadMove(id)
	if e != nil || m.Rule != "images" || m.CRC32C != "e3069283" || m.Phase != "COMPLETED" {
		t.Fatalf("%+v %v", publicMove(m), e)
	}
	if _, e = stores["source"].Stat(s.Key); !os.IsNotExist(e) {
		t.Fatal("source not moved")
	}
	var scans int
	a.DB.QueryRow("SELECT count(*) FROM scan_results WHERE job_id=?", id).Scan(&scans)
	if scans != 0 {
		t.Fatal("excluded file counted as scanned")
	}
}
func TestCrashRecoveryAfterSourceRemovalDoesNotRescan(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.ControlledWriter = false
	calls := 0
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		calls++
		return []byte(`{"scanId":"x","scanResult":0}`), nil
	}
	id, _ := a.insertJob(s)
	_, snap, n, _ := a.claim()
	a.process(context.Background(), id, snap, n)
	move, e := a.loadMove(id)
	if e != nil || move.Phase != "DESTINATION_VERIFIED" {
		t.Fatal(move.Phase, e)
	}
	// Simulate an operator establishing handoff and a crash after unlink but before final DB commit.
	stores["source"].Remove(s.Key)
	snap.Profile.ControlledWriter = true
	a.process(context.Background(), id, snap, n+1)
	var state string
	a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
	if state != "COMPLETED" || calls != 1 {
		t.Fatalf("state=%s scanner calls=%d", state, calls)
	}
}
func TestCorruptedDestinationPreventsSourceDeletion(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.ControlledWriter = false
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"x","scanResult":0}`), nil
	}
	id, _ := a.insertJob(s)
	_, snap, n, _ := a.claim()
	a.process(context.Background(), id, snap, n)
	m, _ := a.loadMove(id)
	os.WriteFile(stores["good"].p(m.Key), []byte("corrupted"), 0600)
	snap.Profile.ControlledWriter = true
	a.process(context.Background(), id, snap, n+1)
	claim, _ := a.loadClaim(id)
	if _, e := stores["source"].Stat(claim.Key); e != nil {
		t.Fatal("claimed source deleted despite corruption")
	}
	var state, dest string
	a.DB.QueryRow("SELECT state,destination FROM jobs WHERE id=?", id).Scan(&state, &dest)
	if state != "RETRY_PENDING" || dest == "" {
		t.Fatalf("state=%s destination=%s", state, dest)
	}
}
func TestRetryBudgetsIndependentAndPermanentExceptions(t *testing.T) {
	a := testApp(t)
	p := Profile{ScanAttempts: 2, TransferAttempts: 3, DeleteAttempts: 4}
	s := Snapshot{Source: Mount{ID: "source", Kind: "smb", Server: "nas", Share: "source"}, Profile: p, Key: "x"}
	id, _ := a.insertJob(s)
	a.retryStage(id, "scan", p, "UNKNOWN", "", "", "scan")
	a.retryStage(id, "transfer", p, "CLEAN", "hash", "destination", "transfer")
	var scan, copy int
	a.DB.QueryRow("SELECT attempts FROM stage_attempts WHERE job_id=? AND stage='scan'", id).Scan(&scan)
	a.DB.QueryRow("SELECT attempts FROM stage_attempts WHERE job_id=? AND stage='transfer'", id).Scan(&copy)
	if scan != 1 || copy != 1 {
		t.Fatal(scan, copy)
	}
	if scanException([]byte(`{"foundErrors":[{"description":"password protected archive"}]}`)) != "permanent" {
		t.Fatal("encrypted archive not permanent")
	}
	if scanException([]byte(`{"foundErrors":[{"description":"service unavailable"}]}`)) != "transient" {
		t.Fatal("outage not retryable")
	}
}
func TestChecksumMismatchSourceNotRemoved(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	sum := sha256.Sum256([]byte("123456789"))
	digest := hex.EncodeToString(sum[:])
	os.WriteFile(stores["source"].p(s.Key), []byte("changed!!"), 0600)
	if e := a.removeVerifiedSource(context.Background(), s, digest); e == nil {
		t.Fatal("changed source deleted")
	}
	if _, e := stores["source"].Stat(s.Key); e != nil {
		t.Fatal(e)
	}
}
func TestUnknownScanRetriesBeforeIsolation(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.ScanAttempts = 2
	calls := 0
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		calls++
		return []byte(`{"scanId":"x","scanResult":-1}`), nil
	}
	id, _ := a.insertJob(s)
	_, snap, n, _ := a.claim()
	a.process(context.Background(), id, snap, n)
	var state string
	a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
	if state != "RETRY_PENDING" {
		t.Fatal(state)
	}
	claim, _ := a.loadClaim(id)
	if _, e := stores["source"].Stat(claim.Key); e != nil {
		t.Fatal("claimed source lost before scan retry exhaustion")
	}
	a.process(context.Background(), id, snap, n+1)
	a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
	if state != "HELD" || calls != 2 {
		t.Fatal(state, calls)
	}
	m, e := a.loadMove(id)
	if e != nil || m.Target.ID != "failed" || m.Phase != "COMPLETED" {
		t.Fatal(m.Phase, e)
	}
	if _, e := stores["source"].Stat(s.Key); !os.IsNotExist(e) {
		t.Fatal("isolated bytes not moved after verification")
	}
}
func TestRecoveryCreatesNewHistoryAndEnrichmentPreservesVerdict(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.RecoveryAttempts = 2
	s.Profile.RecoveryEnabled = true
	for _, m := range []Mount{s.Source, s.Good, s.Bad, s.Failed} {
		_ = a.Save("mounts", m.ID, m)
	}
	_ = a.Save("profiles", s.Profile.ID, s.Profile)
	_ = a.Save("scanner", "default", Scanner{Type: "local", Address: "scanner:50051"})
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"x","foundErrors":[{"description":"unsupported format"}]}`), nil
	}
	parent, _ := a.insertJob(s)
	_, snap, n, _ := a.claim()
	a.process(context.Background(), parent, snap, n)
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"new","scanResult":0}`), nil
	}
	child, e := a.recoverJob(context.Background(), parent, false)
	if e != nil || child == parent {
		t.Fatal(child, e)
	}
	id, recovered, attempt, e := a.claim()
	if e != nil || id != child {
		t.Fatal(id, e)
	}
	a.process(context.Background(), id, recovered, attempt)
	var state, verdict string
	a.DB.QueryRow("SELECT state,verdict FROM jobs WHERE id=?", child).Scan(&state, &verdict)
	if state != "COMPLETED" || verdict != "CLEAN" {
		t.Fatal(state, verdict)
	}
	a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", parent).Scan(&state)
	if state != "RECOVERED" {
		t.Fatal(state)
	}
	if _, e = a.recoverJob(context.Background(), child, true); e != nil {
		t.Fatal(e)
	}
	a.DB.QueryRow("SELECT verdict FROM jobs WHERE id=?", parent).Scan(&verdict)
	if verdict != "UNKNOWN" {
		t.Fatal("historical verdict rewritten")
	}
}
func TestInventoryTracksVersionsAndExplicitlyIgnoredFiles(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	p := s.Profile
	p.SourceMount = "source"
	p.GoodMount = "good"
	p.BadMount = "bad"
	p.FailedMount = "failed"
	p.IgnorePatterns = "*.part"
	_ = a.Save("profiles", p.ID, p)
	for _, m := range []Mount{s.Source, s.Good, s.Bad, s.Failed} {
		_ = a.Save("mounts", m.ID, m)
	}
	_ = a.Save("scanner", "default", Scanner{Type: "local", Address: "scanner:50051"})
	os.WriteFile(stores["source"].p("upload.part"), nil, 0600)
	a.monitorProfile(context.Background(), p)
	os.WriteFile(stores["source"].p(s.Key), []byte("new version bytes"), 0600)
	a.monitorProfile(context.Background(), p)
	var n int
	a.DB.QueryRow("SELECT count(*) FROM inventory WHERE key=?", s.Key).Scan(&n)
	if n != 2 {
		t.Fatal("source versions lost", n)
	}
	var status string
	a.DB.QueryRow("SELECT status FROM inventory WHERE key='upload.part'").Scan(&status)
	if status != "IGNORE" {
		t.Fatal(status)
	}
}

func TestDestinationVerificationProfileModes(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	os.WriteFile(stores["good"].p("result"), []byte("123456789"), 0600)
	m := MoveRecord{Target: s.Good, Key: "result", Size: 9, Digest: "wrong", CRC32C: "wrong"}
	if err := a.verifyDestination(context.Background(), &m); err == nil {
		t.Fatal("default mode accepted mismatched contents")
	}
	m.SkipDestinationVerification = true
	if err := a.verifyDestination(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	if m.VerifiedAt != "" || m.DestinationETag == "" {
		t.Fatal("fast mode misreported content verification")
	}
	m.Size = 10
	if err := a.verifyDestination(context.Background(), &m); err == nil {
		t.Fatal("fast mode accepted incorrect size")
	}
	m.Size = 9
	m.DestinationETag = "changed"
	if err := a.verifyDestination(context.Background(), &m); err == nil {
		t.Fatal("fast mode accepted changed identity")
	}
}
