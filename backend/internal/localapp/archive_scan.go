package localapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
)

var errArchiveCapacity = errors.New("Archive workspace capacity unavailable; source retained")
var archiveAdmissions struct {
	sync.Mutex
	total    int
	profiles map[string]int
}

func archivePermit(ctx context.Context, profile string, limit int) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	archiveAdmissions.Lock()
	defer archiveAdmissions.Unlock()
	if archiveAdmissions.profiles == nil {
		archiveAdmissions.profiles = map[string]int{}
	}
	if archiveAdmissions.total >= 2 || archiveAdmissions.profiles[profile] >= limit {
		return nil, errArchiveCapacity
	}
	archiveAdmissions.total++
	archiveAdmissions.profiles[profile]++
	return func() {
		archiveAdmissions.Lock()
		defer archiveAdmissions.Unlock()
		archiveAdmissions.total--
		archiveAdmissions.profiles[profile]--
	}, nil
}

var extractArchiveProcess = launchArchiveHelper

func launchArchiveHelper(ctx context.Context, r ExtractRequest) ExtractManifest {
	executable, e := os.Executable()
	if e != nil {
		return ExtractManifest{Error: "Cannot locate archive helper"}
	}
	return launchArchiveHelperAt(ctx, r, executable)
}
func launchArchiveHelperAt(ctx context.Context, r ExtractRequest, executable string) ExtractManifest {
	result := ExtractManifest{}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.Options.Seconds)*time.Second)
	defer cancel()
	input, e := json.Marshal(r)
	if e != nil {
		result.Error = "Cannot encode extraction request"
		return result
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		result.Error = "Cannot create extraction pipe"
		return result
	}
	defer reader.Close()
	cmd := exec.CommandContext(ctx, executable, "-extract")
	cmd.Env = []string{"GOMEMLIMIT=128MiB", "TZ=UTC"}
	cmd.Stdin = strings.NewReader(string(input))
	cmd.ExtraFiles = []*os.File{writer}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 5 * time.Second
	if e = cmd.Start(); e != nil {
		writer.Close()
		result.Error = "Cannot start archive helper"
		return result
	}
	writer.Close()
	decodeErr := json.NewDecoder(io.LimitReader(reader, 8<<20)).Decode(&result)
	if decodeErr != nil {
		cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ExtractManifest{Error: "Archive extraction time limit exceeded or job cancelled"}
	}
	if decodeErr != nil || waitErr != nil {
		return ExtractManifest{Error: "Archive helper failed or exceeded process resource/evidence limits"}
	}
	return result
}

type ArchiveMemberResult struct {
	Reused   bool            `json:"reused,omitempty"`
	Name     string          `json:"name"`
	Depth    int             `json:"depth"`
	Size     int64           `json:"size"`
	SHA256   string          `json:"sha256,omitempty"`
	Verdict  string          `json:"verdict"`
	Error    string          `json:"error,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}
type ArchiveEvidence struct {
	Complete           bool                  `json:"complete"`
	ExtractionComplete bool                  `json:"extractionComplete"`
	Entries            int                   `json:"entries"`
	Bytes              int64                 `json:"expandedBytes"`
	Depth              int                   `json:"depth"`
	Error              string                `json:"error,omitempty"`
	Members            []ArchiveMemberResult `json:"members"`
	Limits             ArchiveOptions        `json:"limits"`
}

func archiveEnvelope(ev ArchiveEvidence, verdict string, policyBlocked bool, detections []Detection) []byte {
	scanResult := -1
	if verdict == "CLEAN" {
		scanResult = 0
	}
	if verdict == "MALICIOUS" {
		scanResult = 1
	}
	scannerCalls := 0
	for _, m := range ev.Members {
		if len(m.Response) > 0 && !m.Reused {
			scannerCalls++
		}
	}
	b, _ := json.Marshal(map[string]any{"scannerCalls": scannerCalls, "scanId": "archive-inspection", "scanType": "archive-inspection", "scanResult": scanResult, "archivePolicyBlocked": policyBlocked, "archiveInspection": ev, "foundMalwares": detections})
	return b
}

// The original and every extracted regular member (including nested containers)
// are required scans. Exclusions/size bypass rules never apply to members.
func (a *App) scanWithArchives(ctx context.Context, local, name string, s Scanner, p Profile, originalDigest string, prior ...*ArchiveEvidence) ([]byte, error) {
	ctx = WithScanIdentifier(ctx, name)
	if !p.Archive.Enabled {
		return a.Scan(ctx, local, s, p)
	}
	kind, e := archiveKind(local, name)
	if e != nil {
		return nil, e
	}
	if kind == "" {
		return a.Scan(ctx, local, s, p)
	}
	limits := p.Archive.Defaults()
	ev := ArchiveEvidence{Limits: limits, Members: []ArchiveMemberResult{}}
	release, e := archivePermit(ctx, p.ID, limits.Concurrency)
	if e != nil {
		return nil, e
	}
	defer release()
	releaseSpace, e := reserveCapture(filepath.Dir(local), limits.MaxBytes)
	if e != nil {
		return nil, errArchiveCapacity
	}
	defer releaseSpace()
	workspace, e := os.MkdirTemp(filepath.Dir(local), "archive-")
	if e != nil {
		return nil, errArchiveCapacity
	}
	defer os.RemoveAll(workspace)
	manifest := extractArchiveProcess(ctx, ExtractRequest{Source: local, Name: name, Workspace: workspace, Options: limits})
	ev.ExtractionComplete = manifest.Complete
	ev.Entries = manifest.Count
	ev.Bytes = manifest.Bytes
	ev.Depth = manifest.Depth
	if !manifest.Complete {
		ev.Error = manifest.Error
		return archiveEnvelope(ev, "UNKNOWN", true, nil), nil
	}
	st, statErr := os.Stat(local)
	if statErr != nil {
		return nil, statErr
	}
	entries := append([]ArchiveEntry{{Name: name, Path: local, Size: st.Size(), SHA256: originalDigest}}, manifest.Entries...)
	reusable := map[string]ArchiveMemberResult{}
	if len(prior) > 0 && prior[0] != nil {
		for _, member := range prior[0].Members {
			v := core.Normalize(member.Response)
			if member.SHA256 != "" && (v == "CLEAN" || v == "MALICIOUS") && member.Verdict == v {
				reusable[member.Name+"\x00"+member.SHA256] = member
			}
		}
	}
	verdict := "CLEAN"
	detections := []Detection{}
	responseBytes := 0
	for _, entry := range entries {
		member := ArchiveMemberResult{Name: entry.Name, Depth: entry.Depth, Size: entry.Size, SHA256: entry.SHA256}
		if e = ctx.Err(); e != nil {
			member.Error = "Archive scan job deadline exceeded"
			member.Verdict = "UNKNOWN"
			ev.Members = append(ev.Members, member)
			if verdict != "MALICIOUS" {
				verdict = "UNKNOWN"
			}
			break
		}
		// Never trust child-reported paths to read outside the private workspace.
		if entry.Path != local && (filepath.Dir(entry.Path) != workspace || !strings.HasPrefix(filepath.Base(entry.Path), "member-")) {
			return nil, fmt.Errorf("Invalid extraction manifest path")
		}
		var raw []byte
		var scanErr error
		if cached, ok := reusable[entry.Name+"\x00"+entry.SHA256]; ok {
			raw = cached.Response
			member.Reused = true
		} else {
			raw, scanErr = a.Scan(WithScanIdentifier(ctx, entry.Name), entry.Path, s, p)
		}
		member.Verdict = core.Normalize(raw)
		if scanErr != nil {
			member.Verdict = "UNKNOWN"
			member.Error = redactString(scanErr.Error(), s.APIKey)
		}
		if json.Valid(raw) {
			member.Response = raw
		}
		responseBytes += len(raw) + len(entry.Name) + 512
		if member.Verdict == "MALICIOUS" {
			verdict = "MALICIOUS"
		} else if member.Verdict != "CLEAN" && verdict != "MALICIOUS" {
			verdict = "UNKNOWN"
		}
		for _, d := range extractDetections(raw) {
			d.File = entry.Name
			detections = append(detections, d)
		}
		if responseBytes > 6<<20 {
			member.Response = nil
			member.Error = "Archive result evidence limit exceeded"
			member.Verdict = "UNKNOWN"
			if verdict != "MALICIOUS" {
				verdict = "UNKNOWN"
			}
			ev.Members = append(ev.Members, member)
			break
		}
		ev.Members = append(ev.Members, member)
	}
	ev.Complete = len(ev.Members) == len(entries)
	for _, m := range ev.Members {
		if m.Verdict == "UNKNOWN" {
			ev.Complete = false
		}
	}
	if !ev.Complete {
		ev.Error = "Required archive scans did not all finish successfully"
		if verdict != "MALICIOUS" {
			verdict = "UNKNOWN"
		}
	}
	return archiveEnvelope(ev, verdict, false, detections), nil
}
