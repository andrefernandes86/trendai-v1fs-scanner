package localapp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTenSmallTransfersUseLiveProfileLimit(t *testing.T) {
	t.Setenv("V1FS_TRANSFER_WORKERS", "4")
	a, s, _ := reliabilityFixture(t)
	s.Profile.SimultaneousTransfers = 2
	_ = a.Save("profiles", s.Profile.ID, s.Profile)
	for i := 0; i < 11; i++ {
		s.Key = fmt.Sprintf("small-%d", i)
		id, e := a.insertJob(s)
		if e != nil {
			t.Fatal(e)
		}
		if e = a.enqueueTransfer(id, s, "unused", "hash", "CLEAN", "", ""); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 2; i++ {
		if _, _, e := a.claimTransfer(); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, e := a.claimTransfer(); e == nil {
		t.Fatal("exceeded original limit")
	}
	p := s.Profile
	p.SimultaneousTransfers = 10
	if e := p.ReliabilityValidate(); e != nil {
		t.Fatal(e)
	}
	_ = a.Save("profiles", p.ID, p)
	if a.TransferCapacity() != 10 {
		t.Fatal(a.TransferCapacity())
	}
	for i := 2; i < 10; i++ {
		if _, _, e := a.claimTransfer(); e != nil {
			t.Fatalf("only %d transfers admitted: %v", i, e)
		}
	}
	if _, _, e := a.claimTransfer(); e == nil {
		t.Fatal("exceeded ten")
	}
	p.SimultaneousTransfers = 11
	if p.ReliabilityValidate() == nil {
		t.Fatal("accepted eleven")
	}
}
func TestLargeTransferThresholdStillAppliesAtTen(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.SimultaneousTransfers = 10
	s.Profile.LargeFileTransfers = 1
	_ = a.Save("profiles", s.Profile.ID, s.Profile)
	for i, size := range []int64{1000000000, 1000000000, 999999999} {
		s.Key = fmt.Sprint(i)
		s.Size = size
		id, _ := a.insertJob(s)
		_ = a.enqueueTransfer(id, s, "unused", "hash", "CLEAN", "", "")
	}
	if _, task, e := a.claimTransfer(); e != nil || task.Snapshot.Size != 1000000000 {
		t.Fatal(e)
	}
	if _, task, e := a.claimTransfer(); e != nil || task.Snapshot.Size != 999999999 {
		t.Fatal("large file blocked small delivery", e)
	}
	if _, _, e := a.claimTransfer(); e == nil {
		t.Fatal("second large transfer admitted")
	}
}
func TestTransferWorkersGrowToTen(t *testing.T) {
	a := testApp(t)
	p := Profile{ID: "p", SimultaneousTransfers: 10}
	_ = a.Save("profiles", p.ID, p)
	ctx, cancel := context.WithCancel(context.Background())
	a.wg.Add(1)
	go func() { defer a.wg.Done(); a.manageTransferWorkers(ctx) }()
	defer func() { cancel(); a.wg.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.healthMu.Lock()
		count := 0
		for k := range a.heartbeats {
			if strings.HasPrefix(k, "transfer-") {
				count++
			}
		}
		a.healthMu.Unlock()
		if count == 10 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("pool failed to grow to ten")
}
func TestReadbackOffDoesNotRequestDestinationContent(t *testing.T) {
	a := testApp(t)
	requests := 0
	storageTransport = tagsTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "HEAD" {
			t.Fatalf("unexpected content request %s", r.Method)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"v1"`}, "Content-Length": []string{"404"}}, ContentLength: 404, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	defer func() { storageTransport = nil }()
	m := MoveRecord{Target: testMount("destination", "clean"), Key: "file", Size: 404, SkipDestinationVerification: true, Digest: "source-sha", CRC32C: "source-crc"}
	if e := a.verifyDestination(context.Background(), &m); e != nil {
		t.Fatal(e)
	}
	if requests != 1 || m.VerifiedAt != "" || m.DestinationETag == "" {
		t.Fatal("incorrect fast-check evidence", requests, m)
	}
}
