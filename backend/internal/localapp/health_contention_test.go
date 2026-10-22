package localapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEngineHeartbeatDoesNotQueueBehindWriterConnection(t *testing.T) {
	a := testApp(t)
	if err := a.Save("profiles", "profile", Profile{ID: "profile", SimultaneousScans: 32, SimultaneousTransfers: 10}); err != nil {
		t.Fatal(err)
	}
	a.started = time.Now()
	a.beat("monitor")
	// Occupy the sole engine writer connection for longer than the assertion.
	conn, err := a.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.PublishEngineHealth(ctx); close(done) }()
	defer func() {
		cancel()
		conn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("heartbeat publisher did not stop")
		}
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(a.DataDir, "engine-health.json"))
		if err == nil {
			var h struct {
				Healthy       bool `json:"healthy"`
				WorkerLimit   int  `json:"workerLimit"`
				TransferLimit int  `json:"transferWorkerLimit"`
			}
			if err = json.Unmarshal(raw, &h); err != nil {
				t.Fatal(err)
			}
			if !h.Healthy || h.WorkerLimit != 32 || h.TransferLimit != 10 {
				t.Fatal(string(raw))
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("engine health blocked on the busy writer connection")
}

func TestIndependentHealthStillReportsFailedDatabaseProbe(t *testing.T) {
	a := testApp(t)
	reader, err := OpenReadOnly(a.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	a.started = time.Now()
	a.beat("monitor")
	reader.Close()
	checks, healthy := a.liveStatusWithDB(context.Background(), reader.DB)
	if healthy || checks["database"] != "unresponsive" {
		t.Fatal(checks, healthy)
	}
}
