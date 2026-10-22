package localapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ScanCapacity is derived from saved profile settings, including manual profiles.
// Deployment environment variables cannot silently override the console policy.
func (a *App) ScanCapacity() int {
	profiles, err := a.List("profiles")
	if err != nil {
		return 2
	}
	return profileScanCapacity(profiles)
}
func profileScanCapacity(profiles []json.RawMessage) int {
	total := 0
	for _, raw := range profiles {
		var p Profile
		if json.Unmarshal(raw, &p) == nil {
			total += min(defaultInt(p.SimultaneousScans, 2), 32)
		}
	}
	if total == 0 {
		return 2
	}
	return total
}

// Resize admission workers without cancelling active scans. Retiring workers exit
// between jobs; current per-profile admission limits also apply while they drain.
func (a *App) manageScanWorkers(ctx context.Context) {
	a.manageWorkers(ctx, "worker", a.ScanCapacity, func(ctx context.Context, name string, retire <-chan struct{}) { a.workerNamed(ctx, name, retire) })
}
func (a *App) manageWorkers(ctx context.Context, prefix string, capacity func() int, run func(context.Context, string, <-chan struct{})) {
	workers := map[int]chan struct{}{}
	next := 0
	resize := func() {
		target := capacity()
		for id, retire := range workers {
			if len(workers) <= target {
				break
			}
			close(retire)
			delete(workers, id)
		}
		for len(workers) < target && ctx.Err() == nil {
			id := next
			next++
			name := fmt.Sprintf("%s-%d", prefix, id)
			retire := make(chan struct{})
			workers[id] = retire
			a.beat(name)
			a.wg.Add(1)
			go func() { defer a.wg.Done(); defer a.stopBeat(name); run(ctx, name, retire) }()
		}
	}
	resize()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resize()
		}
	}
}

type ScanRequest struct {
	Identifier string
	Path       string
	Scanner    Scanner
	Profile    Profile
}
type ScanReply struct {
	Response []byte
	Error    string
}

func scanSubprocess(ctx context.Context, path string, s Scanner, p Profile) ([]byte, error) {
	executable, e := os.Executable()
	if e != nil {
		return nil, e
	}
	input, e := json.Marshal(ScanRequest{Path: path, Identifier: scanIdentifier(ctx, path), Scanner: s, Profile: p})
	if e != nil {
		return nil, e
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	defer reader.Close()
	cmd := exec.CommandContext(ctx, executable, "-scan")
	cmd.Stdin = strings.NewReader(string(input))
	cmd.ExtraFiles = []*os.File{writer}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 5 * time.Second
	if e = cmd.Start(); e != nil {
		writer.Close()
		return nil, e
	}
	writer.Close()
	var result ScanReply
	decodeErr := json.NewDecoder(io.LimitReader(reader, 16<<20)).Decode(&result)
	if decodeErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if waitErr != nil {
		return nil, fmt.Errorf("isolated scanner process failed")
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("invalid isolated scanner response")
	}
	if result.Error != "" {
		return result.Response, fmt.Errorf("%s", result.Error)
	}
	return result.Response, nil
}

// The API never starts workers. Its liveness stays available during engine recovery.
func (a *App) StartManagement() {
	a.healthMu.Lock()
	a.started = time.Now()
	a.heartbeats = map[string]time.Time{}
	a.healthMu.Unlock()
}
func EngineHealth(data string) map[string]any {
	b, e := os.ReadFile(filepath.Join(data, "engine-health.json"))
	v := map[string]any{}
	if e != nil || json.Unmarshal(b, &v) != nil {
		return map[string]any{"healthy": false, "message": "Processing engine starting or unavailable."}
	}
	at, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(v["observedAt"]))
	if time.Since(at) > 15*time.Second {
		v["healthy"] = false
		v["message"] = "Processing engine heartbeat is stale; watchdog recovery pending."
	}
	return v
}
func (a *App) PublishEngineHealth(ctx context.Context) {
	publish := func() {
		checks, healthy := a.liveStatus(ctx)
		b, _ := json.Marshal(map[string]any{"healthy": healthy, "checks": checks, "observedAt": stamp(), "pid": os.Getpid(), "workerLimit": a.ScanCapacity(), "transferWorkerLimit": a.TransferCapacity()})
		temp := filepath.Join(a.DataDir, "engine-health.next")
		if os.WriteFile(temp, b, 0600) == nil {
			_ = os.Rename(temp, filepath.Join(a.DataDir, "engine-health.json"))
		}
	}
	publish()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		}
	}
}
