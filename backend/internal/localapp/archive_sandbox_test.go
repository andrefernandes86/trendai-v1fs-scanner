package localapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestArchiveSandboxChild(t *testing.T) {
	if os.Getenv("V1FS_SANDBOX_CHILD") != "1" {
		return
	}
	runtime.LockOSThread()
	var r ExtractRequest
	json.NewDecoder(os.Stdin).Decode(&r)
	r.Options = r.Options.Defaults()
	fail := func(e any) { fmt.Fprintln(os.Stderr, e); os.Exit(2) }
	if e := archiveSandbox(r); e != nil {
		fail(e)
	}
	if _, e := os.ReadFile(r.Source); e != nil {
		fail("source read denied")
	}
	if e := os.WriteFile(filepath.Join(r.Workspace, "allowed"), []byte("ok"), 0600); e != nil {
		fail("workspace write denied")
	}
	if _, e := os.ReadFile(filepath.Join(filepath.Dir(r.Source), "secret")); e == nil {
		fail("outside read escaped confinement")
	}
	if e := os.WriteFile(filepath.Join(filepath.Dir(r.Source), "escaped"), []byte("x"), 0600); e == nil {
		fail("outside write escaped confinement")
	}
	if fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); e == nil {
		unix.Close(fd)
		fail("network socket escaped confinement")
	}
	os.Exit(0)
}
func TestArchiveSandboxFilesystemAndNetwork(t *testing.T) {
	if archiveRaceBuild {
		t.Skip("resource-limited subprocess tested with non-race executable; race runtime requires a much larger address space")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "input")
	os.WriteFile(source, []byte("input"), 0600)
	os.WriteFile(filepath.Join(dir, "secret"), []byte("sensitive"), 0600)
	workspace := filepath.Join(dir, "workspace")
	os.Mkdir(workspace, 0700)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	request, _ := json.Marshal(ExtractRequest{Source: source, Workspace: workspace})
	cmd := exec.Command(exe, "-test.run=^TestArchiveSandboxChild$")
	cmd.Env = []string{"V1FS_SANDBOX_CHILD=1"}
	cmd.Stdin = bytes.NewReader(request)
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("sandbox enforcement failed: %v %s", e, output)
	}
}
