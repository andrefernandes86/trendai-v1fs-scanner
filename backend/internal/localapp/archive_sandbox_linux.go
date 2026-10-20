package localapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Called only by the dedicated extraction child, before touching archive bytes.
// The parser goroutine stays on the Landlock-confined OS thread.
func archiveSandbox(r ExtractRequest) error {
	debug.SetMemoryLimit(128 << 20)
	if e := unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{Cur: 2 << 30, Max: 2 << 30}); e != nil {
		return e
	}
	if e := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 64, Max: 64}); e != nil {
		return e
	}
	if e := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: uint64(r.Options.MaxEntryBytes), Max: uint64(r.Options.MaxEntryBytes)}); e != nil {
		return e
	}
	if e := unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{Cur: uint64(r.Options.Seconds + 1), Max: uint64(r.Options.Seconds + 1)}); e != nil {
		return e
	}
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return e
	}
	// ABI 1 rights work on Linux 5.13+. Unsupported confinement is a hard failure.
	attr := unix.LandlockRulesetAttr{Handled_access_fs: 0x1fff}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), 8, 0)
	if errno != 0 {
		return fmt.Errorf("Landlock unavailable: %s", errno)
	}
	defer unix.Close(int(fd))
	for _, rule := range []struct {
		p      string
		rights uint64
	}{
		{r.Source, unix.LANDLOCK_ACCESS_FS_READ_FILE},
		{r.Workspace, unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE},
	} {
		p, e := unix.Open(rule.p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		entry := unix.LandlockPathBeneathAttr{Allowed_access: rule.rights, Parent_fd: int32(p)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&entry)), 0, 0, 0)
		unix.Close(p)
		if errno != 0 {
			return errno
		}
	}
	if _, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return errno
	}
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	} else if runtime.GOARCH != "amd64" {
		return fmt.Errorf("Unsupported archive sandbox architecture")
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS})
	for _, nr := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_EXECVE, unix.SYS_EXECVEAT} {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: nr, Jf: 1}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno = unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return errno
	}
	return nil
}
func RunArchiveChild() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	output := os.NewFile(3, "archive-result")
	if output == nil {
		return
	}
	defer output.Close()
	var r ExtractRequest
	result := ExtractManifest{}
	if json.NewDecoder(io.LimitReader(os.Stdin, 128<<10)).Decode(&r) != nil {
		result.Error = "Invalid extraction request"
		json.NewEncoder(output).Encode(result)
		return
	}
	r.Options = r.Options.Defaults()
	if e := r.Options.Validate(); e != nil {
		result.Error = e.Error()
		json.NewEncoder(output).Encode(result)
		return
	}
	if e := archiveSandbox(r); e != nil {
		result.Error = "Archive sandbox unavailable; extraction refused: " + e.Error()
		json.NewEncoder(output).Encode(result)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.Options.Seconds)*time.Second)
	defer cancel()
	result = ExtractArchive(ctx, r)
	json.NewEncoder(output).Encode(result)
}
