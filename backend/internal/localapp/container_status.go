package localapp

import (
	"context"
	"crypto/tls"
	"fmt"
	client "github.com/trendmicro/tm-v1-fs-golang-sdk"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func numberFile(path string) uint64 {
	b, _ := os.ReadFile(path)
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}
func quotaCPUs(raw string, available float64) float64 {
	fields := strings.Fields(raw)
	if len(fields) != 2 || fields[0] == "max" {
		return available
	}
	quota, e1 := strconv.ParseFloat(fields[0], 64)
	period, e2 := strconv.ParseFloat(fields[1], 64)
	if e1 == nil && e2 == nil && quota > 0 && period > 0 {
		return min(available, quota/period)
	}
	return available
}
func containerResources(data string) map[string]any {
	cpus := float64(runtime.NumCPU())
	raw, _ := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if len(raw) > 0 {
		cpus = quotaCPUs(string(raw), cpus)
	} else {
		quota, _ := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
		period, _ := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
		cpus = quotaCPUs(string(quota)+" "+string(period), cpus)
	}
	used := numberFile("/sys/fs/cgroup/memory.current")
	limit := numberFile("/sys/fs/cgroup/memory.max")
	if used == 0 {
		used = numberFile("/sys/fs/cgroup/memory/memory.usage_in_bytes")
		limit = numberFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	}
	if limit > 1<<60 {
		limit = 0
	}
	hostTotal, hostAvailable := uint64(0), uint64(0)
	if info, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(info), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			n, _ := strconv.ParseUint(fields[1], 10, 64)
			if fields[0] == "MemTotal:" {
				hostTotal = n * 1024
			}
			if fields[0] == "MemAvailable:" {
				hostAvailable = n * 1024
			}
		}
	}
	total := hostTotal
	if limit > 0 && (total == 0 || limit < total) {
		total = limit
	}
	available := hostAvailable
	if total > used {
		available = min(available, total-used)
	} else {
		available = 0
	}
	result := map[string]any{"cpuCores": cpus, "memoryUsedBytes": used, "memoryLimitBytes": limit, "memoryTotalBytes": total, "memoryAvailableBytes": available, "hostMemoryTotalBytes": hostTotal, "hostMemoryAvailableBytes": hostAvailable, "diskScope": "Data-volume filesystem; shared with other files on that filesystem."}
	var disk syscall.Statfs_t
	if syscall.Statfs(data, &disk) == nil && disk.Blocks > 0 {
		result["diskTotalBytes"] = disk.Blocks * uint64(disk.Bsize)
		result["diskUsedBytes"] = (disk.Blocks - disk.Bfree) * uint64(disk.Bsize)
	}
	return result
}
func (a *App) scannerConnection(ctx context.Context) map[string]any {
	var s Scanner
	if a.Get("scanner", "default", &s) != nil || s.Validate() != nil {
		return map[string]any{"state": "Not configured"}
	}
	endpoint := s.Address
	secure := s.TLS
	if s.Type == "cloud" {
		endpoint = client.V1RegionFQDNMapping[s.Region] + ":443"
		secure = true
	}
	key := fmt.Sprint(s.Type, endpoint, secure)
	a.serviceMu.Lock()
	defer a.serviceMu.Unlock()
	if a.serviceKey == key && time.Since(a.serviceAt) < 30*time.Second {
		return a.serviceCache
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: time.Second}
	started := time.Now()
	var conn net.Conn
	var err error
	if secure {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12}}).DialContext(checkCtx, "tcp", endpoint)
	} else {
		conn, err = dialer.DialContext(checkCtx, "tcp", endpoint)
	}
	latency := float64(time.Since(started).Microseconds()) / 1000
	state := "Reachable"
	if err != nil {
		state = "Unreachable"
	} else {
		conn.Close()
	}
	result := map[string]any{"state": state, "type": s.Type, "latencyMs": latency, "checkedAt": stamp(), "note": "TCP/TLS connectivity check; does not verify API credentials or a scan verdict."}
	a.serviceKey = key
	a.serviceAt = time.Now()
	a.serviceCache = result
	return result
}

func cpuUtilization(usedUsec uint64, seconds, cores float64) float64 {
	if seconds <= 0 || cores <= 0 {
		return 0
	}
	return max(0, min(100, float64(usedUsec)/1e6/seconds/cores*100))
}
func (a *App) resourceStatus() map[string]any {
	r := containerResources(a.DataDir)
	raw, _ := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	usage := uint64(0)
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "usage_usec" {
			usage, _ = strconv.ParseUint(f[1], 10, 64)
		}
	}
	if usage == 0 {
		usage = numberFile("/sys/fs/cgroup/cpuacct/cpuacct.usage") / 1000
	}
	a.resourceMu.Lock()
	defer a.resourceMu.Unlock()
	now := time.Now()
	if !a.resourceAt.IsZero() && now.Sub(a.resourceAt) < time.Second {
		if a.resourcePercent != nil {
			r["cpuUtilizationPercent"] = *a.resourcePercent
		}
		return r
	}
	if !a.resourceAt.IsZero() && usage >= a.resourceUsec {
		value := cpuUtilization(usage-a.resourceUsec, now.Sub(a.resourceAt).Seconds(), r["cpuCores"].(float64))
		a.resourcePercent = &value
		r["cpuUtilizationPercent"] = value
	}
	a.resourceAt = now
	a.resourceUsec = usage
	return r
}
