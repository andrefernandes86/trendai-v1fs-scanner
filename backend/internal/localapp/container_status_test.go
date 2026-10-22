package localapp

import (
	"context"
	"net"
	"testing"
)

func TestCPUQuotaRespectsContainerLimit(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want float64
	}{{"200000 100000", 2}, {"50000 100000", .5}, {"max 100000", 8}, {"bad", 8}, {"1600000 100000", 8}, {"-1 100000", 8}} {
		if got := quotaCPUs(tc.raw, 8); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
func TestScannerConnectionReportsTransportOnly(t *testing.T) {
	a := testApp(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := Scanner{Type: "local", Address: listener.Addr().String()}
	if err = a.Save("scanner", "default", s); err != nil {
		t.Fatal(err)
	}
	status := a.scannerConnection(context.Background())
	if status["state"] != "Reachable" || status["note"] == "" {
		t.Fatal(status)
	}
	r := containerResources(a.DataDir)
	if r["cpuCores"].(float64) <= 0 || r["diskTotalBytes"] == nil {
		t.Fatal(r)
	}
}
