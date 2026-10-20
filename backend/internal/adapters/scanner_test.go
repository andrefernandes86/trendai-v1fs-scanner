package adapters

import (
	"context"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"os"
	"testing"
)

func TestSimulatorVerdicts(t *testing.T) {
	for _, test := range []struct{ body, want string }{{"harmless", "CLEAN"}, {"EICAR test sentinel", "MALICIOUS"}} {
		f, e := os.CreateTemp(t.TempDir(), "sample")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.WriteString(test.body); e != nil {
			t.Fatal(e)
		}
		f.Close()
		s := Scanner{Simulated: true}
		r, e := s.Scan(context.Background(), f.Name(), core.Profile{})
		if e != nil {
			t.Fatal(e)
		}
		if core.Normalize(r) != test.want {
			t.Fatalf("wrong verdict %s", r)
		}
	}
}
func TestOfficialSDKIntegration(t *testing.T) {
	if os.Getenv("RUN_REAL_SDK_TEST") != "true" {
		t.Skip("requires explicit RUN_REAL_SDK_TEST and paid scanner credentials")
	}
	s := Scanner{Key: os.Getenv("TM_AM_AUTH_KEY"), Region: os.Getenv("TM_REGION")}
	defer s.Close()
	f, e := os.CreateTemp(t.TempDir(), "clean")
	if e != nil {
		t.Fatal(e)
	}
	f.WriteString("File Security SDK integration test")
	f.Close()
	r, e := s.Scan(context.Background(), f.Name(), core.Profile{Digest: true, Direct: true})
	if e != nil {
		t.Fatal(e)
	}
	if core.Normalize(r) != "CLEAN" {
		t.Fatalf("scan not verified clean: %s", r)
	}
}
