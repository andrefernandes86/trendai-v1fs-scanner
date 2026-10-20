package core

import (
	"fmt"
	"testing"
)

func TestFailClosedVerdicts(t *testing.T) {
	for _, b := range []string{`{}`, `null`, `{"scanId":"x"}`, `{"scanId":"x","scanResult":-1}`, `{"scanId":"x","result":{"atse":{"malwareCount":0,"error":{"code":500}}}}`, `{"scanResult":0}`, `{"scanId":"x","scanResult":"0"}`, `not json`} {
		if v := Normalize([]byte(b)); v != "UNKNOWN" {
			t.Fatalf("unsafe verdict %s: %s", b, v)
		}
	}
	for _, verbose := range []bool{false, true} {
		for i := 0; i < 2; i++ {
			b := fmt.Sprintf(`{"scanId":"x","scanResult":%d}`, i)
			if verbose {
				b = fmt.Sprintf(`{"scanId":"x","result":{"atse":{"malwareCount":%d,"error":null}}}`, i)
			}
			want := "CLEAN"
			if i == 1 {
				want = "MALICIOUS"
			}
			if Normalize([]byte(b)) != want {
				t.Fatal(b)
			}
		}
	}
}
func TestPromotionGuards(t *testing.T) {
	for _, v := range []string{"UNKNOWN", "MALICIOUS", "ERROR", ""} {
		if Transition("PROMOTING", "COMPLETED", v) {
			t.Fatal("unverified promotion allowed")
		}
	}
	if !Transition("PROMOTING", "COMPLETED", "CLEAN") {
		t.Fatal("clean promotion blocked")
	}
	if Transition("SCANNING", "COMPLETED", "CLEAN") {
		t.Fatal("skipped verification")
	}
}
func TestIdentityAndPaths(t *testing.T) {
	if Identity("a", "b", "c", "d") == Identity("a", "b", "c", "e") {
		t.Fatal("version collision")
	}
	for _, p := range []string{"../x", "a/../x", "/etc/passwd", "a\\b", "a/./b", ""} {
		if ValidKey(p) {
			t.Fatal(p)
		}
	}
	if !ValidKey("incoming/report.pdf") {
		t.Fatal("valid path rejected")
	}
	for _, u := range []string{"http://a.blob.core.windows.net/safe", "https://a.blob.core.windows.net.evil.test/safe", "https://a.blob.core.windows.net/safe?sig=secret", "https://a.blob.core.windows.net/"} {
		if StorageURL(u, "blob") {
			t.Fatal(u)
		}
	}
}

func TestVerboseMultipleEngines(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"scanId":"x","result":{"atse":{"malwareCount":0,"error":null},"trendx":{"malwareCount":0,"error":null}}}`, "CLEAN"},
		{`{"scanId":"x","result":{"atse":{"malwareCount":0,"error":null},"trendx":{"malwareCount":1,"error":null}}}`, "MALICIOUS"},
		{`{"scanId":"x","result":{"atse":{"malwareCount":0,"error":null},"trendx":{"malwareCount":0,"error":{"code":500}}}}`, "UNKNOWN"},
	} {
		if got := Normalize([]byte(tc.raw)); got != tc.want {
			t.Fatalf("%s want %s", got, tc.want)
		}
	}
}
