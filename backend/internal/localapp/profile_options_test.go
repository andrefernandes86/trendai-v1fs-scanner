package localapp

import (
	"testing"
	"time"
)

func TestProfileIntervalAndResultTags(t *testing.T) {
	for _, tc := range []struct{ n, want int }{{0, 30}, {1, 10}, {10, 10}, {65, 65}} {
		if got := (Profile{ScanIntervalSeconds: tc.n}).Interval(); got != time.Duration(tc.want)*time.Second {
			t.Fatalf("interval %d: %v", tc.n, got)
		}
	}
	p := Profile{ScannedTags: "scanned=true,scanner=Vision One", CleanTags: "verdict=clean", MaliciousTags: "verdict=malicious"}
	for _, v := range []string{"CLEAN", "MALICIOUS"} {
		tags, e := p.ResultTags(v)
		if e != nil || len(tags) != 3 || tags["scanned"] != "true" {
			t.Fatalf("tags: %v %v", tags, e)
		}
		if v == "CLEAN" && tags["verdict"] != "clean" || v == "MALICIOUS" && tags["verdict"] != "malicious" {
			t.Fatal(tags)
		}
	}
	p.CleanTags = "invalid"
	if _, e := p.ResultTags("CLEAN"); e == nil {
		t.Fatal("accepted invalid tags")
	}
}
