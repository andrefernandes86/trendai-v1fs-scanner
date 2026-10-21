package localapp

import "testing"

func TestMandatoryResultTags(t *testing.T) {
	p := Profile{}
	for _, verdict := range []string{"CLEAN", "MALICIOUS"} {
		tags, e := p.ResultTags(verdict)
		if e != nil || tags["scanned"] != "true" || tags["verdict"] == "" {
			t.Fatal(tags, e)
		}
	}
	p.CleanTags = "scanned=false"
	if _, e := p.ResultTags("CLEAN"); e == nil {
		t.Fatal("accepted a misleading reserved scan tag")
	}
}
