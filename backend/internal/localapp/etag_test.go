package localapp

import (
	"context"
	"testing"
)

func TestAzureDiscoveryETagQuoteNormalization(t *testing.T) {
	a := testApp(t)
	fake := &fakeAzure{objects: map[string][]byte{"/incoming/file.txt": []byte("safe")}, writes: map[string]int{}, etag: `"v1"`}
	storageTransport = fake
	defer func() { storageTransport = nil }()
	for id, container := range map[string]string{"source": "incoming", "good": "clean", "bad": "malicious", "failed": "failed"} {
		if e := a.Save("mounts", id, testMount(id, container)); e != nil {
			t.Fatal(e)
		}
	}
	_ = a.Save("scanner", "default", Scanner{Type: "local", Address: "localhost:50051"})
	_ = a.Save("profiles", "p", Profile{ID: "p", Name: "Profile", SourceMount: "source", GoodMount: "good", BadMount: "bad", FailedMount: "failed", RequireMarker: true})
	if _, e := a.enqueueExpected(context.Background(), "p", "file.txt", "v1"); e != nil {
		t.Fatal("same Azure ETag rejected", e)
	}
	if _, e := a.enqueueExpected(context.Background(), "p", "file.txt", "changed"); e == nil {
		t.Fatal("changed ETag accepted")
	}
}
