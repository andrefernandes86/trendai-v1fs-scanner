package localapp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type tagsTransport func(*http.Request) (*http.Response, error)

func (f tagsTransport) Do(r *http.Request) (*http.Response, error) { return f(r) }
func TestNativeTagsAndPermissionFallback(t *testing.T) {
	for _, denyTags := range []bool{false, true} {
		t.Run(fmt.Sprint(denyTags), func(t *testing.T) {
			storageTransport = tagsTransport(func(r *http.Request) (*http.Response, error) {
				status := 200
				body := `<EnumerationResults><Blobs><Blob><Name>file.txt</Name><Properties><Etag>"v1"</Etag><Content-Length>4</Content-Length></Properties><Metadata><job>record</job><verdict>CLEAN</verdict></Metadata><Tags><TagSet><Tag><Key>scanned</Key><Value>true</Value></Tag><Tag><Key>verdict</Key><Value>clean</Value></Tag></TagSet></Tags></Blob></Blobs><NextMarker/></EnumerationResults>`
				if denyTags && strings.Contains(r.URL.Query().Get("include"), "tags") {
					status = 403
					body = `<Error><Code>AuthorizationPermissionMismatch</Code></Error>`
				}
				if denyTags && status == 200 {
					start := strings.Index(body, "<Tags>")
					end := strings.Index(body, "</Tags>")
					body = body[:start] + body[end+len("</Tags>"):]
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			t.Cleanup(func() { storageTransport = nil })
			files, _, e := ListBlobs(context.Background(), testMount("source", "incoming"), "", "", true)
			if e != nil || len(files) != 1 {
				t.Fatal(e, len(files))
			}
			if (!denyTags && files[0].Tags["verdict"] != "clean") || (denyTags && len(files[0].Tags) != 0) || files[0].TagsUnavailable != denyTags {
				t.Fatal(files[0])
			}
		})
	}
}
func TestStorageResultLinkIsDestinationSpecific(t *testing.T) {
	a := testApp(t)
	m := testMount("good", "clean")
	s := Snapshot{Profile: Profile{ID: "profile"}, Source: testMount("source", "incoming"), Key: "file.txt", ETag: "one"}
	id, e := a.insertJob(s)
	if e != nil {
		t.Fatal(e)
	}
	_ = a.transition(id, "COMPLETED", "CLEAN", "sha", m.BaseURL()+"/file.txt", "", 0)
	files := []BlobEntry{{Key: "file.txt"}, {Key: "unrelated.txt", Tags: map[string]string{"verdict": "clean"}, Metadata: map[string]string{"job": id}}}
	a.attachStorageResults(m, files)
	if files[0].ScanJobID != id || files[0].Verdict != "CLEAN" {
		t.Fatal(files[0])
	}
	if files[1].Verdict != "" || files[1].ScanJobID != "" {
		t.Fatal("trusted forged tags on unrelated file")
	}
}
