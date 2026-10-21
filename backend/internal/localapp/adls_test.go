package localapp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestADLSListingSkipsDirectoriesAndFailureSidecars(t *testing.T) {
	m := testMount("lake", "incoming")
	m.Kind = "adls"
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if m.Type() != "blob" || !strings.Contains(m.BaseURL(), ".blob.core.windows.net/") {
		t.Fatal(m)
	}
	encoded := encodeADLSTags(map[string]string{"scanned": "true", "team": "finance"})
	storageTransport = tagsTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Query().Get("include"), "tags") {
			t.Fatal("ADLS requested preview index tags")
		}
		body := `<EnumerationResults><Blobs>`
		for _, entry := range []struct{ name, metadata string }{{"folder", `<hdi_isfolder>true</hdi_isfolder>`}, {"folder/report.csv", `<v1fs_result_tags>` + encoded + `</v1fs_result_tags>`}, {"folder/report.csv.v1fs-tags.json", ""}} {
			body += fmt.Sprintf(`<Blob><Name>%s</Name><Properties><Etag>"v1"</Etag><Content-Length>4</Content-Length></Properties><Metadata>%s</Metadata></Blob>`, entry.name, entry.metadata)
		}
		body += `</Blobs><NextMarker/></EnumerationResults>`
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	defer func() { storageTransport = nil }()
	files, _, err := ListBlobs(context.Background(), m, "", "", true)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	if files[0].Key != "folder/report.csv" || files[0].Tags["team"] != "finance" {
		t.Fatal(files)
	}
}

func TestADLSRoutingUsesMetadataAndPersistsPostMetadataIdentity(t *testing.T) {
	for _, tc := range []struct{ raw, state string }{{`{"scanId":"x","scanResult":0}`, "COMPLETED"}, {`{"scanId":"x","scanResult":1}`, "QUARANTINED"}, {`{}`, "HELD"}} {
		t.Run(tc.state, func(t *testing.T) {
			a := testApp(t)
			fake := &fakeAzure{objects: map[string][]byte{"/incoming/report.csv": []byte("file content")}, writes: map[string]int{}, etag: `"v1"`}
			metadataWrites := 0
			storageTransport = tagsTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("comp") == "tags" {
					t.Fatal("ADLS used native index tags")
				}
				if r.Method == "PUT" && r.URL.Query().Get("comp") == "metadata" {
					metadataWrites++
					tags := adlsResultTags(map[string]*string{"v1fs_result_tags": func() *string { v := testHeader(r, "x-ms-meta-v1fs_result_tags"); return &v }()})
					if tags["verdict"] == "" {
						t.Fatal("missing result metadata")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{`"after-metadata"`}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				return fake.Do(r)
			})
			defer func() { storageTransport = nil }()
			m := func(id, container string) Mount { m := testMount(id, container); m.Kind = "adls"; return m }
			s := Snapshot{Source: m("source", "incoming"), Good: m("good", "clean"), Bad: m("bad", "malicious"), Failed: m("failed", "failed"), Profile: Profile{ID: "p", Name: "Lake", ScanAttempts: 1}, Key: "report.csv", ETag: `"v1"`, Size: 12}
			a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) { return []byte(tc.raw), nil }
			id, err := a.insertJob(s)
			if err != nil {
				t.Fatal(err)
			}
			_, snap, n, _ := a.claim()
			a.process(context.Background(), id, snap, n)
			var state string
			a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
			move, err := a.loadMove(id)
			if err != nil || state != tc.state || metadataWrites != 1 || move.DestinationETag != `"after-metadata"` || move.Phase != "COMPLETED" {
				t.Fatal(state, move, metadataWrites, err)
			}
		})
	}
}

func TestADLSFailureLabelsDoNotChangeSourceIdentity(t *testing.T) {
	a := testApp(t)
	fake := &fakeAzure{objects: map[string][]byte{"/incoming/report.csv": []byte("file content")}, writes: map[string]int{}, etag: `"v1"`}
	storageTransport = tagsTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("comp") == "tags" || r.URL.Query().Get("comp") == "metadata" {
			t.Fatal("failure labels mutated ADLS source")
		}
		return fake.Do(r)
	})
	defer func() { storageTransport = nil }()
	m := testMount("source", "incoming")
	m.Kind = "adls"
	s := Snapshot{Source: m, Profile: Profile{ID: "p"}, Key: "report.csv", ETag: `"v1"`, Size: 12}
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.tagExhaustedSource(id, "download", "UNKNOWN"); err != nil {
		t.Fatal(err)
	}
	sidecar := string(fake.objects["/incoming/report.csv.v1fs-tags.json"])
	if !strings.Contains(sidecar, `"scan-failed":"true"`) || !strings.Contains(sidecar, `"failure-stage":"download"`) || string(fake.objects["/incoming/report.csv"]) != "file content" {
		t.Fatal(sidecar)
	}
}
