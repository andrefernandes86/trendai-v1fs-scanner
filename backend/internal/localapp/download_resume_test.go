package localapp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type brokenDownload struct{ sent bool }

func (b *brokenDownload) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, []byte("1234")), nil
	}
	return 0, io.ErrUnexpectedEOF
}
func (b *brokenDownload) Close() error { return nil }
func TestDownloadResumesInterruptedStreamWithIdentityCondition(t *testing.T) {
	calls := 0
	storageTransport = tagsTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		h := http.Header{"Etag": []string{`"v1"`}, "Content-Length": []string{"9"}, "Content-Type": []string{"application/octet-stream"}}
		body := io.ReadCloser(&brokenDownload{})
		status := 200
		if calls > 1 {
			if r.Header.Get("If-Match") != `"v1"` {
				t.Error("resume lost identity condition")
			}
			if !strings.Contains(testHeader(r, "x-ms-range")+testHeader(r, "Range"), "4-") {
				t.Error("not resumed from offset 4")
			}
			body = io.NopCloser(bytes.NewBufferString("56789"))
			h.Set("Content-Length", "5")
			h.Set("Content-Range", "bytes 4-8/9")
			status = 206
		}
		return &http.Response{StatusCode: status, Header: h, Body: body, Request: r}, nil
	})
	defer func() { storageTransport = nil }()
	s := Snapshot{Source: testMount("source", "incoming"), Key: "large.csv", ETag: `"v1"`, Size: 9}
	file, digest, _, err := DownloadChecksums(context.Background(), s, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sum, _, n, err := checksums(file)
	if err != nil || n != 9 || digest != sum || calls != 2 {
		t.Fatal(n, calls, err)
	}
}
