package localapp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestProfileGeneratedInputsAndCleanup(t *testing.T) {
	a := testApp(t)
	fs := &diskShare{root: t.TempDir()}
	original := remoteOpen
	remoteOpen = func(context.Context, Mount) (remoteFS, error) { return fs, nil }
	defer func() { remoteOpen = original }()
	m := Mount{ID: "source", Kind: "smb", Server: "nas", Share: "temp", Prefix: "incoming/"}
	if e := a.Save("mounts", m.ID, m); e != nil {
		t.Fatal(e)
	}
	p := Profile{ID: "demo", SourceMount: m.ID, Prefix: "tests", Enabled: true}
	if e := a.Save("profiles", p.ID, p); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"safe", "eicar"} {
		r := httptest.NewRequest("POST", "http://localhost/api/profiles/demo/test-file", strings.NewReader(`{"kind":"`+kind+`"}`))
		r.SetPathValue("id", p.ID)
		w := httptest.NewRecorder()
		a.profileTestFile(w, r)
		if w.Code != 201 {
			t.Fatal(w.Body.String())
		}
		var out struct {
			Key string `json:"key"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		key := m.Prefix + out.Key
		content, e := os.ReadFile(fs.p(key))
		if e != nil {
			t.Fatal(e)
		}
		if kind == "eicar" && string(content) != eicarContent {
			t.Fatal("incorrect EICAR")
		}
		info, e := remoteProperties(fs, key)
		if e != nil || !info.Complete {
			t.Fatalf("completion %v %v", info, e)
		}
		var owned generatedTestFile
		if e = a.Get("testfiles", testFileID(m, key), &owned); e != nil {
			t.Fatal(e)
		}
		s := Snapshot{Source: m, Key: out.Key, ETag: info.ETag, Size: info.Size, Profile: p}
		a.cleanupTestFile(context.Background(), s, "wrong-digest")
		if _, e := fs.Stat(key); e != nil {
			t.Fatal("removed unverified input")
		}
		a.cleanupTestFile(context.Background(), s, owned.Digest)
		if _, e := fs.Stat(key); !os.IsNotExist(e) {
			t.Fatal("generated input retained")
		}
	}
}
