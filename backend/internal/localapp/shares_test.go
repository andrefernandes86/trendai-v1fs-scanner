package localapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	nfs "github.com/vmware/go-nfs-client/nfs"
	"github.com/vmware/go-nfs-client/nfs/rpc"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type diskShare struct{ root string }

func (f *diskShare) p(k string) string                  { return filepath.Join(f.root, filepath.FromSlash(k)) }
func (f *diskShare) Stat(k string) (os.FileInfo, error) { return os.Lstat(f.p(k)) }
func (f *diskShare) ReadDir(k string) ([]os.FileInfo, error) {
	v, e := os.ReadDir(f.p(k))
	if e != nil {
		return nil, e
	}
	out := []os.FileInfo{}
	for _, entry := range v {
		info, e := entry.Info()
		if e != nil {
			return nil, e
		}
		out = append(out, info)
	}
	return out, nil
}
func (f *diskShare) Open(k string) (io.ReadCloser, error) { return os.Open(f.p(k)) }
func (f *diskShare) UploadExclusive(k string, r io.Reader, size int64) error {
	v, e := os.OpenFile(f.p(k), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = io.Copy(v, r)
	ce := v.Close()
	if e != nil {
		return e
	}
	return ce
}
func (f *diskShare) MkdirAll(k string) error                { return os.MkdirAll(f.p(k), 0700) }
func (f *diskShare) PublishExclusive(from, to string) error { return os.Link(f.p(from), f.p(to)) }
func (f *diskShare) Remove(k string) error                  { return os.Remove(f.p(k)) }
func (f *diskShare) Close() error                           { return nil }
func TestShareConnectionValidationAndIsolation(t *testing.T) {
	for _, kind := range []string{"azureFiles", "smb", "nfs"} {
		m := Mount{ID: "share", Name: "Share", Kind: kind, Account: "storageacct", Share: "incoming", Server: "nas.internal", Username: "scanner", Secret: "password", AuthType: "accountKey", Export: "/incoming", UID: 1000, GID: 1000}
		if e := m.Validate(); e != nil {
			t.Fatalf("%s %v", kind, e)
		}
		if kind == "nfs" && m.Secret != "" {
			t.Fatal("NFS retained a password")
		}
		if m.BaseURL() == "" {
			t.Fatal("missing identity")
		}
	}
	a := Mount{Kind: "nfs", Server: "nas", Export: "/data"}
	b := Mount{Kind: "nfs", Server: "nas", Export: "/data/clean"}
	if !sameStorageRoot(a, b) {
		t.Fatal("overlapping exports accepted")
	}
	if !sameStorageRoot(Mount{Kind: "azureFiles", Account: "storageacct", Share: "incoming"}, Mount{Kind: "smb", Server: "storageacct.file.core.windows.net", Share: "incoming", Port: 445}) {
		t.Fatal("Azure/SMB alias escaped root isolation")
	}
	for _, key := range []string{"../etc", "a/../b", "/absolute", "a\\b", "a//b"} {
		if safeKey(key, false) == nil {
			t.Fatal(key)
		}
	}
}
func TestShareBrowsingDownloadAndAtomicRouting(t *testing.T) {
	a := testApp(t)
	stores := map[string]*diskShare{}
	for _, id := range []string{"source", "good", "bad"} {
		stores[id] = &diskShare{root: t.TempDir()}
	}
	original := remoteOpen
	remoteOpen = func(_ context.Context, m Mount) (remoteFS, error) { return stores[m.ID], nil }
	t.Cleanup(func() { remoteOpen = original })
	content := []byte("file content")
	os.MkdirAll(stores["source"].p("incoming"), 0700)
	os.WriteFile(stores["source"].p("incoming/report.txt"), content, 0600)
	os.WriteFile(stores["source"].p("incoming/report.txt.complete"), nil, 0600)
	os.Symlink("/etc", stores["source"].p("unsafe"))
	for _, kind := range []string{"azureFiles", "smb", "nfs"} {
		t.Run(kind, func(t *testing.T) {
			os.WriteFile(stores["source"].p("incoming/report.txt"), content, 0600)
			os.WriteFile(stores["source"].p("incoming/report.txt.complete"), nil, 0600)
			m := Mount{ID: "source", Kind: kind, Name: "Source", Account: "acct", Share: "incoming", Server: "nas", Export: "/incoming"}
			files, _, e := ListBlobs(context.Background(), m, "incoming/", "")
			if e != nil || len(files) != 1 || !files[0].Complete {
				t.Fatalf("list %v %#v", e, files)
			}
			s := Snapshot{Source: m, Good: Mount{ID: "good", Kind: kind, Server: "nas", Share: "good", Export: "/good"}, Bad: Mount{ID: "bad", Kind: kind, Server: "nas", Share: "bad", Export: "/bad"}, Profile: Profile{ID: "profile-" + kind, Name: "Profile", Revision: 1}, Key: files[0].Key, ETag: files[0].ETag, Size: files[0].Size}
			id, e := a.insertJob(s)
			if e != nil {
				t.Fatal(e)
			}
			_, snapshot, attempt, e := a.claim()
			if e != nil {
				t.Fatal(e)
			}
			a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
				return []byte(`{"scanId":"fixture","scanResult":1}`), nil
			}
			a.process(context.Background(), id, snapshot, attempt)
			var state, destination string
			a.DB.QueryRow("SELECT state,destination FROM jobs WHERE id=?", id).Scan(&state, &destination)
			if state != "QUARANTINED" {
				var message string
				a.DB.QueryRow("SELECT error FROM jobs WHERE id=?", id).Scan(&message)
				t.Fatal(state, message)
			}
			if !strings.Contains(destination, "bad") {
				t.Fatal(destination)
			}
			if _, err := os.Stat(stores["source"].p(s.Key)); !os.IsNotExist(err) {
				t.Fatal("verified source was not moved")
			}
			found := false
			filepath.WalkDir(stores["bad"].root, func(p string, d os.DirEntry, e error) error {
				if e == nil && !d.IsDir() && strings.Contains(p, id) {
					b, _ := os.ReadFile(p)
					if bytes.Equal(b, content) {
						found = true
					}
				}
				return e
			})
			if !found {
				t.Fatal("malicious bytes missing in quarantine")
			}
			hash := sha256.Sum256(content)
			local := filepath.Join(t.TempDir(), "sample")
			os.WriteFile(local, content, 0600)
			if e := Route(context.Background(), s.Bad, id+"/"+s.Key, local, hex.EncodeToString(hash[:]), id, "MALICIOUS", s.Size); e != nil {
				t.Fatal("routing replay failed", e)
			}
			if _, _, e := Download(context.Background(), Snapshot{Source: m, Key: s.Key, ETag: "obsolete", Size: s.Size}, t.TempDir()); e == nil {
				t.Fatal("changed identity accepted")
			}
		})
	}
	entries, _ := os.ReadDir(stores["good"].root)
	if len(entries) != 0 {
		t.Fatal("malware reached clean share")
	}
	if _, e := shareProperties(context.Background(), Mount{ID: "source", Kind: "smb"}, "unsafe/passwd"); e == nil {
		t.Fatal("symlink traversal accepted")
	}
}
func TestNFSRPCEncodingAndFragmentBounds(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	port, _ := strconv.Atoi(strings.Split(ln.Addr().String(), ":")[1])
	received := make(chan []byte, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		var length uint32
		binary.Read(c, binary.BigEndian, &length)
		b := make([]byte, length&0x7fffffff)
		io.ReadFull(c, b)
		received <- b
		var reply bytes.Buffer
		for _, v := range []uint32{binary.BigEndian.Uint32(b[:4]), 1, 0, 0, 0, 0, 0, 42} {
			binary.Write(&reply, binary.BigEndian, v)
		}
		binary.Write(c, binary.BigEndian, uint32(reply.Len())|0x80000000)
		c.Write(reply.Bytes())
	}()
	r, e := rpcRequest(context.Background(), "127.0.0.1", port, rpc.Header{Rpcvers: 2, Prog: 100003, Vers: 3, Proc: 1, Cred: rpc.AuthNull, Verf: rpc.AuthNull}, uint32(77), true)
	if e != nil {
		t.Fatal(e)
	}
	request := <-received
	if len(request) != 44 || binary.BigEndian.Uint32(request[40:44]) != 77 {
		t.Fatalf("invalid XDR request %x", request)
	}
	var answer uint32
	binary.Read(r, binary.BigEndian, &answer)
	if answer != 42 {
		t.Fatal(answer)
	}
	for _, b := range [][]byte{{0xff, 0xff, 0xff, 0xff}, {0, 0, 0, 8, 1, 2}} {
		if _, e := boundedOpaque(bytes.NewReader(b), 128); e == nil {
			t.Fatal("unbounded opaque accepted")
		}
	}
}
func TestNFSRPCCancellation(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	port, _ := strconv.Atoi(strings.Split(ln.Addr().String(), ":")[1])
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, e = rpcRequest(ctx, "127.0.0.1", port, rpc.Header{Rpcvers: 2, Prog: 100003, Vers: 3, Proc: 1}, struct{}{}, true)
	if e == nil {
		t.Fatal("cancel ignored")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RPC socket not closed")
	}
}

func TestNFSFileTypeNormalization(t *testing.T) {
	for _, tc := range []struct {
		kind uint32
		mode os.FileMode
	}{{2, os.ModeDir}, {5, os.ModeSymlink}, {1, 0}, {3, os.ModeIrregular}} {
		info := nfsInfo("entry", nfs.Fattr{Type: tc.kind, FileMode: 0755, Fileid: 1})
		if info.Mode()&os.ModeType != tc.mode {
			t.Fatalf("type %d mapped to %v", tc.kind, info.Mode())
		}
	}
}
func TestAzureFilesRenameKeepsShareRootAndDoesNotReplace(t *testing.T) {
	fixture := &storageDiagnosticFixture{code: 200, body: ""}
	storageTransport = fixture
	t.Cleanup(func() { storageTransport = nil })
	fs, e := openAzureFiles(context.Background(), Mount{Kind: "azureFiles", Account: "testaccount", Share: "incoming", AuthType: "accountKey", Secret: testMount("x", "x").Secret})
	if e != nil {
		t.Fatal(e)
	}
	if e = fs.PublishExclusive(".v1fs-staging/file", "approved/report.txt"); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(fixture.lastURL)
	if e != nil || u.Path != "/incoming/approved/report.txt" {
		t.Fatal("share root duplicated", fixture.lastURL)
	}
}

func TestShareListingPaginationDoesNotSkipSiblingFiles(t *testing.T) {
	dir := t.TempDir()
	fs := &diskShare{root: dir}
	os.MkdirAll(fs.p("a"), 0700)
	os.WriteFile(fs.p("a.txt"), []byte("root"), 0600)
	for i := 0; i < 205; i++ {
		os.WriteFile(fs.p(fmt.Sprintf("a/%03d.txt", i)), nil, 0600)
	}
	original := remoteOpen
	remoteOpen = func(context.Context, Mount) (remoteFS, error) { return fs, nil }
	defer func() { remoteOpen = original }()
	m := Mount{Kind: "smb", ID: "source"}
	first, marker, e := ListBlobs(context.Background(), m, "", "")
	if e != nil || len(first) != 200 || marker == "" {
		t.Fatal(e, len(first), marker)
	}
	second, next, e := ListBlobs(context.Background(), m, "", marker)
	if e != nil || next != "" || len(first)+len(second) != 206 {
		t.Fatal("pagination lost a file", e, len(first), len(second))
	}
	all := append(first, second...)
	for i := 1; i < len(all); i++ {
		if all[i].Key <= all[i-1].Key {
			t.Fatal("cursor ordering is unstable")
		}
	}
}

func TestLegacyBlobIdentityIsPreserved(t *testing.T) {
	a := testApp(t)
	s := Snapshot{Source: Mount{ID: "source", Account: "acct", Container: "incoming"}, Profile: Profile{ID: "policy", Revision: 2}, Key: "file.txt", ETag: "etag", Version: "v1"}
	legacy, _ := json.Marshal([]any{s.Profile.ID, s.Profile.Revision, s.Source.Account, s.Source.Container, s.Key, s.ETag, s.Version})
	h := sha256.Sum256(legacy)
	id, e := a.insertJob(s)
	if e != nil || id != hex.EncodeToString(h[:]) {
		t.Fatal("Blob upgrade changed existing identity", e)
	}
}

func TestAzureFilesDiagnosticRedactsSASInErrors(t *testing.T) {
	a := testApp(t)
	fixture := &storageDiagnosticFixture{code: 403, body: `<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code><Message>Denied sig=private-file-signature</Message></Error>`}
	storageTransport = fixture
	t.Cleanup(func() { storageTransport = nil })
	m := Mount{ID: "draft", Name: "File share", Kind: "azureFiles", Account: "testaccount", Share: "incoming", AuthType: "sas", Secret: "sv=2023-11-03&sp=rl&sig=private-file-signature"}
	body, _ := json.Marshal(map[string]any{"kind": "container", "mount": m})
	w := httptest.NewRecorder()
	a.storageTest(w, httptest.NewRequest("POST", "http://localhost/api/storage/test", bytes.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"success":false`) {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-file-signature") {
		t.Fatal("Azure Files diagnostic leaked a SAS signature")
	}
}
