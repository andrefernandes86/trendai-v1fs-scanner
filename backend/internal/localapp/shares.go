package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"hash/crc32"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

func (m Mount) Type() string {
	if m.Kind == "" {
		return "blob"
	}
	return m.Kind
}
func sameCredentialTarget(a, b Mount) bool {
	return a.Type() == b.Type() && a.Account == b.Account && a.ResourceID == b.ResourceID && strings.EqualFold(a.Server, b.Server) && a.Username == b.Username && a.Domain == b.Domain
}
func (m *Mount) validateShare() error {
	if !idPattern.MatchString(m.ID) || strings.TrimSpace(m.Name) == "" {
		return errors.New("connection ID and name are required")
	}
	if m.Prefix != "" && !core.ValidKey(m.Prefix) {
		return errors.New("invalid connection prefix")
	}
	switch m.Type() {
	case "azureFiles":
		if m.ResourceID != "" {
			parts := strings.Split(strings.Trim(m.ResourceID, "/"), "/")
			found := false
			for i := 0; i+5 < len(parts); i++ {
				if strings.EqualFold(parts[i], "storageAccounts") && strings.EqualFold(parts[i+2], "fileServices") && parts[i+3] == "default" && strings.EqualFold(parts[i+4], "shares") && i+6 == len(parts) {
					m.Account, m.Share = parts[i+1], parts[i+5]
					found = true
					break
				}
			}
			if !found {
				return errors.New("use an Azure file share resource ID ending in fileServices/default/shares/NAME")
			}
		}
		if !accountPattern.MatchString(m.Account) || !containerPattern.MatchString(m.Share) || strings.Contains(m.Share, "--") {
			return errors.New("valid Azure account and file share names are required")
		}
		if m.AuthType != "accountKey" && m.AuthType != "sas" {
			return errors.New("Azure Files supports an account key or SAS token")
		}
		if m.Secret == "" {
			return errors.New("Azure credentials are required")
		}
		if m.AuthType == "sas" {
			q, e := url.ParseQuery(strings.TrimPrefix(m.Secret, "?"))
			if e != nil || q.Get("sig") == "" {
				return errors.New("invalid Azure Files SAS token")
			}
		}
	case "smb":
		m.AuthType = "password"
		if !validServer(m.Server) || !validShareName(m.Share) || m.Username == "" || m.Secret == "" {
			return errors.New("SMB requires server, share name, username and password")
		}
		if m.Port == 0 {
			m.Port = 445
		}
		if m.Port < 1 || m.Port > 65535 {
			return errors.New("invalid SMB port")
		}
	case "nfs":
		if !validServer(m.Server) || !strings.HasPrefix(m.Export, "/") || (m.Export != "/" && !core.ValidKey(strings.TrimPrefix(m.Export, "/"))) {
			return errors.New("NFSv3 requires a server and absolute export path")
		}
		if path.Clean(m.Export) != m.Export {
			return errors.New("use a normalized export path")
		}
		m.Secret = ""
		m.AuthType = "authSys"
	default:
		return errors.New("unknown storage connection type")
	}
	return nil
}
func validServer(s string) bool {
	return s != "" && !strings.ContainsAny(s, "/\\@?# \t\r\n") && (net.ParseIP(s) != nil || !strings.Contains(s, ":"))
}
func validShareName(s string) bool {
	return s != "" && !strings.ContainsAny(s, "/\\\x00") && s != "." && s != ".."
}
func (m Mount) shareURL() string {
	switch m.Type() {
	case "azureFiles":
		return fmt.Sprintf("https://%s.file.core.windows.net/%s", m.Account, m.Share)
	case "smb":
		port := m.Port
		if port == 0 {
			port = 445
		}
		return "smb://" + net.JoinHostPort(strings.ToLower(m.Server), fmt.Sprint(port)) + "/" + url.PathEscape(strings.ToLower(m.Share))
	case "nfs":
		return "nfs://" + strings.ToLower(m.Server) + m.Export
	}
	return ""
}

type remoteFS interface {
	Stat(string) (os.FileInfo, error)
	ReadDir(string) ([]os.FileInfo, error)
	Open(string) (io.ReadCloser, error)
	UploadExclusive(string, io.Reader, int64) error
	MkdirAll(string) error
	PublishExclusive(string, string) error
	Remove(string) error
	Close() error
}

var remoteOpen = connectRemote

func connectRemote(ctx context.Context, m Mount) (remoteFS, error) {
	switch m.Type() {
	case "azureFiles":
		return openAzureFiles(ctx, m)
	case "smb":
		return openSMB(ctx, m)
	case "nfs":
		return openNFS(ctx, m)
	}
	return nil, errors.New("unsupported share type")
}
func safeKey(key string, root bool) error {
	if root && (key == "" || key == ".") {
		return nil
	}
	if !core.ValidKey(key) {
		return errors.New("unsafe share path")
	}
	for _, p := range strings.Split(key, "/") {
		if p == "" {
			return errors.New("empty path component")
		}
	}
	return nil
}
func noLinks(fs remoteFS, key string) error {
	if e := safeKey(key, true); e != nil {
		return e
	}
	parts := strings.Split(strings.Trim(key, "/"), "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		if p == "" || p == "." {
			continue
		}
		info, e := fs.Stat(p)
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic links are excluded")
		}
	}
	return nil
}

type taggedInfo interface{ ETag() string }

func infoTag(info os.FileInfo) string {
	if t, ok := info.(taggedInfo); ok && t.ETag() != "" {
		return t.ETag()
	}
	b, _ := json.Marshal([]any{info.Size(), info.ModTime().UnixNano(), uint32(info.Mode())})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func shareProperties(ctx context.Context, m Mount, key string) (BlobEntry, error) {
	fs, e := remoteOpen(ctx, m)
	if e != nil {
		return BlobEntry{}, e
	}
	defer fs.Close()
	return remoteProperties(fs, key)
}
func remoteProperties(fs remoteFS, key string) (BlobEntry, error) {
	if e := noLinks(fs, key); e != nil {
		return BlobEntry{}, e
	}
	info, e := fs.Stat(key)
	if e != nil {
		return BlobEntry{}, e
	}
	if !info.Mode().IsRegular() {
		return BlobEntry{}, errors.New("only regular files can be scanned")
	}
	complete := false
	if marker, e := fs.Stat(key + ".complete"); e == nil && marker.Mode().IsRegular() && !marker.ModTime().Before(info.ModTime()) {
		complete = true
	}
	return BlobEntry{Key: key, Size: info.Size(), ETag: infoTag(info), Modified: info.ModTime().UTC().Format(time.RFC3339Nano), Complete: complete}, nil
}
func listShare(ctx context.Context, m Mount, prefix, marker string) ([]BlobEntry, string, error) {
	fs, e := remoteOpen(ctx, m)
	if e != nil {
		return nil, "", e
	}
	defer fs.Close()
	want := m.Prefix + prefix
	if want != "" && !core.ValidKey(want) {
		return nil, "", errors.New("invalid prefix")
	}
	out := []BlobEntry{}
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > 64 {
			return errors.New("directory depth exceeds 64")
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := noLinks(fs, dir); e != nil {
			return e
		}
		items, e := fs.ReadDir(dir)
		if e != nil {
			return e
		}
		sort.Slice(items, func(i, j int) bool {
			left, right := items[i].Name(), items[j].Name()
			if items[i].IsDir() {
				left += "/"
			}
			if items[j].IsDir() {
				right += "/"
			}
			return left < right
		})
		for _, item := range items {
			if item.Name() == "." || item.Name() == ".." || (item.Name() == ".v1fs-staging" || item.Name() == ".v1fs-claims") || strings.HasSuffix(item.Name(), ".complete") || strings.HasSuffix(item.Name(), ".v1fs-tags.json") || !validShareName(item.Name()) || item.Mode()&os.ModeSymlink != 0 {
				continue
			}
			key := path.Join(dir, item.Name())
			if item.IsDir() {
				if want == "" || strings.HasPrefix(want, key+"/") || strings.HasPrefix(key+"/", want) {
					if e = walk(key, depth+1); e != nil {
						return e
					}
				}
			} else if item.Mode().IsRegular() && strings.HasPrefix(key, want) && key > marker {
				p, e := remoteProperties(fs, key)
				if e != nil {
					return e
				}
				out = append(out, p)
			}
			if len(out) > 200 {
				return nil
			}
		}
		return nil
	}
	if e = walk("", 0); e != nil {
		return nil, "", e
	}
	next := ""
	if len(out) > 200 {
		out = out[:200]
		next = out[len(out)-1].Key
	}
	return out, next, nil
}
func downloadShare(ctx context.Context, s Snapshot, dir string) (name, digest string, err error) {
	name, digest, _, err = downloadShareChecksums(ctx, s, dir)
	return
}
func downloadShareChecksums(ctx context.Context, s Snapshot, dir string) (name, digest, crc string, err error) {
	fs, e := remoteOpen(ctx, s.Source)
	if e != nil {
		return "", "", "", e
	}
	defer fs.Close()
	before, e := remoteProperties(fs, s.sourceKey())
	if e != nil || before.ETag != s.sourceETag() || before.Size != s.Size {
		return "", "", "", errors.New("source identity changed")
	}
	r, e := fs.Open(s.sourceKey())
	if e != nil {
		return "", "", "", e
	}
	defer r.Close()
	f, e := os.CreateTemp(dir, "share-scan-*")
	if e != nil {
		return "", "", "", e
	}
	defer f.Close()
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	csum := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	n, e := io.Copy(io.MultiWriter(f, h, csum), io.LimitReader(r, s.Size+1))
	if e != nil {
		return "", "", "", e
	}
	after, e := remoteProperties(fs, s.sourceKey())
	if e != nil || n != s.Size || after.ETag != before.ETag {
		return "", "", "", errors.New("source changed during download")
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), fmt.Sprintf("%08x", csum.Sum32()), nil
}
func verifyRemote(fs remoteFS, key, digest string, size int64) error {
	if e := noLinks(fs, key); e != nil {
		return e
	}
	r, e := fs.Open(key)
	if e != nil {
		return e
	}
	defer r.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r, size+1))
	if e != nil {
		return e
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("destination digest mismatch")
	}
	return nil
}
func routeShare(ctx context.Context, m Mount, key, local, digest, job string, size int64, skipVerification ...bool) error {
	if e := safeKey(key, false); e != nil {
		return e
	}
	fs, e := remoteOpen(ctx, m)
	if e != nil {
		return e
	}
	defer fs.Close()
	verify := func(key string) error {
		if len(skipVerification) > 0 && skipVerification[0] {
			info, err := fs.Stat(key)
			if err != nil {
				return err
			}
			if info.Size() != size {
				return errors.New("destination size changed")
			}
			return nil
		}
		return verifyRemote(fs, key, digest, size)
	}
	if _, e = fs.Stat(key); e == nil {
		return verify(key)
	}
	if e = ensureRemoteDirs(fs, path.Dir(key)); e != nil {
		return e
	}
	if e = noLinks(fs, path.Dir(key)); e != nil {
		return e
	}
	stageDir := ".v1fs-staging"
	if e = ensureRemoteDirs(fs, stageDir); e != nil {
		return e
	}
	if e = noLinks(fs, stageDir); e != nil {
		return e
	}
	tmp, e := os.CreateTemp("", "v1fs-stage-id-*")
	if e != nil {
		return e
	}
	tmp.Close()
	os.Remove(tmp.Name())
	stage := stageDir + "/" + job + "-" + path.Base(tmp.Name())
	f, e := os.Open(local)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = fs.UploadExclusive(stage, f, size); e != nil {
		return e
	}
	defer fs.Remove(stage)
	if e = verify(stage); e != nil {
		return e
	}
	publishErr := fs.PublishExclusive(stage, key)
	if publishErr != nil {
		if _, e = fs.Stat(key); e != nil {
			return publishErr
		}
	}
	return verify(key)
}

func sameStorageRoot(a, b Mount) bool {
	if a.BaseURL() == b.BaseURL() {
		return true
	}
	if a.Type() == "nfs" && b.Type() == "nfs" && strings.EqualFold(a.Server, b.Server) {
		return strings.HasPrefix(strings.TrimRight(a.Export, "/")+"/", strings.TrimRight(b.Export, "/")+"/") || strings.HasPrefix(strings.TrimRight(b.Export, "/")+"/", strings.TrimRight(a.Export, "/")+"/")
	}
	canonical := func(m Mount) string {
		if m.Type() == "azureFiles" {
			return strings.ToLower(m.Account + ".file.core.windows.net/" + m.Share)
		}
		if m.Type() == "smb" && (m.Port == 0 || m.Port == 445) {
			return strings.ToLower(m.Server + "/" + m.Share)
		}
		return m.BaseURL()
	}
	return canonical(a) == canonical(b)
}

func ensureRemoteDirs(fs remoteFS, key string) error {
	if e := safeKey(key, true); e != nil {
		return e
	}
	parts := strings.Split(key, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		if p == "" || p == "." {
			continue
		}
		info, e := fs.Stat(p)
		if e != nil {
			if e = fs.MkdirAll(p); e != nil {
				return e
			}
			info, e = fs.Stat(p)
			if e != nil {
				return e
			}
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("destination directory is not a safe regular directory")
		}
	}
	return nil
}
