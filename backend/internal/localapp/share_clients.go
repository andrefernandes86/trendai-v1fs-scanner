package localapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/directory"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/file"
	smb "github.com/hirochachacha/go-smb2"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type remoteInfo struct {
	name string
	size int64
	mode os.FileMode
	at   time.Time
	tag  string
}

func (i remoteInfo) Name() string       { return i.name }
func (i remoteInfo) Size() int64        { return i.size }
func (i remoteInfo) Mode() os.FileMode  { return i.mode }
func (i remoteInfo) ModTime() time.Time { return i.at }
func (i remoteInfo) IsDir() bool        { return i.mode.IsDir() }
func (i remoteInfo) Sys() any           { return nil }
func (i remoteInfo) ETag() string       { return i.tag }

type azureFiles struct {
	ctx     context.Context
	m       Mount
	options azcore.ClientOptions
}

func openAzureFiles(ctx context.Context, m Mount) (remoteFS, error) {
	return &azureFiles{ctx: ctx, m: m, options: azcore.ClientOptions{Transport: storageTransport}}, nil
}
func (a *azureFiles) url(key string) string {
	parts := strings.Split(key, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	u := a.m.BaseURL()
	if key != "" && key != "." {
		u += "/" + strings.Join(parts, "/")
	}
	if a.m.AuthType == "sas" {
		u += "?" + strings.TrimPrefix(a.m.Secret, "?")
	}
	return u
}
func (a *azureFiles) file(key string) (*file.Client, error) {
	if e := safeKey(key, false); e != nil {
		return nil, e
	}
	if a.m.AuthType == "sas" {
		return file.NewClientWithNoCredential(a.url(key), &file.ClientOptions{ClientOptions: a.options})
	}
	cred, e := file.NewSharedKeyCredential(a.m.Account, a.m.Secret)
	if e != nil {
		return nil, e
	}
	return file.NewClientWithSharedKeyCredential(a.url(key), cred, &file.ClientOptions{ClientOptions: a.options})
}
func (a *azureFiles) dir(key string) (*directory.Client, error) {
	if e := safeKey(key, true); e != nil {
		return nil, e
	}
	if a.m.AuthType == "sas" {
		return directory.NewClientWithNoCredential(a.url(key), &directory.ClientOptions{ClientOptions: a.options})
	}
	cred, e := directory.NewSharedKeyCredential(a.m.Account, a.m.Secret)
	if e != nil {
		return nil, e
	}
	return directory.NewClientWithSharedKeyCredential(a.url(key), cred, &directory.ClientOptions{ClientOptions: a.options})
}
func (a *azureFiles) Stat(key string) (os.FileInfo, error) {
	if key == "" || key == "." {
		return remoteInfo{mode: os.ModeDir | 0700}, nil
	}
	c, e := a.file(key)
	if e != nil {
		return nil, e
	}
	p, e := c.GetProperties(a.ctx, nil)
	if e != nil {
		d, de := a.dir(key)
		if de == nil {
			if dp, de := d.GetProperties(a.ctx, nil); de == nil {
				at := time.Time{}
				if dp.LastModified != nil {
					at = *dp.LastModified
				}
				return remoteInfo{name: path.Base(key), mode: os.ModeDir | 0700, at: at}, nil
			}
		}
		return nil, e
	}
	if p.ETag == nil || p.ContentLength == nil {
		return nil, errors.New("Azure Files properties lack a stable identity")
	}
	at := time.Time{}
	if p.LastModified != nil {
		at = *p.LastModified
	}
	tag := ""
	if p.ETag != nil {
		tag = string(*p.ETag)
	}
	size := int64(0)
	if p.ContentLength != nil {
		size = *p.ContentLength
	}
	mode := os.FileMode(0600)
	if p.FileAttributes != nil && strings.Contains(strings.ToLower(*p.FileAttributes), "reparse") {
		mode |= os.ModeSymlink
	}
	if p.FileType != nil && strings.EqualFold(*p.FileType, "symlink") {
		mode |= os.ModeSymlink
	}
	return remoteInfo{name: path.Base(key), size: size, mode: mode, at: at, tag: tag}, nil
}
func (a *azureFiles) ReadDir(key string) ([]os.FileInfo, error) {
	d, e := a.dir(key)
	if e != nil {
		return nil, e
	}
	pager := d.NewListFilesAndDirectoriesPager(nil)
	out := []os.FileInfo{}
	for pager.More() {
		p, e := pager.NextPage(a.ctx)
		if e != nil {
			return nil, e
		}
		for _, v := range p.Segment.Directories {
			if v.Name != nil {
				out = append(out, remoteInfo{name: *v.Name, mode: os.ModeDir | 0700})
			}
		}
		for _, v := range p.Segment.Files {
			if v.Name != nil {
				size := int64(0)
				if v.Properties != nil && v.Properties.ContentLength != nil {
					size = *v.Properties.ContentLength
				}
				out = append(out, remoteInfo{name: *v.Name, size: size, mode: 0600})
			}
		}
	}
	return out, nil
}
func (a *azureFiles) Open(key string) (io.ReadCloser, error) {
	c, e := a.file(key)
	if e != nil {
		return nil, e
	}
	r, e := c.DownloadStream(a.ctx, nil)
	if e != nil {
		return nil, e
	}
	return r.Body, nil
}
func (a *azureFiles) UploadExclusive(key string, r io.Reader, size int64) error {
	if _, e := a.Stat(key); e == nil {
		return os.ErrExist
	}
	c, e := a.file(key)
	if e != nil {
		return e
	}
	if _, e = c.Create(a.ctx, size, nil); e != nil {
		return e
	}
	buf := make([]byte, 4<<20)
	var offset int64
	for offset < size {
		n, e := io.ReadFull(r, buf[:min(int64(len(buf)), size-offset)])
		if e != nil {
			return e
		}
		if _, e = c.UploadRange(a.ctx, offset, streaming.NopCloser(bytes.NewReader(buf[:n])), nil); e != nil {
			return e
		}
		offset += int64(n)
	}
	return nil
}
func (a *azureFiles) MkdirAll(key string) error {
	if key == "." || key == "" {
		return nil
	}
	if e := safeKey(key, false); e != nil {
		return e
	}
	parts := strings.Split(key, "/")
	for i := range parts {
		dir := strings.Join(parts[:i+1], "/")
		d, e := a.dir(dir)
		if e != nil {
			return e
		}
		if _, e = d.Create(a.ctx, nil); e != nil {
			var re *azcore.ResponseError
			if !errors.As(e, &re) || re.StatusCode != 409 {
				return e
			}
			if _, e = d.GetProperties(a.ctx, nil); e != nil {
				return e
			}
		}
	}
	return nil
}
func (a *azureFiles) PublishExclusive(from, to string) error {
	if e := safeKey(to, false); e != nil {
		return e
	}
	if strings.Contains(to, "?") {
		return errors.New("Azure Files destination names containing ? are unsupported")
	}
	c, e := a.file(from)
	if e != nil {
		return e
	}
	_, e = c.Rename(a.ctx, to, &file.RenameOptions{ReplaceIfExists: toPtrFalse()})
	return e
}
func toPtrFalse() *bool { return to.Ptr(false) }
func (a *azureFiles) Remove(key string) error {
	c, e := a.file(key)
	if e != nil {
		return e
	}
	_, e = c.Delete(a.ctx, nil)
	return e
}
func (a *azureFiles) Close() error { return nil }

type smbFS struct {
	share   *smb.Share
	session *smb.Session
	conn    net.Conn
	stop    func() bool
}

func openSMB(ctx context.Context, m Mount) (remoteFS, error) {
	port := m.Port
	if port == 0 {
		port = 445
	}
	conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.Server, fmt.Sprint(port)))
	if e != nil {
		return nil, e
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	d := smb.Dialer{Negotiator: smb.Negotiator{RequireMessageSigning: true}, Initiator: &smb.NTLMInitiator{User: m.Username, Password: m.Secret, Domain: m.Domain}}
	session, e := d.DialContext(ctx, conn)
	if e != nil {
		conn.Close()
		return nil, e
	}
	session = session.WithContext(ctx)
	share, e := session.Mount(m.Share)
	if e != nil {
		session.Logoff()
		conn.Close()
		return nil, e
	}
	f := &smbFS{share: share.WithContext(ctx), session: session, conn: conn}
	f.stop = context.AfterFunc(ctx, func() { conn.Close() })
	return f, nil
}
func (s *smbFS) Stat(key string) (os.FileInfo, error) {
	if e := safeKey(key, true); e != nil {
		return nil, e
	}
	if key == "" {
		key = "."
	}
	return s.share.Lstat(strings.ReplaceAll(key, "/", "\\"))
}
func (s *smbFS) ReadDir(key string) ([]os.FileInfo, error) {
	if e := safeKey(key, true); e != nil {
		return nil, e
	}
	return s.share.ReadDir(strings.ReplaceAll(key, "/", "\\"))
}
func (s *smbFS) Open(key string) (io.ReadCloser, error) {
	if e := safeKey(key, false); e != nil {
		return nil, e
	}
	return s.share.Open(strings.ReplaceAll(key, "/", "\\"))
}
func (s *smbFS) UploadExclusive(key string, r io.Reader, size int64) error {
	if e := safeKey(key, false); e != nil {
		return e
	}
	f, e := s.share.OpenFile(strings.ReplaceAll(key, "/", "\\"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(f, io.LimitReader(r, size+1))
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if n != size {
		return errors.New("upload size mismatch")
	}
	return nil
}
func (s *smbFS) MkdirAll(key string) error {
	if e := safeKey(key, true); e != nil {
		return e
	}
	return s.share.MkdirAll(strings.ReplaceAll(key, "/", "\\"), 0700)
}
func (s *smbFS) PublishExclusive(from, to string) error {
	if e := safeKey(to, false); e != nil {
		return e
	}
	return s.share.Rename(strings.ReplaceAll(from, "/", "\\"), strings.ReplaceAll(to, "/", "\\"))
}
func (s *smbFS) Remove(key string) error {
	if e := safeKey(key, false); e != nil {
		return e
	}
	return s.share.Remove(strings.ReplaceAll(key, "/", "\\"))
}
func (s *smbFS) Close() error {
	if s.stop != nil {
		s.stop()
	}
	s.share.Umount()
	s.session.Logoff()
	return s.conn.Close()
}
