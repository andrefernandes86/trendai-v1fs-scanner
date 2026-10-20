package localapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	nfs "github.com/vmware/go-nfs-client/nfs"
	"github.com/vmware/go-nfs-client/nfs/rpc"
	"github.com/vmware/go-nfs-client/nfs/xdr"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

// NFSv3 over TCP. Bounded, cancellable RPC calls; no privileged OS mounts.
type nfsFS struct {
	ctx  context.Context
	m    Mount
	port int
	root []byte
	auth rpc.Auth
}

func rpcRequest(ctx context.Context, server string, port int, header rpc.Header, args any, checkStatus bool) (*bytes.Reader, error) {
	var payload bytes.Buffer
	var nonce [4]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	id := binary.BigEndian.Uint32(nonce[:])
	if e := xdr.Write(&payload, struct {
		ID, Type uint32
		Header   rpc.Header
		Args     any
	}{id, 0, header, args}); e != nil {
		return nil, e
	}
	conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(server, fmt.Sprint(port)))
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	frame := make([]byte, 4+payload.Len())
	binary.BigEndian.PutUint32(frame, uint32(payload.Len())|0x80000000)
	copy(frame[4:], payload.Bytes())
	for len(frame) > 0 {
		n, e := conn.Write(frame)
		if e != nil {
			return nil, e
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		frame = frame[n:]
	}
	reply := []byte{}
	for {
		var length uint32
		if e = binary.Read(conn, binary.BigEndian, &length); e != nil {
			return nil, e
		}
		n := int(length & 0x7fffffff)
		if n > 8<<20 || len(reply)+n > 8<<20 {
			return nil, errors.New("RPC reply exceeds 8 MiB limit")
		}
		chunk := make([]byte, n)
		if _, e = io.ReadFull(conn, chunk); e != nil {
			return nil, e
		}
		reply = append(reply, chunk...)
		if length&0x80000000 != 0 {
			break
		}
	}
	r := bytes.NewReader(reply)
	var responseID, msgType, accepted, flavor, status uint32
	for _, v := range []*uint32{&responseID, &msgType, &accepted} {
		if e = binary.Read(r, binary.BigEndian, v); e != nil {
			return nil, e
		}
	}
	if responseID != id || msgType != 1 || accepted != 0 {
		return nil, errors.New("RPC request rejected")
	}
	if e = binary.Read(r, binary.BigEndian, &flavor); e != nil {
		return nil, e
	}
	if _, e = boundedOpaque(r, 400); e != nil {
		return nil, e
	}
	if e = binary.Read(r, binary.BigEndian, &status); e != nil {
		return nil, e
	}
	if status != 0 {
		return nil, fmt.Errorf("RPC accept status %d", status)
	}
	if checkStatus {
		if e = binary.Read(r, binary.BigEndian, &status); e != nil {
			return nil, e
		}
		if status != 0 {
			if status == 2 {
				return nil, os.ErrNotExist
			}
			if status == 17 {
				return nil, os.ErrExist
			}
			return nil, fmt.Errorf("NFS/MOUNT status %d", status)
		}
	}
	return r, nil
}
func boundedOpaque(r *bytes.Reader, max int) ([]byte, error) {
	var n uint32
	if e := binary.Read(r, binary.BigEndian, &n); e != nil {
		return nil, e
	}
	padding := (4 - int(n)%4) % 4
	if int64(n) > int64(max) || int64(n)+int64(padding) > int64(r.Len()) {
		return nil, errors.New("invalid RPC opaque length")
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, e
	}
	r.Seek(int64(padding), io.SeekCurrent)
	return b, nil
}
func rpcPort(ctx context.Context, server string, prog, vers uint32) (int, error) {
	h := rpc.Header{Rpcvers: 2, Prog: 100000, Vers: 2, Proc: 3, Cred: rpc.AuthNull, Verf: rpc.AuthNull}
	r, e := rpcRequest(ctx, server, 111, h, struct{ Prog, Vers, Proto, Port uint32 }{prog, vers, 6, 0}, false)
	if e != nil {
		return 0, e
	}
	var port uint32
	if e = binary.Read(r, binary.BigEndian, &port); e != nil {
		return 0, e
	}
	if port == 0 || port > 65535 {
		return 0, errors.New("NFSv3 service is not advertised by rpcbind")
	}
	return int(port), nil
}
func openNFS(ctx context.Context, m Mount) (remoteFS, error) {
	auth := nfsAuth(m)
	mountPort, e := rpcPort(ctx, m.Server, 100005, 3)
	if e != nil {
		return nil, e
	}
	r, e := rpcRequest(ctx, m.Server, mountPort, rpc.Header{Rpcvers: 2, Prog: 100005, Vers: 3, Proc: 1, Cred: auth, Verf: rpc.AuthNull}, m.Export, true)
	if e != nil {
		return nil, e
	}
	root, e := boundedOpaque(r, 128)
	if e != nil {
		return nil, e
	}
	port, e := rpcPort(ctx, m.Server, 100003, 3)
	if e != nil {
		return nil, e
	}
	return &nfsFS{ctx: ctx, m: m, port: port, root: root, auth: auth}, nil
}
func (n *nfsFS) call(proc uint32, args any) (*bytes.Reader, error) {
	return rpcRequest(n.ctx, n.m.Server, n.port, rpc.Header{Rpcvers: 2, Prog: 100003, Vers: 3, Proc: proc, Cred: n.auth, Verf: rpc.AuthNull}, args, true)
}
func (n *nfsFS) lookup(key string) ([]byte, os.FileInfo, error) {
	if e := safeKey(key, true); e != nil {
		return nil, nil, e
	}
	fh := n.root
	var info os.FileInfo
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." {
			continue
		}
		r, e := n.call(3, nfs.Diropargs3{FH: fh, Filename: part})
		if e != nil {
			return nil, nil, e
		}
		fh, e = boundedOpaque(r, 128)
		if e != nil {
			return nil, nil, e
		}
		var attr nfs.PostOpAttr
		if e = xdr.Read(r, &attr); e != nil {
			return nil, nil, e
		}
		if !attr.IsSet {
			return nil, nil, errors.New("NFS attributes missing")
		}
		info = nfsInfo(path.Base(key), attr.Attr)
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("NFS symlink access rejected")
		}
	}
	if info == nil {
		r, e := n.call(1, fh)
		if e != nil {
			return nil, nil, e
		}
		var attr nfs.Fattr
		if e = xdr.Read(r, &attr); e != nil {
			return nil, nil, e
		}
		info = nfsInfo(path.Base(key), attr)
	}
	return fh, info, nil
}
func (n *nfsFS) Stat(key string) (os.FileInfo, error) { _, info, e := n.lookup(key); return info, e }
func (n *nfsFS) ReadDir(key string) ([]os.FileInfo, error) {
	fh, _, e := n.lookup(key)
	if e != nil {
		return nil, e
	}
	out := []os.FileInfo{}
	var cookie, verifier uint64
	for {
		r, e := n.call(17, struct {
			FH                 []byte
			Cookie, Verifier   uint64
			DirCount, MaxCount uint32
		}{fh, cookie, verifier, 4096, 32768})
		if e != nil {
			return nil, e
		}
		var attr nfs.PostOpAttr
		if e = xdr.Read(r, &attr); e != nil {
			return nil, e
		}
		if e = binary.Read(r, binary.BigEndian, &verifier); e != nil {
			return nil, e
		}
		before := cookie
		for {
			var follows uint32
			if e = binary.Read(r, binary.BigEndian, &follows); e != nil {
				return nil, e
			}
			if follows == 0 {
				break
			}
			var id uint64
			if e = binary.Read(r, binary.BigEndian, &id); e != nil {
				return nil, e
			}
			name, e := boundedOpaque(r, 255)
			if e != nil {
				return nil, e
			}
			if e = binary.Read(r, binary.BigEndian, &cookie); e != nil {
				return nil, e
			}
			var itemAttr nfs.PostOpAttr
			if e = xdr.Read(r, &itemAttr); e != nil {
				return nil, e
			}
			var hasFH uint32
			if e = binary.Read(r, binary.BigEndian, &hasFH); e != nil {
				return nil, e
			}
			if hasFH != 0 {
				if _, e = boundedOpaque(r, 128); e != nil {
					return nil, e
				}
			}
			if validShareName(string(name)) {
				if itemAttr.IsSet {
					out = append(out, nfsInfo(string(name), itemAttr.Attr))
				} else {
					_, info, e := n.lookup(path.Join(key, string(name)))
					if e != nil {
						return nil, e
					}
					out = append(out, remoteInfo{name: string(name), size: info.Size(), mode: info.Mode(), at: info.ModTime()})
				}
			}
			if len(out) > 100000 {
				return nil, errors.New("directory exceeds 100000 entry limit")
			}
		}
		var eof uint32
		if e = binary.Read(r, binary.BigEndian, &eof); e != nil {
			return nil, e
		}
		if eof != 0 {
			break
		}
		if before == cookie {
			return nil, errors.New("NFS directory cursor did not advance")
		}
	}
	return out, nil
}

type nfsReader struct {
	fs     *nfsFS
	fh     []byte
	offset uint64
	eof    bool
}

func (n *nfsFS) Open(key string) (io.ReadCloser, error) {
	fh, info, e := n.lookup(key)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return &nfsReader{fs: n, fh: fh}, nil
}
func (f *nfsReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if f.eof {
		return 0, io.EOF
	}
	r, e := f.fs.call(6, struct {
		FH     []byte
		Offset uint64
		Count  uint32
	}{f.fh, f.offset, uint32(min(len(p), 65536))})
	if e != nil {
		return 0, e
	}
	var attr nfs.PostOpAttr
	if e = xdr.Read(r, &attr); e != nil {
		return 0, e
	}
	var count, eof uint32
	if e = binary.Read(r, binary.BigEndian, &count); e != nil {
		return 0, e
	}
	if e = binary.Read(r, binary.BigEndian, &eof); e != nil {
		return 0, e
	}
	b, e := boundedOpaque(r, min(len(p), 65536))
	if e != nil {
		return 0, e
	}
	if len(b) != int(count) {
		return 0, errors.New("NFS read count mismatch")
	}
	n := copy(p, b)
	f.offset += uint64(n)
	f.eof = eof != 0
	if n == 0 && !f.eof {
		return 0, io.ErrNoProgress
	}
	return n, nil
}
func (f *nfsReader) Close() error { return nil }
func (n *nfsFS) UploadExclusive(key string, r io.Reader, size int64) error {
	if e := safeKey(key, false); e != nil {
		return e
	}
	parent, _, e := n.lookup(path.Dir(key))
	if e != nil {
		return e
	}
	_, e = n.call(8, struct {
		Where nfs.Diropargs3
		Mode  uint32
		Attr  nfs.Sattr3
	}{nfs.Diropargs3{FH: parent, Filename: path.Base(key)}, 1, nfs.Sattr3{Mode: nfs.SetMode{SetIt: true, Mode: 0600}}})
	if e != nil {
		return e
	}
	fh, _, e := n.lookup(key)
	if e != nil {
		return e
	}
	buf := make([]byte, 65536)
	var offset int64
	for offset < size {
		count, e := io.ReadFull(r, buf[:min(int64(len(buf)), size-offset)])
		if e != nil {
			return e
		}
		reply, e := n.call(7, struct {
			FH            []byte
			Offset        uint64
			Count, Stable uint32
			Data          []byte
		}{fh, uint64(offset), uint32(count), 2, buf[:count]})
		if e != nil {
			return e
		}
		var wcc nfs.WccData
		if e = xdr.Read(reply, &wcc); e != nil {
			return e
		}
		var written uint32
		if e = binary.Read(reply, binary.BigEndian, &written); e != nil {
			return e
		}
		if written == 0 || written > uint32(count) {
			return io.ErrShortWrite
		}
		offset += int64(written)
		if int(written) != count {
			return io.ErrShortWrite
		}
	}
	_, e = n.call(21, struct {
		FH     []byte
		Offset uint64
		Count  uint32
	}{fh, 0, 0})
	return e
}
func (n *nfsFS) MkdirAll(key string) error {
	if e := safeKey(key, true); e != nil {
		return e
	}
	parts := strings.Split(key, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		if p == "" || p == "." {
			continue
		}
		if _, info, e := n.lookup(p); e == nil {
			if !info.IsDir() {
				return errors.New("not a directory")
			}
			continue
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		parent, _, e := n.lookup(path.Dir(p))
		if e != nil {
			return e
		}
		_, e = n.call(9, struct {
			Where nfs.Diropargs3
			Attr  nfs.Sattr3
		}{nfs.Diropargs3{FH: parent, Filename: path.Base(p)}, nfs.Sattr3{Mode: nfs.SetMode{SetIt: true, Mode: 0700}}})
		if e != nil && !errors.Is(e, os.ErrExist) {
			return e
		}
	}
	return nil
}
func (n *nfsFS) PublishExclusive(from, to string) error {
	if e := safeKey(to, false); e != nil {
		return e
	}
	source, _, e := n.lookup(from)
	if e != nil {
		return e
	}
	parent, _, e := n.lookup(path.Dir(to))
	if e != nil {
		return e
	}
	_, e = n.call(15, struct {
		FH    []byte
		Where nfs.Diropargs3
	}{source, nfs.Diropargs3{FH: parent, Filename: path.Base(to)}})
	return e
}
func (n *nfsFS) Remove(key string) error {
	if e := safeKey(key, false); e != nil {
		return e
	}
	parent, _, e := n.lookup(path.Dir(key))
	if e != nil {
		return e
	}
	_, e = n.call(12, nfs.Diropargs3{FH: parent, Filename: path.Base(key)})
	return e
}
func (n *nfsFS) Close() error { return nil }
func nfsExports(ctx context.Context, m Mount) ([]string, error) {
	port, e := rpcPort(ctx, m.Server, 100005, 3)
	if e != nil {
		return nil, e
	}
	r, e := rpcRequest(ctx, m.Server, port, rpc.Header{Rpcvers: 2, Prog: 100005, Vers: 3, Proc: 5, Cred: nfsAuth(m), Verf: rpc.AuthNull}, struct{}{}, false)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for {
		var follows uint32
		if e = binary.Read(r, binary.BigEndian, &follows); e != nil {
			return nil, e
		}
		if follows == 0 {
			break
		}
		name, e := boundedOpaque(r, 1024)
		if e != nil {
			return nil, e
		}
		out = append(out, string(name))
		for {
			var more uint32
			if e = binary.Read(r, binary.BigEndian, &more); e != nil {
				return nil, e
			}
			if more == 0 {
				break
			}
			if _, e = boundedOpaque(r, 255); e != nil {
				return nil, e
			}
		}
		if len(out) > 10000 {
			return nil, errors.New("too many exports")
		}
	}
	return out, nil
}

func nfsAuth(m Mount) rpc.Auth {
	a := rpc.NewAuthUnix("trendai-scanner", m.UID, m.GID)
	a.Gids = m.GID
	return a.Auth()
}
func nfsInfo(name string, a nfs.Fattr) os.FileInfo {
	mode := os.FileMode(a.FileMode).Perm()
	switch a.Type {
	case nfs.NF3Dir:
		mode |= os.ModeDir
	case nfs.NF3Lnk:
		mode |= os.ModeSymlink
	case nfs.NF3Reg:
	default:
		mode |= os.ModeIrregular
	}
	return remoteInfo{name: name, size: a.Size(), mode: mode, at: a.ModTime(), tag: fmt.Sprintf("nfs:%d:%d:%d:%d:%d:%d", a.Fileid, a.Filesize, a.Mtime.Seconds, a.Mtime.Nseconds, a.Ctime.Seconds, a.Ctime.Nseconds)}
}

// NFSv3 RENAME is atomic within the export. The target namespace is scanner-owned
// and unique per durable job; an existing target is handled by handoff recovery.
func (n *nfsFS) Claim(from, to string) error {
	if e := safeKey(from, false); e != nil {
		return e
	}
	if e := safeKey(to, false); e != nil {
		return e
	}
	if _, e := n.lookupClaimTarget(to); e == nil {
		return os.ErrExist
	} else if !os.IsNotExist(e) {
		return e
	}
	fromDir, _, e := n.lookup(path.Dir(from))
	if e != nil {
		return e
	}
	toDir, _, e := n.lookup(path.Dir(to))
	if e != nil {
		return e
	}
	_, e = n.call(14, struct {
		From nfs.Diropargs3
		To   nfs.Diropargs3
	}{nfs.Diropargs3{FH: fromDir, Filename: path.Base(from)}, nfs.Diropargs3{FH: toDir, Filename: path.Base(to)}})
	return e
}
func (n *nfsFS) lookupClaimTarget(key string) (os.FileInfo, error) { return n.Stat(key) }
