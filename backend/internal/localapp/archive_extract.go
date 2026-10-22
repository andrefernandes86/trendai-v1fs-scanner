package localapp

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type ArchiveEntry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Depth  int    `json:"depth"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind,omitempty"`
}
type ExtractRequest struct {
	Source, Name, Workspace string
	Options                 ArchiveOptions
}
type ExtractManifest struct {
	Entries  []ArchiveEntry `json:"entries"`
	Count    int            `json:"entryCount"`
	Bytes    int64          `json:"expandedBytes"`
	Depth    int            `json:"depth"`
	Complete bool           `json:"complete"`
	Error    string         `json:"error,omitempty"`
}

func archiveKind(file, name string) (string, error) {
	f, e := os.Open(file)
	if e != nil {
		return "", e
	}
	defer f.Close()
	b := make([]byte, 512)
	n, e := io.ReadFull(f, b)
	if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
		return "", e
	}
	b = b[:n]
	lower := strings.ToLower(name)
	switch {
	case len(b) >= 4 && (string(b[:4]) == "PK\x03\x04" || string(b[:4]) == "PK\x05\x06" || string(b[:4]) == "PK\x07\x08"):
		return "zip", nil
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip", nil
	case len(b) >= 262 && string(b[257:262]) == "ustar":
		return "tar", nil
	case len(b) >= 6 && (string(b[:6]) == "7z\xbc\xaf\x27\x1c" || string(b[:6]) == "\xfd7zXZ\x00"):
		return "unsupported", nil
	case len(b) >= 4 && (string(b[:4]) == "Rar!" || string(b[:4]) == "\x28\xb5\x2f\xfd"):
		return "unsupported", nil
	case len(b) >= 4 && (string(b[:4]) == "MSCF" || string(b[:4]) == "\x04\x22\x4d\x18"):
		return "unsupported", nil
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x9d:
		return "unsupported", nil
	case len(b) >= 3 && string(b[:3]) == "BZh":
		return "unsupported", nil
	}
	for _, ext := range []string{".zip", ".docx", ".xlsx", ".pptx", ".jar", ".odt", ".ods", ".epub"} {
		if strings.HasSuffix(lower, ext) {
			return "zip", nil
		}
	}
	for _, ext := range []string{".gz", ".tgz"} {
		if strings.HasSuffix(lower, ext) {
			return "gzip", nil
		}
	}
	if strings.HasSuffix(lower, ".tar") {
		return "tar", nil
	}
	for _, ext := range []string{".7z", ".rar", ".bz2", ".xz", ".zst", ".cab", ".iso"} {
		if strings.HasSuffix(lower, ext) {
			return "unsupported", nil
		}
	}
	return "", nil
}
func safeArchiveName(name string) bool {
	if name == "" || len(name) > 1024 || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

type archiveExtractor struct {
	ctx         context.Context
	req         ExtractRequest
	m           ExtractManifest
	ratioBudget int64
}

func ExtractArchive(ctx context.Context, r ExtractRequest) ExtractManifest {
	r.Options = r.Options.Defaults()
	x := archiveExtractor{ctx: ctx, req: r}
	if e := r.Options.Validate(); e != nil {
		x.m.Error = e.Error()
		return x.m
	}
	st, e := os.Stat(r.Source)
	if e != nil {
		x.m.Error = "Cannot read archive source"
		return x.m
	}
	x.ratioBudget = r.Options.MaxBytes
	if st.Size() <= r.Options.MaxBytes/int64(r.Options.MaxRatio) {
		x.ratioBudget = st.Size() * int64(r.Options.MaxRatio)
	}
	if e = x.walk(r.Source, r.Name, 1); e != nil {
		x.m.Error = e.Error()
		return x.m
	}
	x.m.Complete = true
	return x.m
}
func (x *archiveExtractor) check() error {
	if e := x.ctx.Err(); e != nil {
		return errors.New("Archive extraction time limit exceeded")
	}
	return nil
}
func (x *archiveExtractor) entry(name string) error {
	if e := x.check(); e != nil {
		return e
	}
	x.m.Count++
	if x.m.Count > x.req.Options.MaxFiles {
		return errors.New("Archive entry-count limit exceeded")
	}
	if !safeArchiveName(name) {
		return errors.New("Unsafe archive entry path")
	}
	return nil
}
func (x *archiveExtractor) materialize(r io.Reader, logical string, depth int, declared int64) (ArchiveEntry, error) {
	out := ArchiveEntry{Name: logical, Depth: depth}
	if len(logical) > 2048 {
		return out, errors.New("Nested archive path is too long")
	}
	remaining := min(x.req.Options.MaxBytes-x.m.Bytes, x.ratioBudget-x.m.Bytes, x.req.Options.MaxEntryBytes)
	if remaining < 0 || declared > remaining {
		return out, errors.New("Archive expanded-size or expansion-ratio limit exceeded")
	}
	target := filepath.Join(x.req.Workspace, fmt.Sprintf("member-%06d", x.m.Count))
	f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return out, errors.New("Cannot create archive workspace member")
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(&archiveContextReader{x.ctx, r}, remaining+1))
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		os.Remove(target)
		return out, errors.New("Archive member is corrupt or could not be extracted")
	}
	if n > remaining {
		os.Remove(target)
		return out, errors.New("Archive expanded-size or expansion-ratio limit exceeded")
	}
	if declared >= 0 && n != declared {
		os.Remove(target)
		return out, errors.New("Archive member size mismatch")
	}
	x.m.Bytes += n
	out.Path = target
	out.Size = n
	out.SHA256 = hex.EncodeToString(h.Sum(nil))
	out.Kind, e = archiveKind(target, logical)
	if e != nil {
		return out, e
	}
	x.m.Entries = append(x.m.Entries, out)
	return out, nil
}

type archiveContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *archiveContextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func (x *archiveExtractor) recurse(e ArchiveEntry, depth int) error {
	if e.Kind == "" {
		return nil
	}
	return x.walk(e.Path, e.Name, depth+1)
}
func (x *archiveExtractor) walk(file, logical string, depth int) error {
	if e := x.check(); e != nil {
		return e
	}
	if depth > x.req.Options.MaxDepth {
		return errors.New("Archive nesting-depth limit exceeded")
	}
	x.m.Depth = max(x.m.Depth, depth)
	kind, e := archiveKind(file, logical)
	if e != nil {
		return e
	}
	switch kind {
	case "zip":
		z, e := zip.OpenReader(file)
		if e != nil {
			return errors.New("Invalid or unsupported ZIP archive")
		}
		defer z.Close()
		if len(z.File) > x.req.Options.MaxFiles-x.m.Count {
			return errors.New("Archive entry-count limit exceeded")
		}
		seen := map[string]bool{}
		for _, f := range z.File {
			if e = x.entry(f.Name); e != nil {
				return e
			}
			canonical := path.Clean(f.Name)
			if seen[canonical] {
				return errors.New("Duplicate archive entry path")
			}
			seen[canonical] = true
			if f.Flags&1 != 0 {
				return errors.New("Encrypted archive entry is unsupported")
			}
			mode := f.Mode()
			if mode.IsDir() {
				continue
			}
			if !mode.IsRegular() {
				return errors.New("Archive links and special files are forbidden")
			}
			if f.UncompressedSize64 > uint64(x.req.Options.MaxEntryBytes) {
				return errors.New("Archive member-size limit exceeded")
			}
			if f.CompressedSize64 == 0 && f.UncompressedSize64 > 0 {
				return errors.New("Invalid compressed entry size")
			}
			if f.CompressedSize64 > 0 && f.UncompressedSize64/f.CompressedSize64 > uint64(x.req.Options.MaxRatio) {
				return errors.New("Archive entry expansion-ratio limit exceeded")
			}
			reader, e := f.Open()
			if e != nil {
				return errors.New("Unsupported ZIP compression method")
			}
			child, e := x.materialize(reader, logical+"!/"+f.Name, depth, int64(f.UncompressedSize64))
			ce := reader.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return errors.New("Corrupt ZIP member")
			}
			if e = x.recurse(child, depth); e != nil {
				return e
			}
		}
	case "tar":
		f, e := os.Open(file)
		if e != nil {
			return e
		}
		defer f.Close()
		tr := tar.NewReader(f)
		seen := map[string]bool{}
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return errors.New("Invalid TAR archive")
			}
			if e = x.entry(h.Name); e != nil {
				return e
			}
			canonical := path.Clean(h.Name)
			if seen[canonical] {
				return errors.New("Duplicate archive entry path")
			}
			seen[canonical] = true
			for key := range h.PAXRecords {
				if strings.HasPrefix(key, "GNU.sparse") {
					return errors.New("Sparse TAR entries are forbidden")
				}
			}
			if h.Typeflag == tar.TypeDir {
				continue
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
				return errors.New("TAR links, sparse and special files are forbidden")
			}
			child, e := x.materialize(tr, logical+"!/"+h.Name, depth, h.Size)
			if e != nil {
				return e
			}
			if e = x.recurse(child, depth); e != nil {
				return e
			}
		}
		buf := make([]byte, 32<<10)
		for {
			if e = x.check(); e != nil {
				return e
			}
			n, e := f.Read(buf)
			for _, b := range buf[:n] {
				if b != 0 {
					return errors.New("Uninspected trailing TAR payload")
				}
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				return e
			}
		}
	case "gzip":
		f, e := os.Open(file)
		if e != nil {
			return e
		}
		defer f.Close()
		br := bufio.NewReader(f)
		gz, e := gzip.NewReader(br)
		if e != nil {
			return errors.New("Invalid GZIP stream")
		}
		defer gz.Close()
		gz.Multistream(false)
		name := gz.Name
		if name == "" {
			name = strings.TrimSuffix(path.Base(logical), ".gz")
			if strings.HasSuffix(name, ".tgz") {
				name = strings.TrimSuffix(name, ".tgz") + ".tar"
			}
			if name == path.Base(logical) {
				name = "payload"
			}
		}
		if e = x.entry(name); e != nil {
			return e
		}
		child, e := x.materialize(gz, logical+"!/"+name, depth, -1)
		if e != nil {
			return e
		}
		if _, e = br.Peek(1); e != io.EOF {
			return errors.New("Concatenated or trailing GZIP payload is unsupported")
		}
		if e = x.recurse(child, depth); e != nil {
			return e
		}
	case "unsupported":
		return errors.New("Unsupported archive format")
	default:
		return errors.New("Archive format could not be identified")
	}
	return nil
}
