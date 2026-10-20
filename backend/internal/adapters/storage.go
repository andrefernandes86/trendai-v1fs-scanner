package adapters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/file"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"io"
	"net/url"
	"os"
	"strings"
)

type Storage struct{ Credential azcore.TokenCredential }

func ObjectURL(s core.Source, key string) string {
	suffix := "blob"
	if s.Kind == "files" {
		suffix = "file"
	}
	parts := strings.Split(key, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return fmt.Sprintf("https://%s.%s.core.windows.net/%s/%s", s.Account, suffix, s.Container, strings.Join(parts, "/"))
}
func (s *Storage) Download(ctx context.Context, src core.Source, j core.Job) (path, digest string, err error) {
	if j.Size > src.MaxBytes {
		return "", "", errors.New("size policy exceeded")
	}
	var body io.ReadCloser
	if src.Kind == "blob" {
		c, e := blob.NewClient(ObjectURL(src, j.Key), s.Credential, nil)
		if e != nil {
			return "", "", e
		}
		if j.Version != "" {
			c, e = c.WithVersionID(j.Version)
			if e != nil {
				return "", "", e
			}
		}
		r, e := c.DownloadStream(ctx, &blob.DownloadStreamOptions{AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: to.Ptr(azcore.ETag(j.ETag))}}})
		if e != nil {
			return "", "", e
		}
		body = r.Body
	} else {
		c, e := file.NewClient(ObjectURL(src, j.Key), s.Credential, &file.ClientOptions{FileRequestIntent: to.Ptr(file.ShareTokenIntentBackup)})
		if e != nil {
			return "", "", e
		}
		r, e := c.DownloadStream(ctx, nil)
		if e != nil {
			return "", "", e
		}
		if r.ETag == nil || string(*r.ETag) != j.ETag {
			r.Body.Close()
			return "", "", errors.New("source identity changed")
		}
		body = r.Body
	}
	defer body.Close()
	f, e := os.CreateTemp("", "v1fs-*")
	if e != nil {
		return "", "", e
	}
	defer f.Close()
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, src.MaxBytes+1))
	if e != nil {
		return "", "", e
	}
	if n != j.Size || n > src.MaxBytes {
		return "", "", errors.New("source size changed")
	}
	if e = f.Sync(); e != nil {
		return "", "", e
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}
func (s *Storage) Route(ctx context.Context, dest string, j core.Job, path string) (string, error) {
	if !core.StorageURL(dest, "blob") {
		return "", errors.New("invalid destination")
	}
	target := strings.TrimSuffix(dest, "/") + "/" + j.ID
	c, e := blockblob.NewClient(target, s.Credential, nil)
	if e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	_, e = c.UploadFile(ctx, f, &blockblob.UploadFileOptions{AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfNoneMatch: to.Ptr(azcore.ETag("*"))}}, Metadata: map[string]*string{"job": to.Ptr(j.ID), "sha256": to.Ptr(j.Digest), "verdict": to.Ptr(j.Verdict)}})
	if e != nil {
		var re *azcore.ResponseError
		if !errors.As(e, &re) || re.StatusCode != 412 {
			return "", e
		}
	}
	r, e := c.DownloadStream(ctx, nil)
	if e != nil {
		return "", e
	}
	defer r.Body.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r.Body, j.Size+1))
	if e != nil {
		return "", e
	}
	if n != j.Size || hex.EncodeToString(h.Sum(nil)) != j.Digest {
		return "", errors.New("destination verification failed")
	}
	return target, nil
}
