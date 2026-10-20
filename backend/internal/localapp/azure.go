package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	client "github.com/trendmicro/tm-v1-fs-golang-sdk"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var storageTransport policy.Transporter
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var resourcePattern = regexp.MustCompile(`(?i)/storageAccounts/([^/]+)/blobServices/default/containers/([^/]+)$`)
var accountPattern = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
var containerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func (m *Mount) Validate() error {
	if m.ResourceID != "" {
		r := resourcePattern.FindStringSubmatch(m.ResourceID)
		if r == nil {
			return errors.New("use the full Azure container resource ID")
		}
		m.Account = r[1]
		m.Container = r[2]
	}
	if !idPattern.MatchString(m.ID) || strings.TrimSpace(m.Name) == "" || !accountPattern.MatchString(m.Account) || !containerPattern.MatchString(m.Container) || strings.Contains(m.Container, "--") {
		return errors.New("invalid connection name, account, or container")
	}
	if m.Prefix != "" && !core.ValidKey(m.Prefix) {
		return errors.New("invalid prefix")
	}
	if m.AuthType != "accountKey" && m.AuthType != "sas" {
		return errors.New("select account key or SAS authentication")
	}
	if strings.TrimSpace(m.Secret) == "" {
		return errors.New("credentials required")
	}
	if m.AuthType == "sas" {
		q, e := url.ParseQuery(strings.TrimPrefix(m.Secret, "?"))
		if e != nil || q.Get("sig") == "" {
			return errors.New("invalid SAS token")
		}
	}
	return nil
}
func (m Mount) BaseURL() string {
	return fmt.Sprintf("https://%s.blob.core.windows.net/%s", m.Account, m.Container)
}
func (m Mount) ContainerClient() (*container.Client, error) {
	if m.AuthType == "accountKey" {
		cred, e := container.NewSharedKeyCredential(m.Account, m.Secret)
		if e != nil {
			return nil, e
		}
		return container.NewClientWithSharedKeyCredential(m.BaseURL(), cred, &container.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: storageTransport}})
	}
	return container.NewClientWithNoCredential(m.BaseURL()+"?"+strings.TrimPrefix(m.Secret, "?"), &container.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: storageTransport}})
}
func (m Mount) BlobClient(key, version string) (*blob.Client, error) {
	if !core.ValidKey(key) {
		return nil, errors.New("invalid blob path")
	}
	c, e := m.ContainerClient()
	if e != nil {
		return nil, e
	}
	b := c.NewBlobClient(key)
	if version != "" {
		return b.WithVersionID(version)
	}
	return b, nil
}

type BlobEntry struct {
	Key      string `json:"key"`
	Size     int64  `json:"size"`
	ETag     string `json:"etag"`
	Modified string `json:"modified"`
	Complete bool   `json:"complete"`
}

func ListBlobs(ctx context.Context, m Mount, prefix, marker string) ([]BlobEntry, string, error) {
	c, e := m.ContainerClient()
	if e != nil {
		return nil, "", e
	}
	opts := &container.ListBlobsFlatOptions{Prefix: to.Ptr(m.Prefix + prefix), MaxResults: to.Ptr(int32(200)), Include: container.ListBlobsInclude{Metadata: true}}
	if marker != "" {
		opts.Marker = &marker
	}
	pager := c.NewListBlobsFlatPager(opts)
	out := []BlobEntry{}
	if !pager.More() {
		return out, "", nil
	}
	p, e := pager.NextPage(ctx)
	if e != nil {
		return nil, "", e
	}
	for _, b := range p.Segment.BlobItems {
		if b.Name == nil || b.Properties == nil || b.Properties.ETag == nil || b.Properties.ContentLength == nil {
			continue
		}
		v := BlobEntry{Key: *b.Name, Size: *b.Properties.ContentLength, ETag: string(*b.Properties.ETag)}
		if b.Properties.LastModified != nil {
			v.Modified = b.Properties.LastModified.UTC().Format("2006-01-02T15:04:05Z")
		}
		if val := b.Metadata["v1fs-complete"]; val != nil && *val == "true" {
			v.Complete = true
		}
		out = append(out, v)
	}
	next := ""
	if p.NextMarker != nil {
		next = *p.NextMarker
	}
	return out, next, nil
}
func Download(ctx context.Context, s Snapshot, dir string) (name, digest string, err error) {
	if s.Size > 2<<30 {
		return "", "", errors.New("file exceeds 2 GiB host policy")
	}
	c, e := s.Source.BlobClient(s.Key, s.Version)
	if e != nil {
		return "", "", e
	}
	r, e := c.DownloadStream(ctx, &blob.DownloadStreamOptions{AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: to.Ptr(azcore.ETag(s.ETag))}}})
	if e != nil {
		return "", "", e
	}
	defer r.Body.Close()
	f, e := os.CreateTemp(dir, "scan-*")
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
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, s.Size+1))
	if e != nil {
		return "", "", e
	}
	if n != s.Size {
		return "", "", errors.New("source size changed")
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}
func Route(ctx context.Context, m Mount, key, path, digest, job, verdict string, size int64) error {
	c, e := m.ContainerClient()
	if e != nil {
		return e
	}
	target := c.NewBlockBlobClient(key)
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = target.UploadFile(ctx, f, &blockblob.UploadFileOptions{AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfNoneMatch: to.Ptr(azcore.ETag("*"))}}, Metadata: map[string]*string{"job": &job, "sha256": &digest, "verdict": &verdict}})
	if e != nil {
		var re *azcore.ResponseError
		if !errors.As(e, &re) || re.StatusCode != 412 {
			return e
		}
	}
	r, e := target.DownloadStream(ctx, nil)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r.Body, size+1))
	if e != nil {
		return e
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("destination digest verification failed")
	}
	return nil
}
func (s Scanner) Validate() error {
	if s.Type != "cloud" && s.Type != "local" {
		return errors.New("select cloud or local scanner")
	}
	if s.Type == "cloud" {
		if s.APIKey == "" {
			return errors.New("API key required for cloud scanner")
		}
		valid := false
		for _, r := range client.SupportedV1Regions {
			if r == s.Region {
				valid = true
			}
		}
		if !valid {
			return errors.New("invalid cloud region")
		}
	} else {
		host, port, e := net.SplitHostPort(s.Address)
		if e != nil || host == "" || port == "" || strings.ContainsAny(s.Address, "/@?#") {
			return errors.New("local service address must be host:port")
		}
	}
	return nil
}

// The SDK documents TM_AM_SERVER_ADDR for self-hosted gRPC scanners. Serialize
// initialization so process environment overrides never mix between clients.
func (a *App) Scan(ctx context.Context, path string, s Scanner, p Profile) ([]byte, error) {
	if a.scanFn != nil {
		return a.scanFn(ctx, path, s, p)
	}
	for !a.scanMu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer a.scanMu.Unlock()
	names := []string{"TM_AM_SERVER_ADDR", "TM_AM_DISABLE_TLS", "TM_AM_DISABLE_CERT_VERIFY", "TM_AM_AUTH_KEY_NOT_REQUIRED", "TM_AM_AUTH_KEY"}
	old := map[string]*string{}
	for _, n := range names {
		if v, ok := os.LookupEnv(n); ok {
			v2 := v
			old[n] = &v2
		}
		os.Unsetenv(n)
	}
	defer func() {
		for _, n := range names {
			if v := old[n]; v != nil {
				os.Setenv(n, *v)
			} else {
				os.Unsetenv(n)
			}
		}
	}()
	region := s.Region
	if s.Type == "local" {
		region = "us-east-1"
		os.Setenv("TM_AM_SERVER_ADDR", s.Address)
		if !s.TLS {
			os.Setenv("TM_AM_DISABLE_TLS", "1")
		}
		if s.APIKey == "" {
			os.Setenv("TM_AM_AUTH_KEY_NOT_REQUIRED", "1")
		}
	}
	c, e := client.NewClientWithOptions(s.APIKey, region, client.WithV1Direct(true), client.WithPML(p.PML), client.WithActiveContent(p.ActiveContent), client.WithFeedback(p.Feedback), client.WithVerbose(p.Verbose), client.WithDigest(p.Digest))
	if e != nil {
		return nil, e
	}
	defer c.Destroy()
	raw, e := c.ScanFileWithContext(ctx, path, []string{"app:trendai-v1fs", "profile:" + p.ID})
	return []byte(raw), e
}
