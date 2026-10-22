package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"hash/crc32"
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
	if m.Type() != "blob" {
		return m.validateShare()
	}
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
	if m.Type() != "blob" {
		return m.shareURL()
	}
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
	Tags                 map[string]string `json:"tags,omitempty"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	TagsUnavailable      bool              `json:"tagsUnavailable,omitempty"`
	ScanJobID            string            `json:"scanJobId,omitempty"`
	Verdict              string            `json:"verdict,omitempty"`
	Detections           []Detection       `json:"detections,omitempty"`
	ScanResponseRecorded bool              `json:"scanResponseRecorded"`
	Key                  string            `json:"key"`
	Size                 int64             `json:"size"`
	ETag                 string            `json:"etag"`
	Modified             string            `json:"modified"`
	Complete             bool              `json:"complete"`
}

func ListBlobs(ctx context.Context, m Mount, prefix, marker string, nativeTags ...bool) ([]BlobEntry, string, error) {
	if m.Type() != "blob" {
		return listShare(ctx, m, prefix, marker)
	}
	c, e := m.ContainerClient()
	if e != nil {
		return nil, "", e
	}
	wantTags := len(nativeTags) > 0 && nativeTags[0] && m.Kind != "adls"
	opts := &container.ListBlobsFlatOptions{Prefix: to.Ptr(m.Prefix + prefix), MaxResults: to.Ptr(int32(200)), Include: container.ListBlobsInclude{Metadata: true, Tags: wantTags}}
	if marker != "" {
		opts.Marker = &marker
	}
	pager := c.NewListBlobsFlatPager(opts)
	out := []BlobEntry{}
	if !pager.More() {
		return out, "", nil
	}
	p, e := pager.NextPage(ctx)
	tagsUnavailable := false
	if e != nil {
		var response *azcore.ResponseError
		if wantTags && errors.As(e, &response) && response.StatusCode == 403 {
			opts.Include.Tags = false
			pager = c.NewListBlobsFlatPager(opts)
			p, e = pager.NextPage(ctx)
			tagsUnavailable = true
		}
	}
	if e != nil {
		return nil, "", e
	}
	for _, b := range p.Segment.BlobItems {
		if b.Name == nil || b.Properties == nil || b.Properties.ETag == nil || b.Properties.ContentLength == nil {
			continue
		}
		if m.Kind == "adls" && (isADLSDirectory(b.Metadata) || strings.HasSuffix(*b.Name, ".v1fs-tags.json")) {
			continue
		}
		v := BlobEntry{Tags: map[string]string{}, Metadata: map[string]string{}, TagsUnavailable: tagsUnavailable, Key: *b.Name, Size: *b.Properties.ContentLength, ETag: string(*b.Properties.ETag)}
		for key, value := range b.Metadata {
			if value != nil {
				v.Metadata[key] = *value
			}
		}
		if m.Kind == "adls" {
			v.Tags = adlsResultTags(b.Metadata)
		}
		if b.BlobTags != nil {
			for _, tag := range b.BlobTags.BlobTagSet {
				if tag.Key != nil && tag.Value != nil {
					v.Tags[*tag.Key] = *tag.Value
				}
			}
		}
		if b.Properties.LastModified != nil {
			v.Modified = b.Properties.LastModified.UTC().Format("2006-01-02T15:04:05Z")
		}
		if completeMetadata(b.Metadata) {
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
	name, digest, _, err = DownloadChecksums(ctx, s, dir)
	return
}
func DownloadChecksums(ctx context.Context, s Snapshot, dir string) (name, digest, crc string, err error) {
	if s.Source.Type() != "blob" {
		return downloadShareChecksums(ctx, s, dir)
	}
	c, e := s.Source.BlobClient(s.Key, s.Version)
	if e != nil {
		return "", "", "", e
	}
	r, e := c.DownloadStream(ctx, &blob.DownloadStreamOptions{AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: to.Ptr(azcore.ETag(s.ETag))}}})
	if e != nil {
		return "", "", "", e
	}
	reader := r.NewRetryReader(ctx, &blob.RetryReaderOptions{MaxRetries: 3})
	defer reader.Close()
	f, e := os.CreateTemp(dir, "scan-*")
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
	n, e := io.Copy(io.MultiWriter(f, h, csum), io.LimitReader(reader, s.Size+1))
	if e != nil {
		return "", "", "", e
	}
	if n != s.Size {
		return "", "", "", errors.New("source size changed")
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), fmt.Sprintf("%08x", csum.Sum32()), nil
}
func Route(ctx context.Context, m Mount, key, path, digest, job, verdict string, size int64, tagSets ...map[string]string) error {
	return routeBytes(ctx, m, key, path, digest, job, verdict, size, true, 2, 8, tagSets...)
}
func routeBytes(ctx context.Context, m Mount, key, path, digest, job, verdict string, size int64, verifyNow bool, parallel, blockMiB int, tagSets ...map[string]string) error {
	if m.Type() != "blob" {
		if err := routeShare(ctx, m, key, path, digest, job, size, !verifyNow); err != nil {
			return err
		}
		if len(tagSets) == 0 || len(tagSets[0]) == 0 {
			return nil
		}
		data, err := json.Marshal(map[string]any{"tags": tagSets[0], "verdict": verdict, "sha256": digest, "scanner": "Vision One File Security"})
		if err != nil {
			return err
		}
		f, err := os.CreateTemp("", "v1fs-tags-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if _, err = f.Write(data); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		return routeShare(ctx, m, key+".v1fs-tags.json", f.Name(), hex.EncodeToString(sum[:]), job, int64(len(data)))
	}
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
	metadata := map[string]*string{"job": &job, "sha256": &digest, "verdict": &verdict}
	if m.Kind == "adls" && len(tagSets) > 0 {
		metadata["v1fs_result_tags"] = to.Ptr(encodeADLSTags(tagSets[0]))
	}
	_, e = target.UploadFile(ctx, f, &blockblob.UploadFileOptions{BlockSize: int64(blockMiB) << 20, Concurrency: uint16(parallel), AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfNoneMatch: to.Ptr(azcore.ETag("*"))}}, Metadata: metadata})
	if e != nil {
		var re *azcore.ResponseError
		if !errors.As(e, &re) || re.StatusCode != 412 {
			return e
		}
	}
	if !verifyNow {
		return nil
	} // Worker verifies both hashes once under a lease.
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
	if len(tagSets) > 0 && len(tagSets[0]) > 0 {
		_, e = target.SetTags(ctx, tagSets[0], nil)
		if e != nil {
			return e
		}
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
	if os.Getenv("V1FS_SCAN_SUBPROCESS") == "1" {
		return scanSubprocess(ctx, path, s, p)
	}
	return a.ScanDirect(ctx, path, s, p)
}

// ScanDirect is called only inside a dedicated SDK child process in production.
func (a *App) ScanDirect(ctx context.Context, path string, s Scanner, p Profile) ([]byte, error) {
	for !a.scanMu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer a.scanMu.Unlock()
	names := []string{"TM_AM_SERVER_ADDR", "TM_AM_DISABLE_TLS", "TM_AM_DISABLE_CERT_VERIFY", "TM_AM_AUTH_KEY_NOT_REQUIRED", "TM_AM_AUTH_KEY", "TM_AM_SCAN_TIMEOUT_SECS"}
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
	os.Setenv("TM_AM_SCAN_TIMEOUT_SECS", fmt.Sprint(int(p.JobTimeout().Seconds())))
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
	tags, e := p.SDKTags()
	if e != nil {
		return nil, e
	}
	raw, e := c.ScanFileWithContext(ctx, path, tags)
	return []byte(raw), e
}

func completeMetadata(m map[string]*string) bool {
	for _, key := range []string{"v1fs_complete", "v1fs-complete"} {
		if v := m[key]; v != nil && *v == "true" {
			return true
		}
	}
	return false
}
