package localapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// ADLS uses the interoperable Blob HTTPS API, without requiring preview index tags.
func encodeADLSTags(tags map[string]string) string {
	b, _ := json.Marshal(tags)
	return base64.StdEncoding.EncodeToString(b)
}
func adlsResultTags(metadata map[string]*string) map[string]string {
	tags := map[string]string{}
	for k, v := range metadata {
		if strings.EqualFold(k, "v1fs_result_tags") && v != nil {
			b, err := base64.StdEncoding.DecodeString(*v)
			if err == nil {
				_ = json.Unmarshal(b, &tags)
			}
		}
	}
	return tags
}
func isADLSDirectory(metadata map[string]*string) bool {
	for k, v := range metadata {
		if strings.EqualFold(k, "hdi_isfolder") && v != nil && strings.EqualFold(*v, "true") {
			return true
		}
	}
	return false
}

// A failure sidecar avoids changing the source ETag, preserving bounded retries
// and exact-version ownership. It is excluded from source enumeration.
func (a *App) tagADLSFailure(ctx context.Context, id string, s Snapshot, tags map[string]string, verdict string) error {
	locked, release, err := leaseDestination(ctx, id, MoveRecord{Target: s.Source, Key: s.sourceKey()})
	if err != nil {
		return err
	}
	defer release()
	client, err := s.Source.BlobClient(s.sourceKey(), "")
	if err != nil {
		return err
	}
	props, err := client.GetProperties(locked, nil)
	if err != nil {
		return err
	}
	if props.ETag == nil || string(*props.ETag) != s.sourceETag() {
		return errors.New("source version changed")
	}
	data, err := json.Marshal(map[string]any{"job": id, "sourceETag": s.sourceETag(), "tags": tags, "verdict": verdict})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "v1fs-adls-failure-*")
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
	digest, _, size, err := checksums(f.Name())
	if err != nil {
		return err
	}
	return routeBytes(locked, s.Source, s.sourceKey()+".v1fs-tags.json", f.Name(), digest, id, verdict, size, true, 1, 8)
}
