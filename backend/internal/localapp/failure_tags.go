package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

// A failed delivery leaves the exact source version in place. Never label a replacement.
func (a *App) tagExhaustedSource(id, stage, verdict string) error {
	var payload []byte
	if err := a.DB.QueryRow("SELECT snapshot FROM jobs WHERE id=?", id).Scan(&payload); err != nil {
		return err
	}
	var s Snapshot
	if err := a.Unseal(payload, &s); err != nil {
		return err
	}
	if c, err := a.loadClaim(id); err == nil {
		s.ClaimedKey, s.ClaimedETag = c.Key, c.ETag
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tags, err := s.Profile.FailureTags()
	if err != nil {
		return err
	}
	tags["failure-stage"] = stage
	if verdict == "CLEAN" || verdict == "MALICIOUS" {
		delete(tags, "scanned")
	}
	if verdict != "CLEAN" && verdict != "MALICIOUS" {
		tags["scanned"] = "false"
	}
	if s.Source.Kind == "adls" {
		return a.tagADLSFailure(ctx, id, s, tags, verdict)
	}
	if s.Source.Type() == "blob" {
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
			return fmt.Errorf("source version changed")
		}
		existing, err := client.GetTags(locked, nil)
		if err != nil {
			return err
		}
		merged := map[string]string{}
		if existing.BlobTagSet != nil {
			for _, tag := range existing.BlobTagSet {
				if tag.Key != nil && tag.Value != nil {
					merged[*tag.Key] = *tag.Value
				}
			}
		}
		for key, value := range tags {
			merged[key] = value
		}
		if len(merged) > 10 {
			return fmt.Errorf("source has no room for failure tags")
		}
		_, err = client.SetTags(locked, merged, &blob.SetTagsOptions{AccessConditions: &blob.AccessConditions{LeaseAccessConditions: &blob.LeaseAccessConditions{LeaseID: to.Ptr(destinationLeaseID(id))}}})
		return err
	}
	props, err := shareProperties(ctx, s.Source, s.sourceKey())
	if err != nil {
		return err
	}
	if props.ETag != s.sourceETag() {
		return fmt.Errorf("source version changed")
	}
	data, err := json.Marshal(map[string]any{"job": id, "sourceETag": s.sourceETag(), "tags": tags, "verdict": verdict})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "v1fs-failure-tags-*")
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
	return routeShare(ctx, s.Source, s.sourceKey()+".v1fs-tags.json", f.Name(), hex.EncodeToString(sum[:]), id, int64(len(data)))
}
