package localapp

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"strings"

	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
)

// routeResult publishes the exact downloaded/scanned bytes and verifies the destination.
// The source is never used as a destination, and no result defaults to clean.
func routeResult(ctx context.Context, id string, s Snapshot, local, digest, verdict string, resultTags ...map[string]string) (destination, state string, err error) {
	var target Mount
	var prefix string
	var tags map[string]string
	switch verdict {
	case "CLEAN", "EXCLUDED", "OVERSIZED_CLEAN":
		target, prefix, state = s.Good, s.Profile.GoodPrefix, "COMPLETED"
	case "MALICIOUS":
		target, prefix, state = s.Bad, s.Profile.BadPrefix, "QUARANTINED"
	default:
		target, prefix, state = s.Failed, s.Profile.FailedPrefix, "HELD"
	}
	if target.ID == "" {
		return "", "", errors.New("destination not configured in this job's policy snapshot")
	}
	if sameStorageRoot(s.Source, target) {
		return "", "", errors.New("destination must differ from source")
	}
	tags, err = routingTags(s.Profile, verdict)
	if err != nil {
		return "", "", err
	}
	if len(resultTags) > 0 {
		tags = resultTags[0]
	}
	parts := []string{}
	name := path.Base(s.Key)
	ext := path.Ext(name)
	name = strings.TrimSuffix(name, ext) + "_" + id + ext
	for _, p := range []string{target.Prefix, prefix, name} {
		if p = strings.Trim(p, "/"); p != "" {
			parts = append(parts, p)
		}
	}
	key := strings.Join(parts, "/")
	if !core.ValidKey(key) {
		return "", "", errors.New("invalid destination key")
	}
	if err = routeBytes(ctx, target, key, local, digest, id, verdict, s.Size, target.Type() != "blob", defaultInt(s.Profile.UploadConcurrency, 2), defaultInt(s.Profile.UploadBlockMiB, 8), tags); err != nil {
		return "", "", err
	}
	return target.BaseURL() + "/" + key, state, nil
}

func routingTags(p Profile, verdict string) (map[string]string, error) {
	var tags map[string]string
	var err error
	if verdict == "OVERSIZED" || verdict == "OVERSIZED_CLEAN" {
		tags = map[string]string{"scanned": "false", "verdict": "not_scanned", "reason": "oversized"}
	} else if verdict == "EXCLUDED" {
		tags = map[string]string{"scanned": "false", "verdict": "excluded"}
	} else if verdict == "CLEAN" || verdict == "MALICIOUS" {
		tags, err = p.ResultTags(verdict)
		if err != nil {
			return nil, err
		}
	} else {
		tags = map[string]string{"scanned": "false", "verdict": "scan_failed", "scan-failed": "true"}
	}

	return tags, nil
}

// Include incomplete archive evidence even when a member detected malware.
func (a *App) jobRoutingTags(id string, p Profile, verdict string) (map[string]string, error) {
	tags, err := routingTags(p, verdict)
	if err != nil {
		return nil, err
	}
	var payload []byte
	err = a.DB.QueryRow("SELECT payload FROM scan_summaries WHERE job_id=?", id).Scan(&payload)
	if err == sql.ErrNoRows {
		return tags, nil
	}
	if err != nil {
		return nil, err
	}
	var details ScanDetails
	if err = a.Unseal(payload, &details); err != nil {
		return nil, err
	}
	if details.ArchiveInspection != nil && !details.ArchiveInspection.Complete {
		tags["scan-failed"] = "true"
		tags["scanned"] = "false"
	}
	return tags, nil
}
