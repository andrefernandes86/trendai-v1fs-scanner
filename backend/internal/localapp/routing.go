package localapp

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
)

// routeResult publishes the exact downloaded/scanned bytes and verifies the destination.
// The source is never used as a destination, and no result defaults to clean.
func routeResult(ctx context.Context, id string, s Snapshot, local, digest, verdict string) (destination, state string, err error) {
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
	if verdict == "OVERSIZED" || verdict == "OVERSIZED_CLEAN" {
		tags = map[string]string{"scanned": "false", "verdict": "not_scanned", "reason": "oversized"}
	} else if verdict == "EXCLUDED" {
		tags = map[string]string{"scanned": "false", "verdict": "excluded"}
	} else if verdict == "CLEAN" || verdict == "MALICIOUS" {
		tags, err = s.Profile.ResultTags(verdict)
		if err != nil {
			return "", "", err
		}
	} else {
		tags = map[string]string{"scanned": "false", "verdict": "scan_failed"}
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
	if err = Route(ctx, target, key, local, digest, id, verdict, s.Size, tags); err != nil {
		return "", "", err
	}
	return target.BaseURL() + "/" + key, state, nil
}
