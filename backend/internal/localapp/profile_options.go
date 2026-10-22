package localapp

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

func (p Profile) Interval() time.Duration {
	n := p.ScanIntervalSeconds
	if n == 0 {
		n = 30
	}
	if n < 5 {
		n = 5
	}
	return time.Duration(n) * time.Second
}

var tagText = regexp.MustCompile(`^[a-zA-Z0-9 +\-./:=_]*$`)

// Tags are portable key=value pairs; verdict-specific values override common ones.
func (p Profile) ResultTags(verdict string) (map[string]string, error) {
	if verdict != "CLEAN" && verdict != "MALICIOUS" {
		return nil, fmt.Errorf("Result tags require a confirmed clean or malicious verdict")
	}
	result := map[string]string{}
	specific := p.CleanTags
	if verdict == "MALICIOUS" {
		specific = p.MaliciousTags
	}
	for _, group := range []string{p.ScannedTags, specific} {
		for _, item := range strings.Split(group, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			k, v, ok := strings.Cut(item, "=")
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if !ok || len(k) < 1 || len(k) > 128 || len(v) > 256 || !tagText.MatchString(k) || !tagText.MatchString(v) {
				return nil, fmt.Errorf("Tags must be comma-separated key=value pairs using letters, numbers, spaces or + - . / : = _ (key: 1–128 characters; value: up to 256).")
			}
			result[k] = v
		}
	}
	for key, expected := range map[string]string{"scanned": "true", "verdict": strings.ToLower(verdict), "scan-failed": "false"} {
		if value, ok := result[key]; ok && value != expected {
			return nil, fmt.Errorf("%s is a reserved result tag; expected %s", key, expected)
		}
		result[key] = expected
	}
	if len(result) > 10 {
		return nil, fmt.Errorf("Use at most 10 combined tags per verdict.")
	}
	return result, nil
}

// FailureTags adds operator labels while preserving canonical failure evidence.
func (p Profile) FailureTags() (map[string]string, error) {
	result := map[string]string{}
	for _, item := range strings.Split(p.FailedTags, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		k, v, ok := strings.Cut(item, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || len(k) < 1 || len(k) > 128 || len(v) > 256 || !tagText.MatchString(k) || !tagText.MatchString(v) {
			return nil, fmt.Errorf("Scan-failed labels must be comma-separated key=value pairs.")
		}
		if k == "failure-stage" {
			return nil, fmt.Errorf("failure-stage is set automatically.")
		}
		result[k] = v
	}
	for k, v := range map[string]string{"scan-failed": "true", "scanned": "false", "verdict": "scan_failed"} {
		if old, ok := result[k]; ok && old != v {
			return nil, fmt.Errorf("%s is reserved; expected %s for failed scans", k, v)
		}
		result[k] = v
	}
	if len(result) > 9 {
		return nil, fmt.Errorf("Use at most 6 additional failure labels; room is reserved for scan-result and failure-stage labels.")
	}
	return result, nil
}
