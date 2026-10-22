package localapp

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

type FileRule struct {
	DestinationMount  string `json:"destinationMount"`
	DestinationPrefix string `json:"destinationPrefix"`
	ID                string `json:"id"`
	Pattern           string `json:"pattern"`
	Action            string `json:"action"`
	MinSize           int64  `json:"minSize"`
	MaxSize           int64  `json:"maxSize"`
}

func globMatch(pattern, key string) bool {
	// ** spans path separators; ordinary * matches within one path component.
	expression := regexp.QuoteMeta(pattern)
	expression = strings.ReplaceAll(expression, `\*\*`, "\x00")
	expression = strings.ReplaceAll(expression, `\*`, `[^/]*`)
	expression = strings.ReplaceAll(expression, `\?`, `[^/]`)
	expression = strings.ReplaceAll(expression, "\x00", `.*`)
	re, e := regexp.Compile("^(?:" + expression + ")$")
	return e == nil && (re.MatchString(key) || (!strings.Contains(pattern, "/") && re.MatchString(path.Base(key))))
}

const DefaultMaxScanBytes int64 = 100_000_000_000

func (p Profile) MaxScanSize() int64 {
	if p.MaxScanBytes == 0 {
		return DefaultMaxScanBytes
	}
	return p.MaxScanBytes
}
func (p Profile) JobTimeout() time.Duration {
	return time.Duration(defaultInt(p.JobTimeoutSeconds, 21600)) * time.Second
}
func (p Profile) FilePolicy(key string, size int64) (string, string) {
	// Hold always wins over bypass. Rules are case-sensitive and operate on slash-normalized relative paths.
	for _, action := range []string{"hold", "exclude", "route"} {
		for _, rule := range p.Rules {
			if rule.Action == action && globMatch(rule.Pattern, key) && size >= rule.MinSize && (rule.MaxSize == 0 || size <= rule.MaxSize) {
				return action, rule.ID
			}
		}
	}
	for _, pattern := range strings.Split(p.IgnorePatterns, "\n") {
		if pattern = strings.TrimSpace(pattern); pattern != "" && globMatch(pattern, key) {
			return "ignore", pattern
		}
	}
	if size > p.MaxScanSize() {
		switch p.OversizeAction {
		case "clean":
			return "oversize_clean", "size_limit"
		case "failed":
			return "oversize_failed", "size_limit"
		case "custom":
			return "oversize_custom", "size_limit"
		default:
			return "hold", "oversized: exceeds profile maximum scan size"
		}
	}
	return "scan", ""
}
func (p Profile) ReliabilityValidate() error {
	if _, err := p.FailureTags(); err != nil {
		return err
	}
	if _, err := p.SDKTags(); err != nil {
		return err
	}
	if p.UploadConcurrency < 0 || p.UploadConcurrency > 8 || (p.UploadBlockMiB != 0 && (p.UploadBlockMiB < 4 || p.UploadBlockMiB > 32)) || p.SimultaneousTransfers < 0 || p.SimultaneousTransfers > 10 || p.LargeFileTransfers < 0 || p.LargeFileTransfers > 2 {
		return errors.New("Transfer limits: 1–10 total transfers, 1–8 upload requests, 4–32 MiB blocks, 1–2 large transfers (1 GB or more).")
	}
	if e := p.Archive.Validate(); e != nil {
		return e
	}
	if p.MaxScanBytes < 0 || p.MaxScanBytes > DefaultMaxScanBytes {
		return fmt.Errorf("Maximum scan size must be 1–100 GB, or zero for 100 GB.")
	}
	if p.OversizeAction != "" && p.OversizeAction != "hold" && p.OversizeAction != "clean" && p.OversizeAction != "failed" && p.OversizeAction != "custom" {
		return fmt.Errorf("Invalid oversized file action.")
	}
	if p.LargeFileScans < 0 || p.LargeFileScans > 8 {
		return fmt.Errorf("Large-file concurrency must be 1–8, or zero for 1.")
	}
	if p.JobTimeoutSeconds != 0 && (p.JobTimeoutSeconds < 60 || p.JobTimeoutSeconds > 172800) {
		return fmt.Errorf("Job timeout must be 60–172800 seconds, or zero for 21600.")
	}

	if p.SimultaneousScans < 0 || p.SimultaneousScans > 32 {
		return fmt.Errorf("Simultaneous scans must be between 1 and 32, or 0 for the default of 2.")
	}
	for _, v := range []int{p.ScanAttempts, p.TransferAttempts, p.DeleteAttempts, p.RecoveryAttempts} {
		if v < 0 || v > 100 {
			return fmt.Errorf("Attempt limits must be between 1 and 100, or 0 for defaults.")
		}
	}
	if p.QuietSeconds < 0 || p.QuietSeconds > 86400 || p.RetryBaseSeconds < 0 || p.RetryBaseSeconds > 3600 || p.RecoverySeconds < 0 || p.RecoverySeconds > 2592000 || p.ProcessingDeadlineSeconds < 0 || p.ProcessingDeadlineSeconds > 2592000 {
		return fmt.Errorf("Invalid quiet period, retry delay, recovery interval or deadline.")
	}
	if len(p.Rules) > 100 {
		return fmt.Errorf("At most 100 exclusion/hold rules are allowed.")
	}
	ids := map[string]bool{}
	for _, r := range p.Rules {
		if r.ID == "" || ids[r.ID] || r.Pattern == "" || strings.Contains(r.Pattern, "\\") || strings.Contains(r.Pattern, "..") || strings.HasPrefix(r.Pattern, "/") || (r.Action != "hold" && r.Action != "exclude" && r.Action != "route") || r.MinSize < 0 || r.MaxSize < 0 || (r.MaxSize != 0 && r.MinSize > r.MaxSize) {
			return fmt.Errorf("Rules need unique IDs, relative slash-separated patterns, hold/exclude actions and valid sizes.")
		}
		if r.Action == "route" && r.DestinationMount == "" {
			return fmt.Errorf("Select a storage connection for each move rule.")
		}
		ids[r.ID] = true
	}
	return nil
}
func defaultInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

// SDKTags are scan-event labels sent to Vision One, distinct from storage tags.
func (p Profile) SDKTags() ([]string, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = p.ID // Legacy snapshots without a display name.
	}
	if len("profile:"+name) > 63 {
		return nil, fmt.Errorf("Profile name must fit within 55 bytes for the automatic Vision One profile tag.")
	}
	tags := []string{"app:trendai-v1fs", "profile:" + name}
	for _, tag := range strings.FieldsFunc(p.VisionOneTags, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	if len(tags) > 8 {
		return nil, fmt.Errorf("Vision One accepts 8 tags total; add at most 6 custom tags alongside the 2 automatic tags.")
	}
	for _, tag := range tags {
		if len(tag) > 63 {
			return nil, fmt.Errorf("Each Vision One tag must fit within 63 bytes (63 ASCII characters).")
		}
	}
	return tags, nil
}
