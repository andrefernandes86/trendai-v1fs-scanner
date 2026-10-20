package localapp

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type FileRule struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
	MinSize int64  `json:"minSize"`
	MaxSize int64  `json:"maxSize"`
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
func (p Profile) FilePolicy(key string, size int64) (string, string) {
	// Hold always wins over bypass. Rules are case-sensitive and operate on slash-normalized relative paths.
	for _, action := range []string{"hold", "exclude"} {
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
	return "scan", ""
}
func (p Profile) ReliabilityValidate() error {
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
		if r.ID == "" || ids[r.ID] || r.Pattern == "" || strings.Contains(r.Pattern, "\\") || strings.Contains(r.Pattern, "..") || strings.HasPrefix(r.Pattern, "/") || (r.Action != "hold" && r.Action != "exclude") || r.MinSize < 0 || r.MaxSize < 0 || (r.MaxSize != 0 && r.MinSize > r.MaxSize) {
			return fmt.Errorf("Rules need unique IDs, relative slash-separated patterns, hold/exclude actions and valid sizes.")
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
