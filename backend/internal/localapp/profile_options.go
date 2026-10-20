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
	if n < 10 {
		n = 10
	}
	return time.Duration(n) * time.Second
}

var tagText = regexp.MustCompile(`^[a-zA-Z0-9 +\-./:=_]*$`)

// Tags are portable key=value pairs; verdict-specific values override common ones.
func (p Profile) ResultTags(verdict string) (map[string]string, error) {
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
	if len(result) > 10 {
		return nil, fmt.Errorf("Use at most 10 combined tags per verdict.")
	}
	return result, nil
}
