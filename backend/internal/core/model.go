package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

type Source struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Account     string `json:"account"`
	Container   string `json:"container"`
	Prefix      string `json:"prefix"`
	Tenant      string `json:"tenant"`
	ProfileID   string `json:"profileId"`
	Clean       string `json:"clean"`
	Quarantine  string `json:"quarantine"`
	Hold        string `json:"hold"`
	Enabled     bool   `json:"enabled"`
	Concurrency int    `json:"concurrency"`
	MaxBytes    int64  `json:"maxBytes"`
}
type Profile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	PML           bool   `json:"pml"`
	ActiveContent bool   `json:"activeContent"`
	Feedback      bool   `json:"feedback"`
	Verbose       bool   `json:"verbose"`
	Digest        bool   `json:"digest"`
	Direct        bool   `json:"direct"`
	Concurrency   int    `json:"concurrency"`
}
type Capacity struct {
	Global      int `json:"global"`
	Tenant      int `json:"tenant"`
	PerWorker   int `json:"perWorker"`
	MaxAttempts int `json:"maxAttempts"`
	MinReplicas int `json:"minReplicas"`
	MaxReplicas int `json:"maxReplicas"`
}
type Job struct {
	Source        Source          `json:"source"`
	Profile       Profile         `json:"profile"`
	ID            string          `json:"id"`
	SourceID      string          `json:"sourceId"`
	Tenant        string          `json:"tenant"`
	ProfileID     string          `json:"profileId"`
	Key           string          `json:"key"`
	Version       string          `json:"version"`
	ETag          string          `json:"etag"`
	Size          int64           `json:"size"`
	State         string          `json:"state"`
	Verdict       string          `json:"verdict"`
	Digest        string          `json:"digest"`
	Revision      int64           `json:"revision"`
	Attempts      int             `json:"attempts"`
	CorrelationID string          `json:"correlationId"`
	Result        json.RawMessage `json:"result,omitempty"`
}

func Identity(source, key, version, etag string) string {
	b, _ := json.Marshal([]string{source, key, version, etag})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func ValidKey(s string) bool {
	if s == "" || strings.Contains(s, "\\") || strings.ContainsRune(s, 0) || strings.HasPrefix(s, "/") {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == ".." || p == "." {
			return false
		}
	}
	return true
}
func StorageURL(raw, kind string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	suffix := ".blob.core.windows.net"
	if kind == "files" {
		suffix = ".file.core.windows.net"
	}
	account := strings.TrimSuffix(u.Host, suffix)
	container := strings.Trim(u.Path, "/")
	return strings.HasSuffix(u.Host, suffix) && regexp.MustCompile(`^[a-z0-9]{3,24}$`).MatchString(account) && regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`).MatchString(container) && !strings.Contains(container, "--") && ValidKey(container)
}
func (s Source) Validate() error {
	if s.ID == "" || s.Name == "" || s.Tenant == "" || s.ProfileID == "" || s.Concurrency < 1 || s.Concurrency > 128 || s.MaxBytes < 1 || s.Container == "" || strings.ContainsAny(s.Container, "/\\") {
		return errors.New("invalid source fields")
	}
	if s.Kind != "blob" && s.Kind != "files" {
		return errors.New("invalid source kind")
	}
	if !regexp.MustCompile(`^[a-z0-9]{3,24}$`).MatchString(s.Account) {
		return errors.New("use a storage account name, not credentials or a URL")
	}
	if s.Prefix != "" && !ValidKey(s.Prefix) {
		return errors.New("invalid prefix")
	}
	for _, v := range []string{s.Clean, s.Quarantine, s.Hold} {
		if !StorageURL(v, "blob") {
			return errors.New("destinations must be Azure Blob container HTTPS URLs without credentials")
		}
	}
	if strings.TrimRight(s.Clean, "/") == strings.TrimRight(s.Quarantine, "/") || strings.TrimRight(s.Clean, "/") == strings.TrimRight(s.Hold, "/") || strings.TrimRight(s.Quarantine, "/") == strings.TrimRight(s.Hold, "/") {
		return errors.New("destinations must be distinct")
	}
	if s.Kind == "blob" {
		for _, dest := range []string{s.Clean, s.Quarantine, s.Hold} {
			u, _ := url.Parse(dest)
			if u.Host == s.Account+".blob.core.windows.net" && strings.Trim(u.Path, "/") == s.Container {
				return errors.New("destination must not equal the monitored container")
			}
		}
	}
	return nil
}

var transitions = map[string][]string{
	"DISCOVERED": {"WAITING_FOR_COMPLETION", "READY"}, "WAITING_FOR_COMPLETION": {"READY", "HELD"}, "READY": {"QUEUED"}, "QUEUED": {"SCANNING", "HELD"}, "SCANNING": {"SCANNED", "RETRY_PENDING", "HELD"}, "SCANNED": {"PROMOTION_PENDING", "HELD"}, "PROMOTION_PENDING": {"PROMOTING", "HELD"}, "PROMOTING": {"COMPLETED", "QUARANTINED", "RETRY_PENDING", "HELD"}, "RETRY_PENDING": {"QUEUED", "PROMOTION_PENDING", "HELD"},
}

func Transition(from, to, verdict string) bool {
	if to == "COMPLETED" && verdict != "CLEAN" {
		return false
	}
	if to == "QUARANTINED" && verdict != "MALICIOUS" {
		return false
	}
	for _, v := range transitions[from] {
		if v == to {
			return true
		}
	}
	return false
}

// Require explicit supported verdicts and an SDK scan identifier. Missing data is never clean.
func Normalize(b []byte) string {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(b, &envelope) != nil {
		return "UNKNOWN"
	}
	var errs []json.RawMessage
	if raw, ok := envelope["foundErrors"]; ok && string(raw) != "null" {
		if json.Unmarshal(raw, &errs) != nil || len(errs) > 0 {
			return "UNKNOWN"
		}
	}
	var malwares []json.RawMessage
	if raw, ok := envelope["foundMalwares"]; ok {
		if json.Unmarshal(raw, &malwares) != nil {
			return "UNKNOWN"
		}
		if len(malwares) > 0 {
			return "MALICIOUS"
		}
	}
	var engines map[string]json.RawMessage
	if raw, ok := envelope["result"]; ok {
		if json.Unmarshal(raw, &engines) != nil {
			return "UNKNOWN"
		}
		for k := range engines {
			if k != "atse" {
				return "UNKNOWN"
			}
		}
	}
	var r struct {
		ScanID     string `json:"scanId"`
		ScanResult *int   `json:"scanResult"`
		Result     *struct {
			ATSE *struct {
				MalwareCount *int            `json:"malwareCount"`
				Error        json.RawMessage `json:"error"`
			} `json:"atse"`
		} `json:"result"`
	}
	if json.Unmarshal(b, &r) != nil || r.ScanID == "" {
		return "UNKNOWN"
	}
	if r.ScanResult != nil {
		if *r.ScanResult == 0 {
			return "CLEAN"
		}
		if *r.ScanResult > 0 {
			return "MALICIOUS"
		}
		return "UNKNOWN"
	}
	if r.Result != nil && r.Result.ATSE != nil {
		a := r.Result.ATSE
		if len(a.Error) > 0 && string(a.Error) != "null" {
			return "UNKNOWN"
		}
		if a.MalwareCount != nil {
			if *a.MalwareCount == 0 {
				return "CLEAN"
			}
			if *a.MalwareCount > 0 {
				return "MALICIOUS"
			}
		}
	}
	return "UNKNOWN"
}
