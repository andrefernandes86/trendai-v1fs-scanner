package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	client "github.com/trendmicro/tm-v1-fs-golang-sdk"
	"google.golang.org/grpc/status"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Canonical 68-byte EICAR test pattern; never executed or routed into storage.
const eicarContent = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func (a *App) resolveScanner(s Scanner) Scanner {
	var old Scanner
	if a.Get("scanner", "default", &old) == nil && s.APIKey == "" && s.Type == old.Type && ((s.Type == "cloud" && s.Region == old.Region) || (s.Type == "local" && s.Address == old.Address)) {
		s.APIKey = old.APIKey
	}
	if s.Type == "cloud" {
		s.TLS = true
	}
	return s
}

// Diagnostics submits a real SDK scan. Credential checks scan a small benign
// file because the SDK has no separate authentication-only operation.
func (a *App) scannerTest(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Kind    string  `json:"kind"`
		Scanner Scanner `json:"scanner"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Kind != "key" && input.Kind != "eicar" {
		problem(w, 400, "Select key or EICAR diagnostic.")
		return
	}
	s := a.resolveScanner(input.Scanner)
	if e := s.Validate(); e != nil {
		problem(w, 400, e.Error())
		return
	}
	content, name, expected := "TrendAI File Security credential verification.\n", "v1fs-auth-test.txt", "CLEAN"
	if input.Kind == "eicar" {
		content, name, expected = eicarContent, "eicar.com.txt", "MALICIOUS"
	}
	hash := sha256.Sum256([]byte(content))
	endpoint := s.Address
	if s.Type == "cloud" {
		endpoint = client.V1RegionFQDNMapping[s.Region] + ":443"
	}
	request := map[string]any{"transport": "gRPC through official Vision One Go SDK", "sdkMethod": "ScanFileWithContext", "scannerType": s.Type, "endpoint": endpoint, "tls": s.TLS, "apiKey": func() string {
		if s.APIKey == "" {
			return "not provided (local scanner)"
		}
		return "[REDACTED]"
	}(), "file": map[string]any{"name": name, "bytes": len(content), "sha256": hex.EncodeToString(hash[:]), "content": content}, "options": map[string]bool{"pml": false, "activeContent": false, "feedback": false, "verbose": false, "digest": true}, "routing": "disabled for diagnostics"}
	if s.Type == "cloud" {
		request["region"] = s.Region
	}
	dir, e := os.MkdirTemp(a.DataDir, "diagnostic-*")
	if e != nil {
		problem(w, 500, "Cannot prepare diagnostic file.")
		return
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, name)
	if e = os.WriteFile(path, []byte(content), 0600); e != nil {
		problem(w, 500, "Cannot prepare diagnostic file.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	started := time.Now()
	raw, scanErr := a.Scan(ctx, path, s, Profile{ID: "diagnostic-" + input.Kind, Digest: true})
	elapsed := time.Since(started).Milliseconds()
	response := map[string]any{"scannerResponded": scanErr == nil, "elapsedMs": elapsed}
	verdict := "UNKNOWN"
	passed := false
	if scanErr != nil {
		response["grpcCode"] = status.Code(scanErr).String()
		response["error"] = redactString(scanErr.Error(), s.APIKey)
	} else {
		var result any
		if json.Unmarshal(raw, &result) == nil {
			response["body"] = redactValue(result, s.APIKey)
		} else {
			response["body"] = redactString(string(raw), s.APIKey)
		}
		verdict = core.Normalize(raw)
		passed = verdict == expected
		response["verdict"] = verdict
	}
	response["expectedVerdict"] = expected
	response["expectationMet"] = passed
	response["keyVerified"] = scanErr == nil && verdict != "UNKNOWN" && s.APIKey != ""
	if s.Type == "local" && s.APIKey == "" {
		response["authenticationNote"] = "No API key supplied; this test validates local scanning connectivity, not an API key."
	}
	a.Audit("scanner.test_"+input.Kind, "scanner", func() string {
		if passed {
			return "Diagnostic matched expected verdict"
		}
		return "Diagnostic failed or did not match expected verdict"
	}())
	respond(w, 200, map[string]any{"kind": input.Kind, "success": passed, "testedAt": stamp(), "request": request, "response": response, "note": "Request is an SDK invocation summary, not a raw HTTP or gRPC wire capture. API keys are redacted. Temporary file is deleted after the test."})
}
func redactString(s, key string) string {
	if key != "" {
		for _, v := range []string{key, url.QueryEscape(key), url.PathEscape(key)} {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	return s
}
func redactValue(v any, key string) any {
	switch x := v.(type) {
	case string:
		return redactString(x, key)
	case []any:
		for i := range x {
			x[i] = redactValue(x[i], key)
		}
		return x
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			switch strings.ToLower(strings.ReplaceAll(k, "_", "")) {
			case "apikey", "authorization", "token", "accesstoken", "secret":
				out[k] = "[REDACTED]"
			default:
				out[redactString(k, key)] = redactValue(val, key)
			}
		}
		return out
	default:
		return v
	}
}
