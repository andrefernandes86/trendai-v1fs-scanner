package localapp

import (
	"bytes"
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type captureTransport struct {
	base              policy.Transporter
	request, response map[string]any
	attempts          int
	secrets           []string
}

func (t *captureTransport) clean(s string) string {
	for _, key := range t.secrets {
		s = redactString(s, key)
	}
	return s
}
func safeStorageURL(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return "[invalid URL]"
	}
	q := url.Values{}
	for _, k := range []string{"comp", "restype", "prefix", "maxresults", "marker"} {
		if v := u.Query().Get(k); v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

type replayBody struct {
	io.Reader
	io.Closer
}

func (t *captureTransport) Do(r *http.Request) (*http.Response, error) {
	t.attempts++
	if auth := r.Header.Get("Authorization"); auth != "" {
		t.secrets = append(t.secrets, auth)
		if i := strings.LastIndex(auth, ":"); i >= 0 {
			t.secrets = append(t.secrets, auth[i+1:])
		}
	}
	h := map[string]string{}
	for _, k := range []string{"x-ms-version", "x-ms-date", "x-ms-client-request-id"} {
		if v := r.Header.Get(k); v != "" {
			h[k] = t.clean(v)
		}
	}
	h["Authorization"] = "[REDACTED]"
	t.request = map[string]any{"method": r.Method, "url": safeStorageURL(r.URL.String()), "headers": h, "body": nil}
	res, e := t.base.Do(r)
	if e != nil {
		t.response = map[string]any{"error": t.clean(e.Error())}
		return res, e
	}
	headers := map[string]string{}
	for _, k := range []string{"Content-Type", "x-ms-request-id", "x-ms-error-code", "x-ms-version", "Date"} {
		if v := res.Header.Get(k); v != "" {
			headers[k] = t.clean(v)
		}
	}
	body, e := io.ReadAll(io.LimitReader(res.Body, 256*1024+1))
	if e != nil {
		res.Body.Close()
		return nil, e
	}
	original := res.Body
	res.Body = replayBody{Reader: io.MultiReader(bytes.NewReader(body), original), Closer: original}
	truncated := len(body) > 256*1024
	shown := body
	if truncated {
		shown = shown[:256*1024]
	}
	t.response = map[string]any{"statusCode": res.StatusCode, "headers": headers, "body": t.clean(string(shown)), "bodyTruncated": truncated}
	return res, nil
}
func (a *App) storageTest(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Kind   string `json:"kind"`
		Mount  Mount  `json:"mount"`
		Marker string `json:"marker"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Kind != "containers" && input.Kind != "container" {
		problem(w, 400, "Select container discovery or a container test.")
		return
	}
	m := input.Mount
	// A blank target tests account/server access by discovering available locations.
	target := m.Container
	switch m.Type() {
	case "azureFiles", "smb":
		target = m.Share
	case "nfs":
		target = m.Export
	}
	if strings.TrimSpace(target) == "" && strings.TrimSpace(m.ResourceID) == "" {
		input.Kind = "containers"
	}
	if m.Type() != "blob" {
		a.shareStorageTest(w, r, input.Kind, m, input.Marker)
		return
	}
	if m.ResourceID != "" {
		match := resourcePattern.FindStringSubmatch(m.ResourceID)
		if match == nil {
			problem(w, 400, "Use a full Azure container resource ID.")
			return
		}
		m.Account, m.Container = match[1], match[2]
	}
	var saved Mount
	if m.Secret == "" && a.Get("mounts", m.ID, &saved) == nil && m.Account == saved.Account && m.AuthType == saved.AuthType {
		m.Secret = saved.Secret
	}
	if m.ID == "" {
		m.ID = "diagnostic"
	}
	if m.Name == "" {
		m.Name = "Diagnostic"
	}
	if input.Kind == "containers" {
		m.Container = "discovery"
		m.ResourceID = ""
	}
	if e := m.Validate(); e != nil {
		problem(w, 400, e.Error())
		return
	}
	secrets := []string{m.Secret}
	if m.AuthType == "sas" {
		q, _ := url.ParseQuery(strings.TrimPrefix(m.Secret, "?"))
		secrets = append(secrets, q.Get("sig"))
	}
	base := storageTransport
	if base == nil {
		base = http.DefaultClient
	}
	capture := &captureTransport{base: base, secrets: secrets}
	options := azcore.ClientOptions{Transport: capture, Retry: policy.RetryOptions{MaxRetries: -1}}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	start := time.Now()
	var err error
	names := []string{}
	next := ""
	if input.Kind == "containers" {
		endpoint := "https://" + m.Account + ".blob.core.windows.net/"
		var client *service.Client
		if m.AuthType == "accountKey" {
			var credential *service.SharedKeyCredential
			credential, err = service.NewSharedKeyCredential(m.Account, m.Secret)
			if err == nil {
				client, err = service.NewClientWithSharedKeyCredential(endpoint, credential, &service.ClientOptions{ClientOptions: options})
			}
		} else {
			client, err = service.NewClientWithNoCredential(endpoint+"?"+strings.TrimPrefix(m.Secret, "?"), &service.ClientOptions{ClientOptions: options})
		}
		if err == nil {
			opts := &service.ListContainersOptions{MaxResults: to.Ptr(int32(200))}
			if input.Marker != "" {
				opts.Marker = &input.Marker
			}
			page, e := client.NewListContainersPager(opts).NextPage(ctx)
			err = e
			if e == nil {
				for _, c := range page.ContainerItems {
					if c.Name != nil {
						names = append(names, *c.Name)
					}
				}
				if page.NextMarker != nil {
					next = *page.NextMarker
				}
			}
		}
	} else {
		var client *container.Client
		if m.AuthType == "accountKey" {
			var credential *container.SharedKeyCredential
			credential, err = container.NewSharedKeyCredential(m.Account, m.Secret)
			if err == nil {
				client, err = container.NewClientWithSharedKeyCredential(m.BaseURL(), credential, &container.ClientOptions{ClientOptions: options})
			}
		} else {
			client, err = container.NewClientWithNoCredential(m.BaseURL()+"?"+strings.TrimPrefix(m.Secret, "?"), &container.ClientOptions{ClientOptions: options})
		}
		if err == nil {
			_, err = client.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{Prefix: &m.Prefix, MaxResults: to.Ptr(int32(1))}).NextPage(ctx)
		}
	}
	if capture.request == nil {
		capture.request = map[string]any{"method": "GET", "url": func() string {
			if input.Kind == "containers" {
				return "https://" + m.Account + ".blob.core.windows.net/?comp=list"
			}
			return m.BaseURL() + "?restype=container&comp=list"
		}(), "authorization": "[REDACTED]", "sent": false}
	}
	if capture.response == nil {
		capture.response = map[string]any{}
	}
	if err != nil {
		capture.response["error"] = capture.clean(err.Error())
		var re *azcore.ResponseError
		if errors.As(err, &re) {
			capture.response["statusCode"] = re.StatusCode
			capture.response["azureErrorCode"] = re.ErrorCode
		}
	}
	capture.response["elapsedMs"] = time.Since(start).Milliseconds()
	capture.response["attempts"] = capture.attempts
	note := "Read-only container listing test. Destination write permission is checked during file routing. Credentials and SAS parameters are omitted from the displayed request."
	if input.Kind == "containers" {
		note = "Account-wide discovery requires account-level list permissions. A container-scoped SAS can fail discovery while still passing Test container when its name is entered manually."
	}
	a.Audit("storage.test_"+input.Kind, m.Account, func() string {
		if err == nil {
			return "Read-only Azure request succeeded"
		}
		return "Azure diagnostic failed"
	}())
	respond(w, 200, map[string]any{"kind": input.Kind, "account": m.Account, "success": err == nil, "request": capture.request, "response": capture.response, "containers": names, "nextMarker": next, "note": note})
}
