package localapp

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	fileservice "github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/service"
	smb "github.com/cloudsoda/go-smb2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func smbShares(ctx context.Context, m Mount) ([]string, error) {
	port := m.Port
	if port == 0 {
		port = 445
	}
	conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.Server, fmt.Sprint(port)))
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	d := smb.Dialer{Negotiator: smb.Negotiator{RequireMessageSigning: true}, Initiator: &smb.NTLMInitiator{User: m.Username, Password: m.Secret, Domain: m.Domain}}
	session, e := d.DialConn(ctx, &smbDiscoveryConn{Conn: conn, server: m.Server}, net.JoinHostPort(m.Server, fmt.Sprint(port)))
	if e != nil {
		return nil, e
	}
	session = session.WithContext(ctx)
	defer session.Logoff()
	return session.WithContext(ctx).ListSharenames()
}
func (a *App) shareStorageTest(w http.ResponseWriter, r *http.Request, kind string, m Mount, marker string) {
	if kind != "container" && kind != "containers" {
		problem(w, 400, "Select share discovery or share test.")
		return
	}
	if m.ID == "" {
		m.ID = "diagnostic"
	}
	if m.Name == "" {
		m.Name = "Diagnostic"
	}
	var old Mount
	if m.Secret == "" && a.Get("mounts", m.ID, &old) == nil && sameCredentialTarget(m, old) {
		m.Secret = old.Secret
	}
	if kind == "containers" {
		if m.Type() == "nfs" && m.Export == "" {
			m.Export = "/discovery"
		}
		if m.Share == "" {
			m.Share = "discovery"
		}
	}
	if e := m.Validate(); e != nil {
		problem(w, 400, e.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	started := time.Now()
	request := map[string]any{"transport": "protocol operation summary; not a wire capture", "protocol": m.Type(), "operation": func() string {
		if kind == "containers" {
			return "List shares/exports"
		}
		return "Read share root directory"
	}(), "endpoint": m.BaseURL(), "prefix": m.Prefix, "credentials": "[REDACTED]"}
	if m.Type() == "smb" {
		request["username"] = m.Username
		request["domain"] = m.Domain
	}
	if m.Type() == "nfs" {
		request["protocol"] = "NFSv3 TCP AUTH_SYS"
		request["uid"] = m.UID
		request["gid"] = m.GID
	}
	if kind == "containers" && m.Type() != "azureFiles" {
		request["endpoint"] = m.Server
	}
	names := []string{}
	entries := []map[string]any{}
	next := ""
	var e error
	var capture *captureTransport
	if m.Type() == "azureFiles" {
		base := storageTransport
		if base == nil {
			base = http.DefaultClient
		}
		capture = &captureTransport{base: base, secrets: []string{m.Secret}}
		if m.AuthType == "sas" {
			capture.secrets = append(capture.secrets, sasSignature(m.Secret))
		}
		opts := azcore.ClientOptions{Transport: capture}
		if kind == "containers" {
			endpoint := "https://" + m.Account + ".file.core.windows.net/"
			var c *fileservice.Client
			if m.AuthType == "sas" {
				c, e = fileservice.NewClientWithNoCredential(endpoint+"?"+strings.TrimPrefix(m.Secret, "?"), &fileservice.ClientOptions{ClientOptions: opts})
			} else {
				cred, ce := fileservice.NewSharedKeyCredential(m.Account, m.Secret)
				e = ce
				if e == nil {
					c, e = fileservice.NewClientWithSharedKeyCredential(endpoint, cred, &fileservice.ClientOptions{ClientOptions: opts})
				}
			}
			if e == nil {
				o := &fileservice.ListSharesOptions{MaxResults: to.Ptr(int32(200))}
				if marker != "" {
					o.Marker = &marker
				}
				page, pe := c.NewListSharesPager(o).NextPage(ctx)
				e = pe
				if pe == nil {
					for _, v := range page.Shares {
						if v.Name != nil {
							names = append(names, *v.Name)
						}
					}
					if page.NextMarker != nil {
						next = *page.NextMarker
					}
				}
			}
		} else {
			fs := &azureFiles{ctx: ctx, m: m, options: opts}
			d, de := fs.dir("")
			e = de
			if e == nil {
				_, e = d.NewListFilesAndDirectoriesPager(nil).NextPage(ctx)
			}
		}
	} else if kind == "containers" {
		if m.Type() == "smb" {
			names, e = smbShares(ctx, m)
		} else {
			names, e = nfsExports(ctx, m)
		}
	} else {
		var fs remoteFS
		fs, e = remoteOpen(ctx, m)
		if e == nil {
			items, re := fs.ReadDir("")
			e = re
			for i, v := range items {
				if i >= 200 {
					break
				}
				entries = append(entries, map[string]any{"name": v.Name(), "directory": v.IsDir(), "size": v.Size()})
			}
			fs.Close()
		}
	}
	response := map[string]any{"elapsedMs": time.Since(started).Milliseconds(), "entries": entries}
	if capture != nil {
		if capture.request != nil {
			request = capture.request
		}
		for k, v := range capture.response {
			response[k] = v
		}
	}
	if e != nil {
		if capture != nil {
			response["error"] = capture.clean(e.Error())
		} else {
			response["error"] = redactString(e.Error(), m.Secret)
			if m.Type() == "smb" && kind == "containers" {
				response["guidance"] = "Server share enumeration requires IPC$/SRVSVC permissions. A known share can still be entered and tested directly; listing is not required to save it."
			}
		}
	}
	a.Audit("storage.test_"+m.Type(), m.ID, func() string {
		if e == nil {
			return "Read-only share operation succeeded"
		}
		return "Share operation failed"
	}())
	respond(w, 200, map[string]any{"kind": kind, "storageType": m.Type(), "account": m.Account, "success": e == nil, "request": request, "response": response, "containers": names, "nextMarker": next, "note": "Read-only connection test. Shares use fresh filename.complete sidecars for upload completion. NFS supports v3 TCP AUTH_SYS; NFSv4 and Kerberos are not implemented. Destination write access is checked during routing."})
}

func sasSignature(s string) string {
	q, _ := url.ParseQuery(strings.TrimPrefix(s, "?"))
	return q.Get("sig")
}

// SRVSVC expects a server name, not the TCP peer string containing :445.
type smbDiscoveryAddr string

func (a smbDiscoveryAddr) Network() string { return "tcp" }
func (a smbDiscoveryAddr) String() string  { return string(a) }

type smbDiscoveryConn struct {
	net.Conn
	server string
}

func (c *smbDiscoveryConn) RemoteAddr() net.Addr { return smbDiscoveryAddr(c.server) }
