package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/directory"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/file"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"log/slog"
	"strings"
	"time"
)

func (w *Worker) Reconcile(ctx context.Context) error {
	sources, e := w.Store.List(ctx, "sources")
	if e != nil {
		return e
	}
	for _, b := range sources {
		var s core.Source
		if json.Unmarshal(b, &s) != nil || !s.Enabled {
			continue
		}
		if s.Kind == "files" {
			e = w.walk(ctx, s, strings.TrimSuffix(s.Prefix, "/"), 0)
		} else {
			e = w.blobs(ctx, s)
		}
		if e != nil {
			slog.Error("source reconciliation failed", "source", s.ID, "error", e)
		}
	}
	rows, e := w.Store.DB.Query(ctx, "SELECT id FROM jobs WHERE state IN ('SCANNING','SCANNED','PROMOTING','QUEUED','PROMOTION_PENDING') AND updated_at<now()-interval '15 minutes' LIMIT 500")
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		tx, e := w.Store.DB.Begin(ctx)
		if e != nil {
			return e
		}
		e = w.Store.Enqueue(ctx, tx, id, "retry", 0)
		if e == nil {
			_, e = tx.Exec(ctx, "UPDATE outbox SET sent_at=NULL,available_at=now() WHERE job_id=$1 AND id=(SELECT max(id) FROM outbox WHERE job_id=$1)", id)
		}
		if e != nil {
			tx.Rollback(ctx)
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
	}
	return nil
}
func (w *Worker) blobs(ctx context.Context, s core.Source) error {
	c, e := container.NewClient(fmt.Sprintf("https://%s.blob.core.windows.net/%s", s.Account, s.Container), w.Storage.Credential, nil)
	if e != nil {
		return e
	}
	pager := c.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{Prefix: &s.Prefix, Include: container.ListBlobsInclude{Metadata: true, Versions: true}})
	for pager.More() {
		p, e := pager.NextPage(ctx)
		if e != nil {
			return e
		}
		for _, b := range p.Segment.BlobItems {
			if b.Name == nil || b.Properties == nil || b.Properties.ETag == nil || b.Properties.ContentLength == nil {
				continue
			}
			marker := b.Metadata["v1fs-complete"]
			if marker == nil || *marker != "true" {
				continue
			}
			v := ""
			if b.VersionID != nil {
				v = *b.VersionID
			}
			if e = w.Store.Discover(ctx, core.Job{SourceID: s.ID, Tenant: s.Tenant, ProfileID: s.ProfileID, Key: *b.Name, Version: v, ETag: string(*b.Properties.ETag), Size: *b.Properties.ContentLength}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (w *Worker) walk(ctx context.Context, s core.Source, path string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("directory nesting exceeds policy")
	}
	u := fmt.Sprintf("https://%s.file.core.windows.net/%s", s.Account, s.Container)
	if path != "" {
		u += "/" + path
	}
	d, e := directory.NewClient(u, w.Storage.Credential, &directory.ClientOptions{FileRequestIntent: to.Ptr(directory.ShareTokenIntentBackup)})
	if e != nil {
		return e
	}
	pager := d.NewListFilesAndDirectoriesPager(nil)
	for pager.More() {
		page, e := pager.NextPage(ctx)
		if e != nil {
			return e
		}
		for _, dir := range page.Segment.Directories {
			if dir.Name == nil {
				continue
			}
			key := strings.TrimPrefix(path+"/"+*dir.Name, "/")
			if !core.ValidKey(key) {
				continue
			}
			if e = w.walk(ctx, s, key, depth+1); e != nil {
				return e
			}
		}
		for _, f := range page.Segment.Files {
			if f.Name == nil || strings.HasSuffix(*f.Name, ".complete") {
				continue
			}
			key := strings.TrimPrefix(path+"/"+*f.Name, "/")
			if !core.ValidKey(key) {
				continue
			}
			fc, e := file.NewClient(ObjectURL(s, key), w.Storage.Credential, &file.ClientOptions{FileRequestIntent: to.Ptr(file.ShareTokenIntentBackup)})
			if e != nil {
				return e
			}
			props, e := fc.GetProperties(ctx, nil)
			if e != nil {
				return e
			}
			if props.ETag == nil || props.ContentLength == nil {
				continue
			}
			mc, e := file.NewClient(ObjectURL(s, key+".complete"), w.Storage.Credential, &file.ClientOptions{FileRequestIntent: to.Ptr(file.ShareTokenIntentBackup)})
			if e != nil {
				return e
			}
			mp, e := mc.GetProperties(ctx, nil)
			if e != nil {
				continue
			}
			if mp.LastModified == nil || props.LastModified == nil || mp.LastModified.Before(*props.LastModified) {
				continue
			}
			var first time.Time
			e = w.Store.DB.QueryRow(ctx, "INSERT INTO observations(source_id,object_key,etag,size) VALUES($1,$2,$3,$4) ON CONFLICT(source_id,object_key) DO UPDATE SET first_seen=CASE WHEN observations.etag=excluded.etag AND observations.size=excluded.size THEN observations.first_seen ELSE now() END,etag=excluded.etag,size=excluded.size,last_seen=now() RETURNING first_seen", s.ID, key, string(*props.ETag), *props.ContentLength).Scan(&first)
			if e != nil {
				return e
			}
			if time.Since(first) < 60*time.Second {
				continue
			}
			if e = w.Store.Discover(ctx, core.Job{SourceID: s.ID, Tenant: s.Tenant, ProfileID: s.ProfileID, Key: key, ETag: string(*props.ETag), Size: *props.ContentLength}); e != nil {
				return e
			}
		}
	}
	return nil
}
