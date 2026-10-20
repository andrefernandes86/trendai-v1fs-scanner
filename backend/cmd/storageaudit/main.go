package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/localapp"
	"os"
	"strings"
)

func main() {
	data := flag.String("data", "", "Existing data directory, read only")
	limit := flag.Int("limit", 4, "Destinations to inspect")
	prefix := flag.String("prefix", "", "Source-key prefix to inspect")
	mount := flag.String("mount", "", "Inspect a native storage listing for this saved mount")
	flag.Parse()
	if e := run(*data, *limit, *prefix, *mount); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(data string, limit int, prefix string, mount string) error {
	a, e := localapp.OpenReadOnly(data)
	if e != nil {
		return e
	}
	defer a.Close()
	if mount != "" {
		var m localapp.Mount
		if e = a.Get("mounts", mount, &m); e != nil {
			return e
		}
		files, _, e := localapp.ListBlobs(context.Background(), m, prefix, "", true)
		if e != nil {
			return e
		}
		for i, f := range files {
			if i >= limit {
				break
			}
			b, _ := json.Marshal(map[string]any{"file": f.Key, "tags": f.Tags, "metadataVerdict": f.Metadata["verdict"], "tagsUnavailable": f.TagsUnavailable})
			fmt.Println(string(b))
		}
		return nil
	}
	rows, e := a.DB.Query("SELECT id,key,verdict,destination,snapshot FROM jobs WHERE state IN ('COMPLETED','QUARANTINED') AND destination<>'' AND key LIKE ? ORDER BY created_at DESC LIMIT ?", prefix+"%", limit)
	if e != nil {
		return e
	}
	type rec struct {
		id, key, verdict, destination string
		payload                       []byte
	}
	var list []rec
	for rows.Next() {
		var r rec
		if e = rows.Scan(&r.id, &r.key, &r.verdict, &r.destination, &r.payload); e != nil {
			return e
		}
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		var s localapp.Snapshot
		if e = a.Unseal(r.payload, &s); e != nil {
			return e
		}
		m := s.Good
		if r.verdict == "MALICIOUS" {
			m = s.Bad
		}
		key := strings.TrimPrefix(r.destination, m.BaseURL()+"/")
		client, e := m.BlobClient(key, "")
		if e != nil {
			return e
		}
		v, e := client.GetTags(context.Background(), nil)
		if e != nil {
			return e
		}
		tags := map[string]string{}
		for _, t := range v.BlobTagSet {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}
		out := map[string]any{"job": r.id, "file": r.key, "verdict": r.verdict, "nativeTags": tags}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	}
	return nil
}
