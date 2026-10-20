package localapp

import "fmt"

type ArchiveOptions struct {
	Enabled       bool  `json:"enabled"`
	MaxDepth      int   `json:"maxDepth"`
	MaxFiles      int   `json:"maxFiles"`
	MaxBytes      int64 `json:"maxBytes"`
	MaxEntryBytes int64 `json:"maxEntryBytes"`
	MaxRatio      int   `json:"maxRatio"`
	Seconds       int   `json:"seconds"`
	Concurrency   int   `json:"concurrency"`
}

func (o ArchiveOptions) Defaults() ArchiveOptions {
	if o.MaxDepth == 0 {
		o.MaxDepth = 5
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = 1000
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 10_000_000_000
	}
	if o.MaxEntryBytes == 0 {
		o.MaxEntryBytes = 2_000_000_000
	}
	if o.MaxRatio == 0 {
		o.MaxRatio = 100
	}
	if o.Seconds == 0 {
		o.Seconds = 300
	}
	if o.Concurrency == 0 {
		o.Concurrency = 1
	}
	return o
}
func (o ArchiveOptions) Validate() error {
	o = o.Defaults()
	if o.MaxDepth < 1 || o.MaxDepth > 20 || o.MaxFiles < 1 || o.MaxFiles > 10000 || o.MaxBytes < 1 || o.MaxBytes > 100_000_000_000 || o.MaxEntryBytes < 1 || o.MaxEntryBytes > o.MaxBytes || o.MaxRatio < 1 || o.MaxRatio > 10000 || o.Seconds < 1 || o.Seconds > 3600 || o.Concurrency < 1 || o.Concurrency > 2 {
		return fmt.Errorf("Archive limits: depth 1–20, entries 1–10000, expanded bytes 1–100 GB, member bytes <= total, ratio 1–10000, extraction seconds 1–3600, concurrent inspections 1–2.")
	}
	return nil
}
