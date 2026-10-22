package localapp

import (
	"context"
	client "github.com/trendmicro/tm-v1-fs-golang-sdk"
	"path/filepath"
)

type scanIdentifierKey struct{}

// WithScanIdentifier carries the original storage key independently of the local capture path.
func WithScanIdentifier(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, scanIdentifierKey{}, name)
}
func scanIdentifier(ctx context.Context, local string) string {
	if name, ok := ctx.Value(scanIdentifierKey{}).(string); ok && name != "" {
		return name
	}
	return filepath.Base(local)
}

// The SDK reads the existing captured file; only its reporting identity changes.
// No rename, extra disk copy, or whole-file memory buffer is needed.
type namedScanReader struct {
	*client.AmaasClientFileReader
	name string
}

func (r namedScanReader) Identifier() string { return r.name }

var _ client.AmaasClientReader = namedScanReader{}
