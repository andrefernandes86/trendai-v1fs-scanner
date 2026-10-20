package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
	"syscall"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

// Reservations are engine-local; the single-engine data-directory lock prevents
// competing engines. Full source captures live on the persistent data volume.
var captureBudget struct {
	sync.Mutex
	bytes uint64
}

func reserveCapture(dir string, size int64) (func(), error) {
	captureBudget.Lock()
	defer captureBudget.Unlock()
	var stat syscall.Statfs_t
	if size < 0 || syscall.Statfs(dir, &stat) != nil {
		return nil, errors.New("Cannot check temporary disk capacity; source retained.")
	}
	need := uint64(size) + 32<<20
	available := stat.Bavail * uint64(stat.Bsize)
	const reserve = uint64(5 << 30)
	if available <= reserve || need > available-reserve || captureBudget.bytes > available-reserve-need {
		return nil, errors.New("Waiting for temporary disk capacity: captured file plus 5 GiB reserve required; source retained.")
	}
	captureBudget.bytes += need
	return func() { captureBudget.Lock(); captureBudget.bytes -= need; captureBudget.Unlock() }, nil
}

// Verify remote bytes with bounded buffers, without writing a second local copy.
func streamChecksums(ctx context.Context, s Snapshot) (string, string, int64, error) {
	var r io.ReadCloser
	var fs remoteFS
	var err error
	if s.Source.Type() == "blob" {
		c, e := s.Source.BlobClient(s.Key, s.Version)
		if e != nil {
			return "", "", 0, e
		}
		response, e := c.DownloadStream(ctx, &blob.DownloadStreamOptions{AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: to.Ptr(azcore.ETag(s.ETag))}}})
		if e != nil {
			return "", "", 0, e
		}
		r = response.Body
	} else {
		fs, err = remoteOpen(ctx, s.Source)
		if err != nil {
			return "", "", 0, err
		}
		defer fs.Close()
		before, e := remoteProperties(fs, s.Key)
		if e != nil {
			return "", "", 0, e
		}
		if before.ETag != s.ETag || before.Size != s.Size {
			return "", "", 0, errors.New("destination identity changed")
		}
		r, err = fs.Open(s.Key)
		if err != nil {
			return "", "", 0, err
		}
	}
	defer r.Close()
	sha, crc := sha256.New(), crc32.New(crc32.MakeTable(crc32.Castagnoli))
	n, err := io.Copy(io.MultiWriter(sha, crc), io.LimitReader(r, s.Size+1))
	if err != nil {
		return "", "", n, err
	}
	if fs != nil {
		after, e := remoteProperties(fs, s.Key)
		if e != nil {
			return "", "", n, e
		}
		if after.ETag != s.ETag || after.Size != s.Size {
			return "", "", n, errors.New("destination changed during verification")
		}
	}
	return hex.EncodeToString(sha.Sum(nil)), fmt.Sprintf("%08x", crc.Sum32()), n, nil
}
