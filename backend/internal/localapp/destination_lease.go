package localapp

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"
	"sync"
	"time"
)

// A renewable destination lease prevents overwrite/delete during verify-and-delete finalization.
func leaseDestination(ctx context.Context, id string, m MoveRecord) (context.Context, func(), error) {
	if m.Target.Type() != "blob" {
		return ctx, func() {}, nil
	}
	b, e := m.Target.BlobClient(m.Key, "")
	if e != nil {
		return ctx, nil, e
	}
	// Deterministic lease ownership permits restart recovery; the finite lease also expires if the host dies.
	if len(id) < 32 {
		return ctx, nil, fmt.Errorf("invalid lease identity")
	}
	token := id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:32]
	l, e := lease.NewBlobClient(b, &lease.BlobClientOptions{LeaseID: to.Ptr(token)})
	if e != nil {
		return ctx, nil, e
	}
	if _, e = l.AcquireLease(ctx, 60, nil); e != nil {
		if _, e = l.RenewLease(ctx, nil); e != nil {
			return ctx, nil, e
		}
	}
	locked, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-locked.Done():
				return
			case <-t.C:
				if _, e := l.RenewLease(locked, nil); e != nil {
					cancel()
					return
				}
			}
		}
	}()
	release := func() {
		cancel()
		wg.Wait()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = l.ReleaseLease(c, nil)
	}
	return locked, release, nil
}
