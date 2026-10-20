package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"github.com/jackc/pgx/v5"
	"time"
)

type Bus struct {
	Client *azservicebus.Client
	Prefix string
}

func (b *Bus) Dispatch(ctx context.Context, s *core.Store) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var id int64
	var queue string
	var payload []byte
	e = tx.QueryRow(ctx, "SELECT id,queue,payload FROM outbox WHERE sent_at IS NULL AND available_at<=now() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1").Scan(&id, &queue, &payload)
	if e == pgx.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	sender, e := b.Client.NewSender(b.Prefix+queue, nil)
	if e != nil {
		return e
	}
	defer sender.Close(ctx)
	mid := fmt.Sprintf("outbox-%d", id)
	e = sender.SendMessage(ctx, &azservicebus.Message{Body: payload, MessageID: &mid}, nil)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE outbox SET sent_at=now() WHERE id=$1", id); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (b *Bus) Consume(ctx context.Context, queue string, handle func(context.Context, string) error) error {
	r, e := b.Client.NewReceiverForQueue(b.Prefix+queue, nil)
	if e != nil {
		return e
	}
	defer r.Close(context.Background())
	for ctx.Err() == nil {
		msgs, e := r.ReceiveMessages(ctx, 1, nil)
		if e != nil {
			return e
		}
		for _, m := range msgs {
			var p struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(m.Body, &p) != nil || p.ID == "" {
				reason := "Malformed job"
				_ = r.DeadLetterMessage(ctx, m, &azservicebus.DeadLetterOptions{Reason: &reason})
				continue
			}
			cctx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				t := time.NewTicker(15 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-done:
						return
					case <-cctx.Done():
						return
					case <-t.C:
						if r.RenewMessageLock(cctx, m, nil) != nil {
							cancel()
							return
						}
					}
				}
			}()
			e = handle(cctx, p.ID)
			close(done)
			cancel()
			if e == nil {
				_ = r.CompleteMessage(ctx, m, nil)
			} else {
				_ = r.AbandonMessage(ctx, m, nil)
			}
		}
	}
	return ctx.Err()
}
