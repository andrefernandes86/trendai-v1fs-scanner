package main

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/adapters"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/httpapi"
	"github.com/andrefernandes86/trendai-v1fs-scanner/migrations"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if e := run(); e != nil {
		slog.Error("gateway stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	pool, e := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		return e
	}
	defer pool.Close()
	if e = pool.Ping(ctx); e != nil {
		return e
	}
	store := &core.Store{DB: pool}
	mode := os.Getenv("MODE")
	if mode == "migrate" {
		_, e = pool.Exec(ctx, migrations.SQL)
		return e
	}
	sim := os.Getenv("SIMULATED_SCANNER") == "true"
	if sim && os.Getenv("ENVIRONMENT") != "test" {
		return &configError{"simulator requires ENVIRONMENT=test"}
	}
	if mode == "api" || mode == "" {
		issuer := os.Getenv("ENTRA_ISSUER")
		aud := os.Getenv("ENTRA_AUDIENCE")
		if issuer == "" || aud == "" {
			return &configError{"Entra issuer and audience are required"}
		}
		provider, e := oidc.NewProvider(ctx, issuer)
		if e != nil {
			return e
		}
		api := &httpapi.API{Store: store, Verifier: provider.Verifier(&oidc.Config{ClientID: aud}), Origin: os.Getenv("CONSOLE_ORIGIN"), Simulated: sim}
		server := &http.Server{Addr: ":8080", Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			server.Shutdown(sctx)
		}()
		slog.Info("API listening", "port", 8080)
		e = server.ListenAndServe()
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	}
	cred, e := azidentity.NewDefaultAzureCredential(nil)
	if e != nil {
		return e
	}
	bc, e := azservicebus.NewClient(os.Getenv("SERVICEBUS_NAMESPACE"), cred, nil)
	if e != nil {
		return e
	}
	defer bc.Close(context.Background())
	bus := &adapters.Bus{Client: bc, Prefix: "v1fs-"}
	scanner := &adapters.Scanner{Key: os.Getenv("TM_AM_AUTH_KEY"), Region: os.Getenv("TM_REGION"), Simulated: sim}
	defer scanner.Close()
	worker := &adapters.Worker{Store: store, Storage: &adapters.Storage{Credential: cred}, Scanner: scanner, Capacity: core.Capacity{Global: 8, Tenant: 4, PerWorker: 2, MaxAttempts: 5, MinReplicas: 1, MaxReplicas: 10}}
	metrics := &http.Server{Addr: ":9090", Handler: promhttp.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go metrics.ListenAndServe()
	defer metrics.Close()
	var wg sync.WaitGroup
	launch := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }
	switch mode {
	case "dispatch":
		launch(func() { repeat(ctx, 250*time.Millisecond, func() error { return bus.Dispatch(ctx, store) }) })
	case "reconcile":
		launch(func() { repeat(ctx, time.Minute, func() error { return worker.Reconcile(ctx) }) })
	case "scan", "promote", "quarantine", "retry":
		cap := worker.Capacity
		_ = store.Config(ctx, "capacity", "default", &cap)
		for n := 0; n < cap.PerWorker; n++ {
			launch(func() { repeat(ctx, 5*time.Second, func() error { return bus.Consume(ctx, mode, worker.Handle) }) })
		}
	default:
		return &configError{"unsupported MODE"}
	}
	wg.Wait()
	return nil
}

type configError struct{ s string }

func (e *configError) Error() string { return e.s }
func repeat(ctx context.Context, d time.Duration, fn func() error) {
	for ctx.Err() == nil {
		if e := fn(); e != nil {
			slog.Error("background operation failed", "error", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}
