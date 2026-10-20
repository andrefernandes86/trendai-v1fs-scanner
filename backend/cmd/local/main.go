package main

import (
	"context"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/localapp"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-supervise":
			supervise()
			return
		case "-healthcheck":
			if e := healthCheck(); e != nil {
				log.Print(e)
				os.Exit(1)
			}
			return
		case "-serve":
		default:
			log.Fatal("Unknown command")
		}
	}
	data := os.Getenv("V1FS_DATA_DIR")
	if data == "" {
		data = "data"
	}
	web := os.Getenv("V1FS_WEB_DIR")
	if web == "" {
		web = "../dist"
	}
	a, e := localapp.Open(data, web)
	if e != nil {
		log.Fatal("Cannot open local scanner storage: ", e)
	}
	defer a.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a.Run(ctx)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8095"
	}
	srv := &http.Server{Addr: ":" + port, Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 90 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	p, _ := filepath.Abs(data)
	log.Printf("Local Blob scanner listening on port %s; persistent data %s", port, p)
	cert, key := os.Getenv("V1FS_TLS_CERT"), os.Getenv("V1FS_TLS_KEY")
	if cert != "" && key != "" {
		e = srv.ListenAndServeTLS(cert, key)
	} else {
		e = srv.ListenAndServe()
	}
	if e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
