package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func healthURL() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8095"
	}
	scheme := "http"
	if os.Getenv("V1FS_TLS_CERT") != "" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort("127.0.0.1", port) + "/livez"
}
func healthCheck() error {
	client := &http.Client{Timeout: 3 * time.Second}
	if certFile := os.Getenv("V1FS_TLS_CERT"); certFile != "" {
		data, e := os.ReadFile(certFile)
		if e != nil {
			return e
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("invalid local TLS certificate")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return e
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		roots.AppendCertsFromPEM(data)
		serverName := "127.0.0.1"
		if len(cert.DNSNames) > 0 {
			serverName = cert.DNSNames[0]
		} else if len(cert.IPAddresses) > 0 {
			serverName = cert.IPAddresses[0].String()
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}}
	}
	r, e := client.Get(healthURL())
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("liveness status %d", r.StatusCode)
	}
	return nil
}
func supervisorDuration(key string, fallback time.Duration) time.Duration {
	n, e := strconv.Atoi(os.Getenv(key))
	if e != nil || n < 1 {
		return fallback
	}
	return time.Duration(n) * time.Second
}
func supervise() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	executable, e := os.Executable()
	if e != nil {
		log.Fatal(e)
	}
	backoff := time.Second
	for ctx.Err() == nil {
		cmd := exec.Command(executable, "-serve")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = nil
		if e = cmd.Start(); e != nil {
			log.Printf("Cannot start scanner: %v", e)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		log.Printf("Supervisor started scanner PID %d", cmd.Process.Pid)
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		interval := supervisorDuration("V1FS_WATCHDOG_INTERVAL_SECONDS", 5*time.Second)
		ticker := time.NewTicker(interval)
		started := time.Now()
		failures := 0
		finished := false
		terminate := func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-exited
			}
		}
		for !finished {
			select {
			case <-ctx.Done():
				ticker.Stop()
				terminate()
				return
			case err := <-exited:
				log.Printf("Scanner exited (%v); supervisor will restart it", err)
				finished = true
			case <-ticker.C:
				if time.Since(started) < supervisorDuration("V1FS_WATCHDOG_STARTUP_SECONDS", 20*time.Second) {
					continue
				}
				if err := healthCheck(); err != nil {
					failures++
					log.Printf("Scanner watchdog check %d/3 failed: %v", failures, err)
				} else {
					failures = 0
					if time.Since(started) > time.Minute {
						backoff = time.Second
					}
				}
				if failures >= 3 {
					log.Printf("Restarting unhealthy scanner process")
					terminate()
					finished = true
				}
			}
		}
		ticker.Stop()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}
