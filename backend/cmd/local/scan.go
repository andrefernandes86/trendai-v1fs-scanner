package main

import (
	"context"
	"encoding/json"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/localapp"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func runIsolatedScan() {
	output := os.NewFile(3, "scan-result")
	if output == nil {
		os.Exit(1)
	}
	defer output.Close()
	var request localapp.ScanRequest
	if json.NewDecoder(io.LimitReader(os.Stdin, 128<<10)).Decode(&request) != nil {
		_ = json.NewEncoder(output).Encode(localapp.ScanReply{Error: "Invalid isolated scanner request"})
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, request.Profile.JobTimeout())
	defer cancel()
	response, err := (&localapp.App{}).ScanDirect(ctx, request.Path, request.Scanner, request.Profile)
	result := localapp.ScanReply{Response: response}
	if err != nil {
		result.Error = err.Error()
	}
	_ = json.NewEncoder(output).Encode(result)
}
