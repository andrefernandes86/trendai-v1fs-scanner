package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	client "github.com/trendmicro/tm-v1-fs-golang-sdk"
	"os"
	"sync"
)

type Scanner struct {
	Key, Region string
	Simulated   bool
	mu          sync.Mutex
	clients     map[string]*client.AmaasClient
}

func (s *Scanner) Scan(ctx context.Context, path string, p core.Profile) ([]byte, error) {
	if s.Simulated {
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		v := 0
		if bytes.Contains(b, []byte("EICAR")) {
			v = 1
		}
		return json.Marshal(map[string]any{"scanId": "SIMULATED", "scanResult": v, "simulated": true})
	}
	b, _ := json.Marshal(p)
	key := string(b)
	s.mu.Lock()
	if s.clients == nil {
		s.clients = map[string]*client.AmaasClient{}
	}
	c := s.clients[key]
	if c == nil {
		var e error
		c, e = client.NewClientWithOptions(s.Key, s.Region, client.WithPML(p.PML), client.WithActiveContent(p.ActiveContent), client.WithFeedback(p.Feedback), client.WithVerbose(p.Verbose), client.WithDigest(p.Digest), client.WithV1Direct(p.Direct))
		if e != nil {
			s.mu.Unlock()
			return nil, e
		}
		s.clients[key] = c
	}
	s.mu.Unlock()
	r, e := c.ScanFileWithContext(ctx, path, []string{"gateway:v1fs"})
	return []byte(r), e
}
func (s *Scanner) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		c.Destroy()
	}
}
