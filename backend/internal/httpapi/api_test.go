package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnconfiguredIdentityFailsClosed(t *testing.T) {
	a := &API{Origin: "https://console.example"}
	for _, path := range []string{"/api/jobs", "/api/config/sources", "/api/audit", "/api/eventgrid"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 503 {
			t.Fatalf("%s exposed without identity: %d", path, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("untrusted CORS origin allowed")
		}
	}
}
