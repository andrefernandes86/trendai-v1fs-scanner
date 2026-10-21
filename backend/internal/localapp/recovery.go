package localapp

import (
	"context"
	"fmt"
	"net/http"
)

// Retain a clear rejection for older clients. Delivered files are owned by the
// downstream application, so neither recovery nor enrichment may access them.
func (a *App) recoverJob(_ context.Context, _ string, _ bool) (string, error) {
	return "", fmt.Errorf("Delivered files are managed by the downstream application. Destination recovery and rescanning are disabled; upload a new source file to scan again.")
}
func (a *App) recoverHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := a.recoverJob(r.Context(), r.PathValue("id"), false)
	problem(w, http.StatusConflict, err.Error())
}
