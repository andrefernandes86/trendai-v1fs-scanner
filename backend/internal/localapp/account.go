package localapp

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Current string `json:"currentPassword"`
		New     string `json:"newPassword"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.New) < 12 || len(input.New) > 72 {
		problem(w, 400, "Use a new password between 12 and 72 characters.")
		return
	}
	if input.Current == input.New {
		problem(w, 400, "Choose a different new password.")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var last string
	a.Get("authThrottle", "passwordChange", &last)
	at, _ := time.Parse(time.RFC3339Nano, last)
	if time.Since(at) < 2*time.Second {
		problem(w, 429, "Please wait before trying again.")
		return
	}
	if err := a.Save("authThrottle", "passwordChange", stamp()); err != nil {
		problem(w, 500, "Password change unavailable.")
		return
	}
	var oldHash string
	if a.Get("admin", "default", &oldHash) != nil || bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(input.Current)) != nil {
		problem(w, 403, "Current password is incorrect.")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.New), 12)
	if err != nil {
		problem(w, 500, "Could not secure new password.")
		return
	}
	sealed, err := a.Seal(string(hash))
	if err != nil {
		problem(w, 500, "Could not secure new password.")
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		problem(w, 500, "Password change unavailable.")
		return
	}
	token := hex.EncodeToString(tokenBytes)
	tx, err := a.DB.Begin()
	if err != nil {
		problem(w, 500, "Password change unavailable.")
		return
	}
	defer tx.Rollback()
	var currentPayload []byte
	var currentHash string
	if tx.QueryRow("SELECT value FROM config WHERE kind='admin' AND id='default'").Scan(&currentPayload) != nil || a.Unseal(currentPayload, &currentHash) != nil || currentHash != oldHash {
		problem(w, 409, "Account changed. Sign in again before retrying.")
		return
	}
	if _, err = tx.Exec("UPDATE config SET value=? WHERE kind='admin' AND id='default'", sealed); err != nil {
		problem(w, 500, "Password change failed.")
		return
	}
	if _, err = tx.Exec("DELETE FROM sessions"); err != nil {
		problem(w, 500, "Could not invalidate old sessions.")
		return
	}
	if _, err = tx.Exec("INSERT INTO sessions(token,expires) VALUES(?,?)", hashToken(token), time.Now().Add(12*time.Hour).Unix()); err != nil {
		problem(w, 500, "Could not renew current session.")
		return
	}
	if _, err = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), "auth.password_changed", "admin", "Administrator changed password; previous sessions invalidated."); err != nil {
		problem(w, 500, "Could not audit password change.")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "Could not save password change.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "v1fs_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 43200})
	respond(w, 200, map[string]bool{"authenticated": true})
}
