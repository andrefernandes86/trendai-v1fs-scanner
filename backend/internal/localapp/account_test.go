package localapp

import (
	"bytes"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChangePasswordRequiresCurrentAndInvalidatesSessions(t *testing.T) {
	a := testApp(t)
	old := "old-test-password-only"
	next := "new-test-password-only"
	hash, _ := bcrypt.GenerateFromPassword([]byte(old), bcrypt.MinCost)
	a.Save("admin", "default", string(hash))
	a.DB.Exec("INSERT INTO sessions(token,expires) VALUES(?,?)", hashToken("prior-session"), time.Now().Add(time.Hour).Unix())
	change := func(current, newValue string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"currentPassword": current, "newPassword": newValue})
		r := httptest.NewRequest("POST", "/api/account/password", bytes.NewReader(b))
		w := httptest.NewRecorder()
		a.changePassword(w, r)
		return w
	}
	if w := change("wrong", next); w.Code != 403 {
		t.Fatal(w.Code)
	}
	a.DB.Exec("DELETE FROM config WHERE kind='authThrottle' AND id='passwordChange'")
	w := change(old, next)
	if w.Code != 200 || len(w.Result().Cookies()) == 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	var saved string
	a.Get("admin", "default", &saved)
	if bcrypt.CompareHashAndPassword([]byte(saved), []byte(next)) != nil || bcrypt.CompareHashAndPassword([]byte(saved), []byte(old)) == nil {
		t.Fatal("password not replaced")
	}
	var prior, sessions, audits int
	a.DB.QueryRow("SELECT count(*) FROM sessions WHERE token=?", hashToken("prior-session")).Scan(&prior)
	a.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&sessions)
	a.DB.QueryRow("SELECT count(*) FROM audit WHERE action='auth.password_changed'").Scan(&audits)
	if prior != 0 || sessions != 1 || audits != 1 {
		t.Fatal(prior, sessions, audits)
	}
	var payload []byte
	a.DB.QueryRow("SELECT value FROM config WHERE kind='admin'").Scan(&payload)
	if bytes.Contains(payload, []byte(next)) || bytes.Contains(payload, []byte(saved)) {
		t.Fatal("unencrypted password evidence")
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1/api/account/password", bytes.NewBufferString(`{}`))
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("password route did not require session", w.Code)
	}
}
