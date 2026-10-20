package localapp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type App struct {
	lockFile        *os.File
	wg              sync.WaitGroup
	scanFn          func(context.Context, string, Scanner, Profile) ([]byte, error)
	DB              *sql.DB
	aead            cipher.AEAD
	DataDir, WebDir string
	mu              sync.Mutex
	scanMu          sync.Mutex
	wake            chan struct{}
}
type Mount struct {
	Kind            string `json:"kind"`
	Server          string `json:"server"`
	Share           string `json:"share"`
	Username        string `json:"username"`
	Domain          string `json:"domain"`
	Export          string `json:"export"`
	UID             uint32 `json:"uid"`
	GID             uint32 `json:"gid"`
	Port            int    `json:"port"`
	ID              string `json:"id"`
	Name            string `json:"name"`
	ResourceID      string `json:"resourceId"`
	Account         string `json:"account"`
	Container       string `json:"container"`
	Prefix          string `json:"prefix"`
	AuthType        string `json:"authType"`
	Secret          string `json:"secret,omitempty"`
	CredentialSaved bool   `json:"credentialSaved"`
}
type Scanner struct {
	Type     string `json:"type"`
	APIKey   string `json:"apiKey,omitempty"`
	KeySaved bool   `json:"keySaved"`
	Region   string `json:"region"`
	Address  string `json:"address"`
	TLS      bool   `json:"tls"`
}
type Profile struct {
	FailedMount         string `json:"failedMount"`
	FailedPrefix        string `json:"failedPrefix"`
	ScanIntervalSeconds int    `json:"scanIntervalSeconds"`
	ScannedTags         string `json:"scannedTags"`
	CleanTags           string `json:"cleanTags"`
	MaliciousTags       string `json:"maliciousTags"`
	ID                  string `json:"id"`
	Name                string `json:"name"`
	SourceMount         string `json:"sourceMount"`
	Prefix              string `json:"prefix"`
	GoodMount           string `json:"goodMount"`
	GoodPrefix          string `json:"goodPrefix"`
	BadMount            string `json:"badMount"`
	BadPrefix           string `json:"badPrefix"`
	Enabled             bool   `json:"enabled"`
	RequireMarker       bool   `json:"requireMarker"`
	PML                 bool   `json:"pml"`
	ActiveContent       bool   `json:"activeContent"`
	Feedback            bool   `json:"feedback"`
	Verbose             bool   `json:"verbose"`
	Digest              bool   `json:"digest"`
	Revision            int64  `json:"revision"`
}
type Snapshot struct {
	Source             Mount   `json:"source"`
	Good               Mount   `json:"good"`
	Failed             Mount   `json:"failed"`
	Bad                Mount   `json:"bad"`
	Scanner            Scanner `json:"scanner"`
	Profile            Profile `json:"profile"`
	Key, ETag, Version string
	Size               int64
}
type Job struct {
	NewerCompletedJobID  string      `json:"newerCompletedJobId,omitempty"`
	Detections           []Detection `json:"detections"`
	ScanResponseRecorded bool        `json:"scanResponseRecorded"`
	ID                   string      `json:"id"`
	Key                  string      `json:"key"`
	ProfileID            string      `json:"profileId"`
	ProfileName          string      `json:"profileName"`
	SourceID             string      `json:"sourceId"`
	ETag                 string      `json:"etag"`
	Version              string      `json:"version"`
	Size                 int64       `json:"size"`
	State                string      `json:"state"`
	Verdict              string      `json:"verdict"`
	Digest               string      `json:"digest"`
	Destination          string      `json:"destination"`
	Error                string      `json:"error"`
	Attempts             int         `json:"attempts"`
	CreatedAt            string      `json:"createdAt"`
	UpdatedAt            string      `json:"updatedAt"`
}

func Open(data, web string) (*App, error) {
	if e := os.MkdirAll(data, 0700); e != nil {
		return nil, e
	}
	os.Chmod(data, 0700)
	kp := filepath.Join(data, "master.key")
	key, e := os.ReadFile(kp)
	if os.IsNotExist(e) {
		if _, dbErr := os.Stat(filepath.Join(data, "scanner.db")); dbErr == nil {
			return nil, errors.New("master key missing for existing database; restore it from backup")
		}
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return nil, e
		}
		f, e := os.OpenFile(kp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		_, e = f.Write(key)
		f.Close()
		if e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(data, "instance.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("another scanner process is using this data directory")
	}
	success := false
	defer func() {
		if !success {
			lock.Close()
		}
	}()
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	ae, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", filepath.Join(data, "scanner.db"))
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS config(kind TEXT NOT NULL,id TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scan_details(job_id TEXT PRIMARY KEY,payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scan_results(job_id TEXT PRIMARY KEY, scanned_at TEXT NOT NULL, verdict TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,key TEXT NOT NULL,profile_id TEXT NOT NULL,profile_name TEXT NOT NULL,source_id TEXT NOT NULL,etag TEXT NOT NULL,version TEXT NOT NULL,size INTEGER NOT NULL,state TEXT NOT NULL,verdict TEXT NOT NULL DEFAULT 'UNKNOWN',digest TEXT NOT NULL DEFAULT '',destination TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '',attempts INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,available_at INTEGER NOT NULL,snapshot BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS pending_jobs ON jobs(state,available_at);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL,detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(profile_id TEXT NOT NULL,key TEXT NOT NULL,etag TEXT NOT NULL,first_seen INTEGER NOT NULL,PRIMARY KEY(profile_id,key));`)
	if e != nil {
		db.Close()
		return nil, e
	}
	a := &App{lockFile: lock, DB: db, aead: ae, DataDir: data, WebDir: web, wake: make(chan struct{}, 1)}
	_, e = db.Exec("UPDATE jobs SET state='QUEUED' WHERE state IN ('SCANNING','ROUTING')")
	success = e == nil
	return a, e
}
func (a *App) Seal(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return a.aead.Seal(nonce, nonce, b, nil), nil
}
func (a *App) Unseal(b []byte, out any) error {
	n := a.aead.NonceSize()
	if len(b) < n {
		return errors.New("invalid encrypted record")
	}
	plain, e := a.aead.Open(nil, b[:n], b[n:], nil)
	if e != nil {
		return e
	}
	return json.Unmarshal(plain, out)
}
func (a *App) Get(kind, id string, out any) error {
	var b []byte
	if e := a.DB.QueryRow("SELECT value FROM config WHERE kind=? AND id=?", kind, id).Scan(&b); e != nil {
		return e
	}
	return a.Unseal(b, out)
}
func (a *App) List(kind string) ([]json.RawMessage, error) {
	rows, e := a.DB.Query("SELECT value FROM config WHERE kind=? ORDER BY id", kind)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		var v json.RawMessage
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = a.Unseal(b, &v); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (a *App) Save(kind, id string, value any) error {
	b, e := a.Seal(value)
	if e != nil {
		return e
	}
	tx, e := a.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO config(kind,id,value) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET value=excluded.value", kind, id, b); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), kind+".saved", id, "Configuration updated; secrets omitted"); e != nil {
		return e
	}
	return tx.Commit()
}
func stamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func (a *App) Audit(action, id, detail string) {
	_, _ = a.DB.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), action, id, detail)
}
func (a *App) Close() error {
	a.wg.Wait()
	e := a.DB.Close()
	if a.lockFile != nil {
		a.lockFile.Close()
	}
	return e
}
func (a *App) Run(ctx context.Context) {
	for i := 0; i < 2; i++ {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); a.worker(ctx) }()
	}
	a.wg.Add(1)
	go func() { defer a.wg.Done(); a.monitor(ctx) }()
}
