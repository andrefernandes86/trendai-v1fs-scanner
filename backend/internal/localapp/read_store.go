package localapp

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"os"
	"path/filepath"
)

// OpenReadOnly inspects encrypted records without claiming runtime ownership or changing job states.
func OpenReadOnly(data string) (*App, error) {
	data, e := filepath.Abs(data)
	if e != nil {
		return nil, e
	}
	key, e := os.ReadFile(filepath.Join(data, "master.key"))
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	ae, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", "file:"+filepath.Join(data, "scanner.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if e != nil {
		return nil, e
	}
	return &App{DB: db, aead: ae, DataDir: data}, nil
}
