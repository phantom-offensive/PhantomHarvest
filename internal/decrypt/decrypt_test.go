//go:build decrypt && linux

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite"
)

// TestChromiumLinuxRoundTrip encrypts a known password the same way Chromium
// does on Linux (peanuts + PBKDF2 + AES-CBC + 16-space IV + v10 prefix),
// stuffs it into a real SQLite Login Data file, and verifies the decrypt
// pipeline returns the original plaintext.
func TestChromiumLinuxRoundTrip(t *testing.T) {
	const wantPW = "hunter2-correct-horse"
	key := pbkdf2.Key([]byte("peanuts"), []byte("saltysalt"), 1, 16, sha1.New)

	// PKCS7 pad + AES-CBC encrypt + v10 prefix.
	pt := []byte(wantPW)
	pad := aes.BlockSize - len(pt)%aes.BlockSize
	for i := 0; i < pad; i++ {
		pt = append(pt, byte(pad))
	}
	block, _ := aes.NewCipher(key)
	iv := bytes.Repeat([]byte{' '}, 16)
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, pt)
	enc := append([]byte("v10"), ct...)

	// Round-trip directly through chromiumDecryptValue.
	keys := &chromiumKeys{V10: key}
	got, err := chromiumDecryptValue(enc, keys)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != wantPW {
		t.Fatalf("plaintext mismatch: got %q want %q", got, wantPW)
	}

	// Now build a fake Login Data sqlite file and run the full pipeline.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Login Data")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO logins VALUES (?, ?, ?)`, "https://example.com", "alice", enc); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	findings, err := decryptChromiumLogins(dbPath, keys, "TestBrowser")
	if err != nil {
		t.Fatalf("decryptChromiumLogins: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Value != wantPW {
		t.Fatalf("finding value mismatch: got %q want %q", findings[0].Value, wantPW)
	}

	// Sanity: ensure tmp file copy was cleaned up.
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("source db disappeared: %v", err)
	}
}
