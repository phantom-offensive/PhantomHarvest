//go:build decrypt && linux

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"

	"github.com/godbus/dbus/v5"
	"golang.org/x/crypto/pbkdf2"
)

// getChromiumMasterKey tries the Secret Service first then falls back to
// the literal "peanuts" password (Chromium's default when no keyring).
// Linux Chromium has no app-bound encryption, so V20 is always nil.
func getChromiumMasterKey(profileDir, browserName string) (*chromiumKeys, error) {
	password := lookupSecretService(browserName)
	if password == "" {
		password = "peanuts"
	}
	return &chromiumKeys{V10: pbkdf2.Key([]byte(password), []byte("saltysalt"), 1, 16, sha1.New)}, nil
}

// lookupSecretService queries org.freedesktop.secrets for the browser's
// "Safe Storage" password. Best-effort: returns "" on any failure.
func lookupSecretService(browserName string) string {
	conn, err := dbus.SessionBus()
	if err != nil {
		return ""
	}
	defer conn.Close()

	secrets := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
	attrs := map[string]string{
		"application": "chrome",
	}
	var unlocked, locked []dbus.ObjectPath
	if err := secrets.Call("org.freedesktop.Secret.Service.SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		return ""
	}
	items := append(unlocked, locked...)
	if len(items) == 0 {
		return ""
	}
	// Open a plain session.
	var sessionOut dbus.Variant
	var sessionPath dbus.ObjectPath
	if err := secrets.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&sessionOut, &sessionPath); err != nil {
		return ""
	}
	item := conn.Object("org.freedesktop.secrets", items[0])
	var secret struct {
		Session     dbus.ObjectPath
		Parameters  []byte
		Value       []byte
		ContentType string
	}
	if err := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, sessionPath).Store(&secret); err != nil {
		return ""
	}
	return string(secret.Value)
}

// chromiumDecryptValue: AES-CBC with 16-space IV, PBKDF2-derived key,
// strip 3-byte v10/v11 prefix.
func chromiumDecryptValue(blob []byte, keys *chromiumKeys) ([]byte, error) {
	if len(blob) < 3 {
		return nil, fmt.Errorf("blob too short")
	}
	if bytes.Equal(blob[:3], []byte("v10")) || bytes.Equal(blob[:3], []byte("v11")) {
		blob = blob[3:]
	}
	key := keys.V10
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(blob)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not a multiple of block size")
	}
	iv := bytes.Repeat([]byte{' '}, 16)
	mode := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(blob))
	mode.CryptBlocks(out, blob)
	return pkcs7Unpad(out), nil
}

func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad <= 0 || pad > len(b) {
		return b
	}
	return b[:len(b)-pad]
}
