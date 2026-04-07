//go:build decrypt

package decrypt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
func DecryptChromiumProfile(profileDir, browserName string) ([]DecryptedFinding, error) {
	key, err := getChromiumMasterKey(profileDir, browserName)
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

	// Saved logins
	if logins, err := decryptChromiumLogins(filepath.Join(profileDir, "Login Data"), key, browserName); err == nil {
		out = append(out, logins...)
	}
	// Cookies
	if cookies, err := decryptChromiumCookies(filepath.Join(profileDir, "Network", "Cookies"), key, browserName); err == nil {
		out = append(out, cookies...)
	} else if cookies, err := decryptChromiumCookies(filepath.Join(profileDir, "Cookies"), key, browserName); err == nil {
		out = append(out, cookies...)
	}
	// Credit cards & autofill
	if cards, err := decryptChromiumWebData(filepath.Join(profileDir, "Web Data"), key, browserName); err == nil {
		out = append(out, cards...)
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

func decryptChromiumLogins(dbPath string, key []byte, browser string) ([]DecryptedFinding, error) {
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
		pw, err := chromiumDecryptValue(enc, key)
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

func decryptChromiumCookies(dbPath string, key []byte, browser string) ([]DecryptedFinding, error) {
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
		val, err := chromiumDecryptValue(enc, key)
		if err != nil || len(val) == 0 {
			continue
		}
		out = append(out, DecryptedFinding{
			Category:   "Browser",
			Type:       "cookie",
			File:       dbPath,
			Key:        fmt.Sprintf("%s | %s | %s", browser, host, name),
			Value:      truncateStr(string(val), 256),
			Confidence: ConfHigh,
		})
	}
	return out, nil
}

func decryptChromiumWebData(dbPath string, key []byte, browser string) ([]DecryptedFinding, error) {
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
			num, err := chromiumDecryptValue(enc, key)
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
