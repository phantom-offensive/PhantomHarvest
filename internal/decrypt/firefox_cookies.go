//go:build decrypt

package decrypt

import (
	"fmt"
	"path/filepath"
)

// DumpFirefoxCookies queries a Firefox profile's cookies.sqlite and returns
// one DecryptedFinding per cookie. Firefox cookies are stored in plaintext
// (unencrypted SQLite), so no NSS/DPAPI decryption is required.
func DumpFirefoxCookies(profileDir string) ([]DecryptedFinding, error) {
	dbPath := filepath.Join(profileDir, "cookies.sqlite")
	db, cleanup, err := openSQLiteCopy(dbPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	rows, err := db.Query("SELECT host, path, isSecure, name, expiry, value FROM moz_cookies;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DecryptedFinding
	for rows.Next() {
		var host, path, isSecure, name, expiry, value string
		if err := rows.Scan(&host, &path, &isSecure, &name, &expiry, &value); err != nil {
			continue
		}
		out = append(out, DecryptedFinding{
			Category:   "Browser",
			Type:       "firefox_cookie",
			File:       dbPath,
			Key:        fmt.Sprintf("%s | %s | %s | secure=%s", host, path, name, isSecure),
			Value:      value,
			Confidence: ConfMedium,
		})
	}
	return out, rows.Err()
}

// DumpFirefoxBookmarks queries a Firefox profile's places.sqlite and returns
// one DecryptedFinding per bookmark (title + URL).
func DumpFirefoxBookmarks(profileDir string) ([]DecryptedFinding, error) {
	dbPath := filepath.Join(profileDir, "places.sqlite")
	db, cleanup, err := openSQLiteCopy(dbPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	rows, err := db.Query("SELECT moz_bookmarks.title, moz_places.url FROM moz_bookmarks INNER JOIN moz_places ON moz_bookmarks.fk = moz_places.id;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DecryptedFinding
	for rows.Next() {
		var title, url string
		if err := rows.Scan(&title, &url); err != nil {
			continue
		}
		if url == "" {
			continue
		}
		out = append(out, DecryptedFinding{
			Category:   "Browser",
			Type:       "firefox_bookmark",
			File:       dbPath,
			Key:        title,
			Value:      url,
			Confidence: ConfLow,
		})
	}
	return out, rows.Err()
}
