package harvest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// scanPasswordManagers finds local password manager vault files.
func (s *Scanner) scanPasswordManagers() {
	homes := findHomeDirs(s.root)

	for _, home := range homes {
		// KeePass databases (.kdbx, .kdb)
		s.findFiles(home, []string{".kdbx", ".kdb"}, "Password Manager", "keepass_vault",
			"KeePass Vault", "(crack master password with keepass2john + hashcat)", ConfHigh)

		// 1Password local vaults
		onePassPaths := []string{
			".1password", ".config/1Password",
			"AppData/Local/1Password", "AppData/Roaming/1Password",
			"Library/Group Containers/2BUA8C4S2C.com.1password",
		}
		for _, p := range onePassPaths {
			vaultDir := filepath.Join(home, p)
			if info, err := os.Stat(vaultDir); err == nil && info.IsDir() {
				s.addFinding(Finding{
					Category:   "Password Manager",
					Type:       "1password_vault",
					File:       vaultDir,
					Key:        "1Password Local Vault",
					Value:      "(local vault directory detected)",
					Confidence: ConfHigh,
				})
			}
		}

		// LastPass local cache
		lastPassPaths := []string{
			"AppData/Local/LastPass",
			"AppData/Roaming/LastPass",
			".lastpass",
			".config/lastpass",
		}
		for _, p := range lastPassPaths {
			lpDir := filepath.Join(home, p)
			if info, err := os.Stat(lpDir); err == nil && info.IsDir() {
				s.addFinding(Finding{
					Category:   "Password Manager",
					Type:       "lastpass_cache",
					File:       lpDir,
					Key:        "LastPass Local Cache",
					Value:      "(may contain encrypted vault data)",
					Confidence: ConfHigh,
				})
			}
		}

		// Bitwarden local data
		bitwardenPaths := []string{
			"AppData/Roaming/Bitwarden",
			"AppData/Roaming/Bitwarden CLI",
			".config/Bitwarden",
			".config/Bitwarden CLI",
		}
		for _, p := range bitwardenPaths {
			bwDir := filepath.Join(home, p)
			if info, err := os.Stat(bwDir); err == nil && info.IsDir() {
				s.addFinding(Finding{
					Category:   "Password Manager",
					Type:       "bitwarden_data",
					File:       bwDir,
					Key:        "Bitwarden Local Data",
					Value:      "(may contain encrypted vault)",
					Confidence: ConfMedium,
				})
			}
		}

		// NordPass
		if runtime.GOOS == "windows" {
			nordDir := filepath.Join(home, "AppData/Roaming/NordPass")
			if info, err := os.Stat(nordDir); err == nil && info.IsDir() {
				s.addFinding(Finding{
					Category:   "Password Manager",
					Type:       "nordpass_data",
					File:       nordDir,
					Key:        "NordPass Local Data",
					Value:      "(local NordPass data directory)",
					Confidence: ConfMedium,
				})
			}
		}

		// pass (Unix password manager) - stores GPG encrypted files
		passDir := filepath.Join(home, ".password-store")
		if info, err := os.Stat(passDir); err == nil && info.IsDir() {
			s.addFinding(Finding{
				Category:   "Password Manager",
				Type:       "pass_store",
				File:       passDir,
				Key:        "Unix pass Store",
				Value:      "(GPG-encrypted passwords — need private key)",
				Confidence: ConfHigh,
			})
		}

		// GPG private keys
		gpgDir := filepath.Join(home, ".gnupg")
		if info, err := os.Stat(gpgDir); err == nil && info.IsDir() {
			s.addFinding(Finding{
				Category:   "Crypto",
				Type:       "gpg_keyring",
				File:       gpgDir,
				Key:        "GPG Keyring",
				Value:      "(private keys for decryption)",
				Confidence: ConfHigh,
			})
		}
	}

	// Also walk the filesystem for .kdbx files outside home dirs
	filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".kdbx" || ext == ".kdb" {
			s.addFinding(Finding{
				Category:   "Password Manager",
				Type:       "keepass_vault",
				File:       path,
				Key:        "KeePass Vault",
				Value:      "(crack with keepass2john + hashcat)",
				Confidence: ConfHigh,
			})
		}

		return nil
	})
}

// findFiles searches for files with specific extensions under a directory.
func (s *Scanner) findFiles(root string, extensions []string, category, ftype, key, value string, confidence string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		for _, e := range extensions {
			if ext == e {
				s.addFinding(Finding{
					Category:   category,
					Type:       ftype,
					File:       path,
					Key:        key,
					Value:      value,
					Confidence: confidence,
				})
			}
		}
		return nil
	})
}
