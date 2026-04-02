package harvest

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// scanWindows runs Windows-specific credential discovery.
func (s *Scanner) scanWindows() {
	if runtime.GOOS != "windows" {
		// On Linux, check if we're scanning a mounted Windows filesystem
		if !strings.Contains(s.root, "/mnt/c") && !strings.Contains(s.root, "Windows") {
			return
		}
	}

	homes := findHomeDirs(s.root)

	// Windows Credential Manager (only works on Windows)
	if runtime.GOOS == "windows" {
		s.scanCredentialManager()
		s.scanWiFiPasswords()
	}

	// RDP connection files (works on any OS scanning Windows FS)
	for _, home := range homes {
		s.scanRDPFiles(home)
		s.scanDPAPIData(home)
		s.scanWindowsVault(home)
	}

	// Also walk for .rdp files elsewhere
	filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))

		// RDP files
		if ext == ".rdp" {
			s.parseRDPFile(path)
		}

		// Unattend.xml / sysprep files (Windows deployment creds)
		base := strings.ToLower(filepath.Base(path))
		if base == "unattend.xml" || base == "sysprep.xml" || base == "autounattend.xml" {
			s.addFinding(Finding{
				Category:   "Windows",
				Type:       "unattend_xml",
				File:       path,
				Key:        "Windows Unattend/Sysprep",
				Value:      "(may contain admin password in base64)",
				Confidence: ConfHigh,
			})
			s.parseCredentialFile(path, "Windows", "unattend_xml")
		}

		// SAM/SYSTEM/SECURITY hive backups
		if base == "sam" || base == "system" || base == "security" {
			if strings.Contains(strings.ToLower(path), "repair") ||
				strings.Contains(strings.ToLower(path), "regback") ||
				strings.Contains(strings.ToLower(path), "backup") {
				s.addFinding(Finding{
					Category:   "Windows",
					Type:       "registry_hive",
					File:       path,
					Key:        "Registry Hive Backup (" + base + ")",
					Value:      "(extract hashes with secretsdump.py or mimikatz)",
					Confidence: ConfHigh,
				})
			}
		}

		return nil
	})
}

// scanCredentialManager enumerates Windows Credential Manager.
func (s *Scanner) scanCredentialManager() {
	out, err := exec.Command("cmdkey", "/list").Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	var currentTarget string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Target:") {
			currentTarget = strings.TrimPrefix(line, "Target:")
			currentTarget = strings.TrimSpace(currentTarget)
		}
		if strings.HasPrefix(line, "User:") && currentTarget != "" {
			user := strings.TrimPrefix(line, "User:")
			user = strings.TrimSpace(user)
			s.addFinding(Finding{
				Category:   "Windows",
				Type:       "credential_manager",
				File:       "Windows Credential Manager",
				Key:        currentTarget,
				Value:      "User: " + user,
				Confidence: ConfHigh,
			})
		}
	}
}

// scanWiFiPasswords extracts saved Wi-Fi passwords.
func (s *Scanner) scanWiFiPasswords() {
	// Get list of profiles
	out, err := exec.Command("netsh", "wlan", "show", "profiles").Output()
	if err != nil {
		return
	}

	profileRe := regexp.MustCompile(`(?i)All User Profile\s*:\s*(.+)`)
	matches := profileRe.FindAllStringSubmatch(string(out), -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		profileName := strings.TrimSpace(match[1])

		// Get password for each profile
		passOut, err := exec.Command("netsh", "wlan", "show", "profile",
			"name="+profileName, "key=clear").Output()
		if err != nil {
			continue
		}

		keyRe := regexp.MustCompile(`(?i)Key Content\s*:\s*(.+)`)
		keyMatch := keyRe.FindStringSubmatch(string(passOut))
		if len(keyMatch) >= 2 {
			password := strings.TrimSpace(keyMatch[1])
			s.addFinding(Finding{
				Category:   "WiFi",
				Type:       "wifi_password",
				File:       "netsh wlan",
				Key:        profileName,
				Value:      password,
				Confidence: ConfHigh,
			})
		}
	}
}

// scanRDPFiles searches for .rdp files in common locations.
func (s *Scanner) scanRDPFiles(home string) {
	rdpPaths := []string{
		"Documents", "Desktop", "Downloads",
		"AppData/Local/Microsoft/Terminal Server Client",
	}

	for _, relPath := range rdpPaths {
		dirPath := filepath.Join(home, relPath)
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(path), ".rdp") {
				s.parseRDPFile(path)
			}
			return nil
		})
	}
}

// parseRDPFile extracts credentials from .rdp files.
func (s *Scanner) parseRDPFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	var server, username, password string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		key := strings.ToLower(parts[0])
		value := strings.TrimSpace(parts[2])

		switch key {
		case "full address":
			server = value
		case "username":
			username = value
		case "password 51":
			password = "(DPAPI encrypted — decrypt with mimikatz)"
		}
	}

	if server != "" || username != "" {
		val := server
		if username != "" {
			val = username + "@" + server
		}
		if password != "" {
			val += " " + password
		}

		s.addFinding(Finding{
			Category:   "RDP",
			Type:       "rdp_file",
			File:       path,
			Key:        "RDP Connection",
			Value:      truncate(val, 100),
			Confidence: ConfHigh,
		})
	}
}

// scanDPAPIData checks for DPAPI master keys and protected data.
func (s *Scanner) scanDPAPIData(home string) {
	// DPAPI master keys
	dpapiPaths := []string{
		"AppData/Roaming/Microsoft/Protect",
		"AppData/Local/Microsoft/Protect",
	}

	for _, relPath := range dpapiPaths {
		dpapiDir := filepath.Join(home, relPath)
		if info, err := os.Stat(dpapiDir); err == nil && info.IsDir() {
			// Count master keys
			count := 0
			filepath.Walk(dpapiDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					count++
				}
				return nil
			})

			if count > 0 {
				s.addFinding(Finding{
					Category:   "DPAPI",
					Type:       "dpapi_masterkeys",
					File:       dpapiDir,
					Key:        "DPAPI Master Keys",
					Value:      "(decrypt with domain backup key or user password)",
					Confidence: ConfHigh,
				})
			}
		}
	}

	// DPAPI credentials
	credPaths := []string{
		"AppData/Roaming/Microsoft/Credentials",
		"AppData/Local/Microsoft/Credentials",
	}

	for _, relPath := range credPaths {
		credDir := filepath.Join(home, relPath)
		if info, err := os.Stat(credDir); err == nil && info.IsDir() {
			count := 0
			filepath.Walk(credDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					count++
				}
				return nil
			})

			if count > 0 {
				s.addFinding(Finding{
					Category:   "DPAPI",
					Type:       "dpapi_credentials",
					File:       credDir,
					Key:        "DPAPI Protected Credentials",
					Value:      "(extract with mimikatz dpapi::cred or SharpDPAPI)",
					Confidence: ConfHigh,
				})
			}
		}
	}
}

// scanWindowsVault checks for Windows Vault files.
func (s *Scanner) scanWindowsVault(home string) {
	vaultPaths := []string{
		"AppData/Local/Microsoft/Vault",
		"AppData/Roaming/Microsoft/Vault",
	}

	for _, relPath := range vaultPaths {
		vaultDir := filepath.Join(home, relPath)
		if info, err := os.Stat(vaultDir); err == nil && info.IsDir() {
			s.addFinding(Finding{
				Category:   "Windows",
				Type:       "windows_vault",
				File:       vaultDir,
				Key:        "Windows Vault",
				Value:      "(may contain web credentials — extract with vaultcmd or mimikatz)",
				Confidence: ConfMedium,
			})
		}
	}
}
