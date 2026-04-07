package harvest

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// scanAppConfigs finds credentials in third-party application configs.
func (s *Scanner) scanAppConfigs() {
	homes := findHomeDirs(s.root)

	for _, home := range homes {
		s.scanFileZilla(home)
		s.scanDBeaver(home)
		s.scanPgAdmin(home)
		s.scanHeidiSQL(home)
		s.scanVPNConfigs(home)
		s.scanCertificateKeys(home)
	}

	// Walk for certs/VPN/keys across the whole tree
	s.walkForSecureFiles()
}

// ═══════ FileZilla (plaintext XML!) ═══════

type fileZillaServer struct {
	Host string `xml:"Host"`
	Port string `xml:"Port"`
	User string `xml:"User"`
	Pass string `xml:"Pass"`
	Name string `xml:"Name"`
}

type fileZillaServers struct {
	Servers []fileZillaServer `xml:"Server"`
}

func (s *Scanner) scanFileZilla(home string) {
	var paths []string
	if runtime.GOOS == "windows" {
		paths = append(paths,
			"AppData/Roaming/FileZilla/sitemanager.xml",
			"AppData/Roaming/FileZilla/recentservers.xml",
		)
	}
	// Linux/macOS variants
	paths = append(paths,
		".config/filezilla/sitemanager.xml",
		".config/filezilla/recentservers.xml",
		".filezilla/sitemanager.xml",
	)

	for _, p := range paths {
		fzPath := filepath.Join(home, p)
		data, err := os.ReadFile(fzPath)
		if err != nil {
			continue
		}

		var servers fileZillaServers
		if err := xml.Unmarshal(data, &servers); err != nil {
			// Try wrapping in root element
			wrapped := "<root>" + string(data) + "</root>"
			if err := xml.Unmarshal([]byte(wrapped), &servers); err != nil {
				fmt.Fprintf(os.Stderr, "[!] failed to parse FileZilla config %s: %v\n", fzPath, err)
				continue
			}
		}

		if len(servers.Servers) > 0 {
			for _, srv := range servers.Servers {
				if srv.User != "" {
					value := srv.User + "@" + srv.Host
					if srv.Pass != "" {
						value += " (password in XML!)"
					}
					s.addFinding(Finding{
						Category:   "FTP Client",
						Type:       "filezilla_creds",
						File:       fzPath,
						Key:        "FileZilla: " + srv.Host,
						Value:      value,
						Confidence: ConfHigh,
					})
				}
			}
		} else {
			// XML parse failed but file exists — still valuable
			s.addFinding(Finding{
				Category:   "FTP Client",
				Type:       "filezilla_config",
				File:       fzPath,
				Key:        "FileZilla Site Manager",
				Value:      "(saved FTP connections — passwords may be in base64)",
				Confidence: ConfHigh,
			})
		}
	}
}

// ═══════ DBeaver ═══════

func (s *Scanner) scanDBeaver(home string) {
	var paths []string
	if runtime.GOOS == "windows" {
		paths = append(paths,
			"AppData/Roaming/DBeaverData/workspace6/General/.dbeaver/credentials-config.json",
			"AppData/Roaming/DBeaverData/workspace6/General/.dbeaver/data-sources.json",
		)
	}
	// Linux/macOS
	paths = append(paths,
		".local/share/DBeaverData/workspace6/General/.dbeaver/credentials-config.json",
		".local/share/DBeaverData/workspace6/General/.dbeaver/data-sources.json",
	)

	for _, p := range paths {
		dbPath := filepath.Join(home, p)
		if _, err := os.Stat(dbPath); err == nil {
			ftype := "dbeaver_datasources"
			hint := "(database connection configs)"
			if strings.Contains(p, "credentials") {
				ftype = "dbeaver_credentials"
				hint = "(encrypted with PBE — decrypt with dbeaver-password-decryptor)"
			}
			s.addFinding(Finding{
				Category:   "DB Client",
				Type:       ftype,
				File:       dbPath,
				Key:        "DBeaver",
				Value:      hint,
				Confidence: ConfHigh,
			})
		}
	}
}

// ═══════ pgAdmin ═══════

func (s *Scanner) scanPgAdmin(home string) {
	var paths []string
	if runtime.GOOS == "windows" {
		paths = append(paths,
			"AppData/Roaming/pgAdmin/pgadmin4.db",
			"AppData/Roaming/pgAdmin4/pgadmin4.db",
		)
	}
	paths = append(paths, ".pgadmin/pgadmin4.db")

	for _, p := range paths {
		pgPath := filepath.Join(home, p)
		if _, err := os.Stat(pgPath); err == nil {
			s.addFinding(Finding{
				Category:   "DB Client",
				Type:       "pgadmin_db",
				File:       pgPath,
				Key:        "pgAdmin Database",
				Value:      "(SQLite — contains saved PostgreSQL connections and passwords)",
				Confidence: ConfHigh,
			})
		}
	}
}

// ═══════ HeidiSQL ═══════

func (s *Scanner) scanHeidiSQL(home string) {
	if runtime.GOOS != "windows" {
		return
	}

	// HeidiSQL stores creds in registry, but also has a portable settings file
	paths := []string{
		"AppData/Roaming/HeidiSQL/portable_settings.txt",
		"Documents/HeidiSQL/portable_settings.txt",
	}

	for _, p := range paths {
		hPath := filepath.Join(home, p)
		data, err := os.ReadFile(hPath)
		if err != nil {
			continue
		}

		// HeidiSQL settings contain host, user, password (encoded)
		content := string(data)
		if strings.Contains(content, "Servers\\") {
			s.addFinding(Finding{
				Category:   "DB Client",
				Type:       "heidisql_config",
				File:       hPath,
				Key:        "HeidiSQL Saved Connections",
				Value:      "(passwords stored with simple encoding — easily reversible)",
				Confidence: ConfHigh,
			})
		}

		// Also scan for password lines
		s.parseCredentialFile(hPath, "DB Client", "heidisql")
	}
}

// ═══════ VPN Configs ═══════

func (s *Scanner) scanVPNConfigs(home string) {
	vpnDirs := []string{
		"OpenVPN/config", "AppData/Roaming/OpenVPN Connect/profiles",
		".config/openvpn", "/etc/openvpn",
	}

	for _, dir := range vpnDirs {
		vpnDir := filepath.Join(home, dir)
		entries, err := os.ReadDir(vpnDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasSuffix(strings.ToLower(entry.Name()), ".ovpn") {
				s.parseOVPN(filepath.Join(vpnDir, entry.Name()))
			}
		}
	}
}

func (s *Scanner) parseOVPN(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	content := string(data)
	conf := ConfHigh

	// Check for embedded credentials
	hasAuth := strings.Contains(content, "auth-user-pass")
	hasKey := strings.Contains(content, "<key>") || strings.Contains(content, "<tls-auth>")
	hasCert := strings.Contains(content, "<cert>") || strings.Contains(content, "<ca>")
	hasInlinePass := strings.Contains(content, "<auth-user-pass>")

	value := "VPN config"
	if hasInlinePass {
		value = "(EMBEDDED USERNAME + PASSWORD in config!)"
	} else if hasKey {
		value = "(embedded private key)"
	} else if hasCert && hasAuth {
		value = "(certificate + external auth-user-pass file)"
		conf = ConfMedium
	}

	s.addFinding(Finding{
		Category:   "VPN",
		Type:       "ovpn_config",
		File:       path,
		Key:        "OpenVPN Config",
		Value:      value,
		Confidence: conf,
	})

	// Also extract remote server
	remoteRe := regexp.MustCompile(`(?m)^remote\s+(\S+)\s+(\d+)`)
	if match := remoteRe.FindStringSubmatch(content); len(match) >= 3 {
		s.addFinding(Finding{
			Category:   "VPN",
			Type:       "vpn_server",
			File:       path,
			Key:        "VPN Server",
			Value:      match[1] + ":" + match[2],
			Confidence: ConfMedium,
		})
	}
}

// ═══════ Certificate & Key Files ═══════

func (s *Scanner) scanCertificateKeys(home string) {
	certDirs := []string{
		".ssl", ".certs", "certs", "ssl",
		"AppData/Roaming/Microsoft/SystemCertificates",
	}

	for _, dir := range certDirs {
		certDir := filepath.Join(home, dir)
		if info, err := os.Stat(certDir); err == nil && info.IsDir() {
			filepath.Walk(certDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				s.classifyCertFile(path)
				return nil
			})
		}
	}
}

func (s *Scanner) classifyCertFile(path string) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".key", ".pem":
		// Check if it's a private key
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		content := string(data)
		if strings.Contains(content, "PRIVATE KEY") {
			encrypted := strings.Contains(content, "ENCRYPTED")
			value := "(UNENCRYPTED private key!)"
			conf := ConfHigh
			if encrypted {
				value = "(encrypted private key)"
				conf = ConfMedium
			}
			s.addFinding(Finding{
				Category:   "Certificate",
				Type:       "private_key_file",
				File:       path,
				Key:        "Private Key",
				Value:      value,
				Confidence: conf,
			})
		}
	case ".pfx", ".p12":
		s.addFinding(Finding{
			Category:   "Certificate",
			Type:       "pfx_file",
			File:       path,
			Key:        "PKCS#12 Certificate",
			Value:      "(may contain private key — extract with openssl pkcs12)",
			Confidence: ConfHigh,
		})
	case ".jks":
		s.addFinding(Finding{
			Category:   "Certificate",
			Type:       "java_keystore",
			File:       path,
			Key:        "Java Keystore",
			Value:      "(crack with keystorecracker or keytool)",
			Confidence: ConfHigh,
		})
	}
}

// walkForSecureFiles scans the whole tree for certs, VPN configs, and key files.
func (s *Scanner) walkForSecureFiles() {
	filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				if shouldSkipDir(info.Name()) {
					return filepath.SkipDir
				}
				depth := strings.Count(strings.TrimPrefix(path, s.root), string(os.PathSeparator))
				if depth > s.maxDepth {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if shouldSkipPath(path) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))

		// Certificate and key files
		switch ext {
		case ".pfx", ".p12", ".jks":
			s.classifyCertFile(path)
		case ".key", ".pem":
			if info.Size() < 100*1024 { // Only small files
				s.classifyCertFile(path)
			}
		case ".ovpn":
			s.parseOVPN(path)
		}

		return nil
	})
}
