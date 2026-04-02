package harvest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Regex patterns for credential detection in file contents
var credPatterns = []struct {
	name    string
	pattern *regexp.Regexp
	cat     string
}{
	// Passwords and secrets
	{"password", regexp.MustCompile(`(?i)(password|passwd|pwd|[a-z_]*pass)\s*[=:]\s*['"]?([^\s'"#;,}{]+)`), "Auth"},
	{"secret", regexp.MustCompile(`(?i)(secret|secret_key|app_secret)\s*[=:]\s*['"]?([^\s'"#;,}{]+)`), "Auth"},
	{"token", regexp.MustCompile(`(?i)(token|api_token|auth_token|access_token|bearer)\s*[=:]\s*['"]?([^\s'"#;,}{]+)`), "Auth"},
	{"api_key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([^\s'"#;,}{]+)`), "Auth"},

	// AWS
	{"aws_access_key", regexp.MustCompile(`(AKIA[0-9A-Z]{16})`), "Cloud"},
	{"aws_secret_key", regexp.MustCompile(`(?i)(aws_secret_access_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})`), "Cloud"},

	// GitHub/GitLab tokens
	{"github_token", regexp.MustCompile(`(ghp_[A-Za-z0-9]{36,})`), "API"},
	{"github_oauth", regexp.MustCompile(`(gho_[A-Za-z0-9]{36,})`), "API"},
	{"gitlab_token", regexp.MustCompile(`(glpat-[A-Za-z0-9\-]{20,})`), "API"},

	// Stripe
	{"stripe_live", regexp.MustCompile(`(sk_live_[A-Za-z0-9]{24,})`), "API"},
	{"stripe_test", regexp.MustCompile(`(sk_test_[A-Za-z0-9]{24,})`), "API"},

	// Slack
	{"slack_token", regexp.MustCompile(`(xox[baprs]-[A-Za-z0-9\-]{10,})`), "API"},

	// Connection strings
	{"mysql_conn", regexp.MustCompile(`mysql://([^@]+)@`), "Database"},
	{"postgres_conn", regexp.MustCompile(`postgres(?:ql)?://([^@]+)@`), "Database"},
	{"mongodb_conn", regexp.MustCompile(`mongodb(?:\+srv)?://([^@]+)@`), "Database"},
	{"redis_conn", regexp.MustCompile(`redis://(:?[^@]+)@`), "Database"},

	// Private keys
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "SSH"},

	// JWT
	{"jwt", regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`), "Auth"},

	// Generic DB credentials
	{"db_password", regexp.MustCompile(`(?i)(db_pass|db_password|database_password|mysql_password|pg_password|pgpassword|mongo_password)\s*[=:]\s*['"]?([^\s'"#;,}{]+)`), "Database"},

	// Mail credentials
	{"mail_password", regexp.MustCompile(`(?i)(mail_pass|mail_password|smtp_pass|smtp_password|email_password)\s*[=:]\s*['"]?([^\s'"#;,}{]+)`), "Mail"},

	// Generic user/key assignments (catch ADMIN_USER=, DB_USER=, etc.)
	{"username", regexp.MustCompile(`(?i)([a-z_]*user|[a-z_]*username|[a-z_]*login)\s*[=:]\s*['"]?([^\s'"#;,}{]+)`), "Auth"},

	// Hashes (useful for offline cracking)
	{"hash_bcrypt", regexp.MustCompile(`(\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53})`), "Hash"},
	{"hash_sha512", regexp.MustCompile(`(\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{86})`), "Hash"},
	{"hash_md5crypt", regexp.MustCompile(`(\$1\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{22})`), "Hash"},
	{"hash_ntlm", regexp.MustCompile(`(?i)([a-f0-9]{32}:[a-f0-9]{32})`), "Hash"},
}

// File extensions to scan for credential patterns
var scanExtensions = map[string]bool{
	".env": true, ".yml": true, ".yaml": true, ".json": true,
	".xml": true, ".conf": true, ".cfg": true, ".ini": true,
	".properties": true, ".toml": true, ".php": true, ".py": true,
	".rb": true, ".js": true, ".ts": true, ".sh": true, ".bash": true,
	".tf": true, ".tfvars": true, ".config": true, ".txt": true,
	".bak": true, ".old": true, ".sql": true,
}

// Directories to skip during file content scanning
var skipPaths = []string{
	// Linux
	"/var/log", "/var/cache", "/tmp/pip", "/var/lib/dpkg",
	"/var/lib/apt", "/etc/alternatives",
	// Windows noise
	"TikTok LIVE Studio/effect", "TikTok LIVE Studio/fileCache",
	"TikTok LIVE Studio/gecko_cache",
	"/Extensions/", "/extensions/",
	"AzureFunctionsTools/Releases",
	"Microsoft/Blend", "Microsoft/Edge/User Data/Edge",
	"Kingsoft/WPS Office", "assembly_tokens",
	"node_modules", "__pycache__", ".gradle",
	"Android/Sdk", "Microsoft SDKs",
}

func shouldSkipPath(path string) bool {
	for _, p := range skipPaths {
		if strings.HasPrefix(path, p) || strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// parseCredentialFile reads a file and extracts credentials using regex patterns.
func (s *Scanner) parseCredentialFile(path, category, fileType string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	content := string(data)
	if len(content) > 512*1024 { // Skip files > 512KB
		return
	}

	lines := strings.Split(content, "\n")
	found := false

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		for _, p := range credPatterns {
			matches := p.pattern.FindStringSubmatch(line)
			if len(matches) >= 2 {
				value := matches[len(matches)-1]
				key := matches[1]
				if len(matches) == 2 {
					key = p.name
					value = matches[1]
				}

				// Filter out common false positives
				if isNoisy(value) {
					continue
				}

				s.addFinding(Finding{
					Category:   category,
					Type:       p.name,
					File:       path,
					Key:        key,
					Value:      truncate(value, 80),
					Line:       lineNum + 1,
					Confidence: classifyConfidence(p.name, key, value, path),
				})
				found = true
			}
		}
	}

	// If no regex matched but it's a known cred file, note it
	base := filepath.Base(path)
	if !found && isKnownCredFile(base) {
		s.addFinding(Finding{
			Category:   category,
			Type:       fileType,
			File:       path,
			Key:        "file_found",
			Value:      "(credential file detected — review manually)",
			Confidence: ConfMedium,
		})
	}
}

// parseGitConfig extracts credentials from git remote URLs.
func (s *Scanner) parseGitConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Match URLs with embedded credentials: https://user:pass@host
	re := regexp.MustCompile(`url\s*=\s*https?://([^:]+):([^@]+)@`)
	for _, match := range re.FindAllStringSubmatch(string(data), -1) {
		if len(match) >= 3 {
			s.addFinding(Finding{
				Category:   "Git",
				Type:       "git_credential",
				File:       path,
				Key:        match[1],
				Value:      match[2],
				Confidence: ConfHigh,
			})
		}
	}
}

// parseTerraformState extracts secrets from Terraform state files.
func (s *Scanner) parseTerraformState(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	if len(data) > 5*1024*1024 { // Skip > 5MB
		return
	}

	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}

	s.addFinding(Finding{
		Category:   "IaC",
		Type:       "terraform_state",
		File:       path,
		Key:        "tfstate",
		Value:      "(Terraform state file — likely contains secrets)",
		Confidence: ConfHigh,
	})

	// Also scan the raw content for credential patterns
	s.parseCredentialFile(path, "IaC", "terraform")
}

// scanFileContents walks the filesystem and scans file contents for credential patterns.
func (s *Scanner) scanFileContents() {
	filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			name := info.Name()
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			depth := strings.Count(strings.TrimPrefix(path, s.root), string(os.PathSeparator))
			if depth > s.maxDepth {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip noisy system paths
		if shouldSkipPath(path) {
			return nil
		}

		// Only scan files with relevant extensions
		ext := strings.ToLower(filepath.Base(path))
		if idx := strings.LastIndex(ext, "."); idx >= 0 {
			ext = ext[idx:]
		}

		if !scanExtensions[ext] {
			return nil
		}

		// Skip large files
		if info.Size() > 512*1024 {
			return nil
		}

		// Skip already-found known files (they were parsed in scanKnownFiles)
		// Only scan if not a top-level known file
		s.parseCredentialFile(path, "File Scan", ext)

		return nil
	})
}

// scanHistoryFiles checks shell history for commands containing credentials.
func (s *Scanner) scanHistoryFiles() {
	homes := findHomeDirs(s.root)

	historyFiles := []string{
		".bash_history",
		".zsh_history",
		".python_history",
		".mysql_history",
		".psql_history",
		".node_repl_history",
		".rediscli_history",
	}

	// Password patterns commonly found in history
	historyPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)sshpass\s+-p\s+['"]?([^\s'"]+)`),
		regexp.MustCompile(`(?i)mysql\s+.*-p([^\s]+)`),
		regexp.MustCompile(`(?i)psql\s+.*password[= ](['"]?[^\s'"]+)`),
		regexp.MustCompile(`(?i)PGPASSWORD[= ]['"]?([^\s'"]+)`),
		regexp.MustCompile(`(?i)curl\s+.*[-]u\s+([^\s]+:[^\s]+)`),
		regexp.MustCompile(`(?i)curl\s+.*Authorization:\s+Bearer\s+([^\s'"]+)`),
		regexp.MustCompile(`(?i)wget\s+.*--password[= ]['"]?([^\s'"]+)`),
		regexp.MustCompile(`(?i)echo\s+['"]?([^\s'"]+)['"]?\s*\|\s*su`),
		regexp.MustCompile(`(?i)net\s+use\s+.*\/user:([^\s]+)\s+([^\s]+)`),
		regexp.MustCompile(`(?i)mount\s+.*username=([^,]+).*password=([^\s,]+)`),
		regexp.MustCompile(`(?i)ftp\s+.*-p\s+([^\s]+)`),
		regexp.MustCompile(`(?i)ssh\s+.*@`),
	}

	for _, home := range homes {
		for _, histFile := range historyFiles {
			path := home + "/" + histFile
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				for _, pattern := range historyPatterns {
					matches := pattern.FindStringSubmatch(line)
					if len(matches) >= 2 {
						s.addFinding(Finding{
							Category:   "History",
							Type:       "shell_history",
							File:       path,
							Key:        truncate(line, 100),
							Value:      matches[1],
							Line:       lineNum,
							Confidence: ConfHigh,
						})
					}
				}
			}
		}
	}
}

// scanSSHKeys finds private keys and authorized_keys files.
func (s *Scanner) scanSSHKeys() {
	homes := findHomeDirs(s.root)

	keyFiles := []string{
		".ssh/id_rsa",
		".ssh/id_ecdsa",
		".ssh/id_ed25519",
		".ssh/id_dsa",
		".ssh/authorized_keys",
		".ssh/known_hosts",
		".ssh/config",
	}

	for _, home := range homes {
		for _, keyFile := range keyFiles {
			path := home + "/" + keyFile
			if _, err := os.Stat(path); err == nil {
				ftype := "ssh_key"
				if strings.Contains(keyFile, "authorized") {
					ftype = "authorized_keys"
				} else if strings.Contains(keyFile, "config") {
					ftype = "ssh_config"
				} else if strings.Contains(keyFile, "known_hosts") {
					ftype = "known_hosts"
				}

				// Check if private key is encrypted
				value := "(exists)"
				if strings.Contains(keyFile, "id_") && !strings.Contains(keyFile, ".pub") {
					data, err := os.ReadFile(path)
					if err == nil {
						if strings.Contains(string(data), "ENCRYPTED") {
							value = "(encrypted private key)"
						} else {
							value = "(UNENCRYPTED private key!)"
						}
					}
				}

				conf := ConfMedium
				if strings.Contains(value, "UNENCRYPTED") {
					conf = ConfHigh
				} else if ftype == "known_hosts" {
					conf = ConfLow
				}
				s.addFinding(Finding{
					Category:   "SSH",
					Type:       ftype,
					File:       path,
					Key:        keyFile,
					Value:      value,
					Confidence: conf,
				})
			}
		}
	}
}

// findHomeDirs returns all home directories (and /root).
func findHomeDirs(root string) []string {
	var homes []string

	// Check /root
	if _, err := os.Stat(root + "/root"); err == nil {
		homes = append(homes, root+"/root")
	}
	if root == "/" {
		if _, err := os.Stat("/root"); err == nil {
			homes = append(homes, "/root")
		}
	}

	// Check /home/*
	homePath := root + "/home"
	if root == "/" {
		homePath = "/home"
	}

	entries, err := os.ReadDir(homePath)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, homePath+"/"+e.Name())
			}
		}
	}

	return homes
}

func isNoisy(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return true
	}
	noisy := []string{
		"none", "null", "true", "false", "yes", "no",
		"password", "changeme", "xxx", "***", "your_",
		"example", "placeholder", "${", "{{", "<",
		"todo", "fixme", "files", "compat", "request.",
		"os.environ", "os.getenv", "process.env",
		"config.", "settings.", "amd64", "i386", "all",
	}
	for _, n := range noisy {
		if v == n || strings.HasPrefix(v, n) {
			return true
		}
	}
	if len(v) < 3 {
		return true
	}
	return false
}

func isKnownCredFile(name string) bool {
	known := []string{".env", ".pgpass", ".my.cnf", ".netrc", ".htpasswd",
		"wp-config.php", "credentials", "credentials.xml", "shadow",
		"kubeconfig", "secrets.yaml", "secrets.yml"}
	for _, k := range known {
		if name == k {
			return true
		}
	}
	return false
}

// classifyConfidence assigns HIGH/MEDIUM/LOW based on context.
func classifyConfidence(patternName, key, value, path string) string {
	pathLower := strings.ToLower(path)
	keyLower := strings.ToLower(key)
	valueLower := strings.ToLower(value)

	// HIGH: Known credential files with actual values
	highPaths := []string{".env", ".pgpass", ".my.cnf", ".netrc", ".htpasswd",
		".git/config", "credentials", ".aws/", "config.yml", "config.yaml",
		".bash_history", ".zsh_history", "shadow", "wp-config.php"}
	for _, hp := range highPaths {
		if strings.Contains(pathLower, hp) {
			return ConfHigh
		}
	}

	// HIGH: Specific high-value patterns
	highPatterns := []string{"aws_access_key", "aws_secret_key", "github_token",
		"gitlab_token", "stripe_live", "slack_token", "private_key",
		"postgres_conn", "mysql_conn", "mongodb_conn", "db_password",
		"mail_password", "git_credential", "shell_history"}
	for _, hp := range highPatterns {
		if patternName == hp {
			return ConfHigh
		}
	}

	// HIGH: Value looks like a real credential (not code)
	if strings.Contains(keyLower, "pass") && len(value) >= 6 &&
		!strings.Contains(valueLower, "(") && !strings.Contains(valueLower, "=") &&
		!strings.Contains(valueLower, "this.") && !strings.Contains(valueLower, "function") {
		return ConfHigh
	}

	// MEDIUM: API keys, tokens, secrets in config-like files
	mediumPatterns := []string{"api_key", "secret", "token", "password", "jwt"}
	for _, mp := range mediumPatterns {
		if patternName == mp {
			return ConfMedium
		}
	}

	// LOW: Everything else (code references, variable names)
	return ConfLow
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
