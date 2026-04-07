package harvest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ScanMeta contains metadata about the scan.
type ScanMeta struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	User      string `json:"user"`
	ScanPath  string `json:"scan_path"`
	Timestamp string `json:"timestamp"`
}

// Scanner walks the filesystem looking for credentials.
type Scanner struct {
	root     string
	maxDepth int
	results  []Finding
	mu       sync.Mutex
	Meta     ScanMeta
}

// Confidence levels for findings
const (
	ConfHigh   = "HIGH"
	ConfMedium = "MEDIUM"
	ConfLow    = "LOW"
)

// Finding represents a discovered credential or secret.
type Finding struct {
	Category   string `json:"category"`
	Type       string `json:"type"`
	File       string `json:"file"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	Line       int    `json:"line,omitempty"`
	Confidence string `json:"confidence"`
}

func NewScanner(root string, maxDepth int) *Scanner {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}

	return &Scanner{
		root:     root,
		maxDepth: maxDepth,
		Meta: ScanMeta{
			Hostname:  hostname,
			OS:        runtime.GOOS + "/" + runtime.GOARCH,
			User:      username,
			ScanPath:  root,
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		},
	}
}

// AddExcludes adds user-specified paths to skip during scanning.
func (s *Scanner) AddExcludes(paths []string) {
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" {
			skipPaths = append(skipPaths, p)
		}
	}
}

func (s *Scanner) addFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, f)
}

// Run executes all credential scanning modules.
func (s *Scanner) Run() []Finding {
	fmt.Println("  \033[36m[*]\033[0m Scanning:", s.root)
	fmt.Println()

	var wg sync.WaitGroup

	// Phase 1: Find known credential files
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanKnownFiles()
	}()

	// Phase 2: Walk filesystem for pattern matches in file contents
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanFileContents()
	}()

	// Phase 3: Check history files
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanHistoryFiles()
	}()

	// Phase 4: Check SSH keys
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanSSHKeys()
	}()

	// Phase 5: Browser passwords and history
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanBrowsers()
	}()

	// Phase 6: Password manager vaults
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanPasswordManagers()
	}()

	// Phase 7: Windows-specific (Credential Manager, Wi-Fi, RDP, DPAPI)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanWindows()
	}()

	// Phase 8: Environment variables
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanEnvironment()
	}()

	// Phase 9: App tokens (Slack, Discord, Teams, Telegram)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanAppTokens()
	}()

	// Phase 10: App configs (FileZilla, DBeaver, pgAdmin, HeidiSQL, VPN, Certs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanAppConfigs()
	}()

	wg.Wait()

	// Deduplicate (hold lock since goroutines may have just finished writing)
	s.mu.Lock()
	s.results = deduplicate(s.results)
	results := s.results
	s.mu.Unlock()

	fmt.Printf("  \033[32m[+]\033[0m Found \033[1m%d\033[0m credentials\n\n", len(results))
	return results
}

// scanKnownFiles checks for files that are known to contain credentials.
func (s *Scanner) scanKnownFiles() {
	knownFiles := map[string]string{
		".env":                "Web App",
		".env.local":          "Web App",
		".env.development":    "Web App",
		".env.production":     "Web App",
		".env.test":           "Web App",
		".env.example":        "Web App",
		".env.defaults":       "Web App",
		".pgpass":             "Database",
		".my.cnf":             "Database",
		".netrc":              "Auth",
		".htpasswd":           "Web App",
		"wp-config.php":       "Web App",
		"config.php":          "Web App",
		"database.yml":        "Web App",
		"settings.py":         "Web App",
		"web.config":          "Web App",
		"appsettings.json":    "Web App",
		"credentials":         "Cloud",
		"credentials.xml":     "CI/CD",
		"shadow":              "System",
		"docker-compose.yml":  "Container",
		"docker-compose.yaml": "Container",
		".docker/config.json": "Container",
		"kubeconfig":          "Cloud",
		"terraform.tfvars":    "IaC",
		"secrets.yaml":        "Cloud",
		"secrets.yml":         "Cloud",
		"vault.json":          "Cloud",
		"config.yml":          "Config",
		"config.yaml":         "Config",
	}

	filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip common noisy directories
		if info.IsDir() {
			name := info.Name()
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			// Check depth
			depth := strings.Count(strings.TrimPrefix(path, s.root), string(os.PathSeparator))
			if depth > s.maxDepth {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a known credential file
		base := filepath.Base(path)
		if cat, ok := knownFiles[base]; ok {
			s.parseCredentialFile(path, cat, base)
		}

		// Check for .git/config
		if base == "config" && strings.Contains(path, ".git/") {
			s.parseGitConfig(path)
		}

		// Check for tfstate files (Terraform state with secrets)
		if strings.HasSuffix(base, ".tfstate") {
			s.parseTerraformState(path)
		}

		// Check for AWS credential files
		if strings.Contains(path, ".aws/credentials") || strings.Contains(path, ".aws/config") {
			s.parseCredentialFile(path, "Cloud", "AWS Config")
		}

		// Check for Azure config
		if strings.Contains(path, ".azure/") && (base == "accessTokens.json" || base == "azureProfile.json") {
			s.parseCredentialFile(path, "Cloud", "Azure Config")
		}

		// Check for GCP config
		if strings.Contains(path, "gcloud/") && (base == "credentials.db" || base == "application_default_credentials.json") {
			s.parseCredentialFile(path, "Cloud", "GCP Config")
		}

		return nil
	})
}

func shouldSkipDir(name string) bool {
	skip := []string{"proc", "sys", "dev", "run", "snap", "boot",
		"lib", "lib64", "usr", "bin", "sbin", "node_modules",
		"__pycache__", ".cache", "vendor"}
	for _, s := range skip {
		if name == s {
			return true
		}
	}
	return false
}

func deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding
	for _, f := range findings {
		key := f.File + "|" + f.Key + "|" + f.Value
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
}
