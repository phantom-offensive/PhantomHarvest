package decrypt

import "errors"

// ErrNotCompiledIn is returned by stub functions when the binary
// was built without the `decrypt` build tag.
var ErrNotCompiledIn = errors.New("decryption support not compiled in (rebuild with -tags decrypt)")

// DecryptedFinding mirrors harvest.Finding but lives in the decrypt package
// so the decrypt package does not depend on harvest (avoiding import cycles).
// The harvest package converts these into harvest.Finding values.
type DecryptedFinding struct {
	Category   string
	Type       string
	File       string
	Key        string
	Value      string
	Confidence string
}

// Confidence levels (mirrored from harvest to keep packages decoupled).
const (
	ConfHigh   = "HIGH"
	ConfMedium = "MEDIUM"
	ConfLow    = "LOW"
)

// Enabled reports whether the binary was built with decryption support.
// The default (no build tag) implementation returns false; the `decrypt`
// build tag overrides this in decrypt_full.go.
func Enabled() bool { return enabled }

// chromiumKeys carries every master key we may need to decrypt a Chromium
// profile. Different values use different keys based on their prefix:
//
//	"v10"/"v11"  → V10 (legacy DPAPI-wrapped AES key on Windows, or the
//	               keyring/keychain/peanuts-derived key on Linux/macOS).
//	"v20"        → V20 (Chrome v127+ app-bound encryption key, obtained on
//	               Windows by calling the browser's IElevator COM service;
//	               always nil on Linux/macOS).
//
// The Windows-specific variant of getChromiumMasterKey populates both
// when the local Chrome install has enabled app-bound encryption. If
// V20 is nil, v20-prefixed entries will simply be skipped.
type chromiumKeys struct {
	V10 []byte
	V20 []byte
}
