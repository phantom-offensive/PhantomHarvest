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
