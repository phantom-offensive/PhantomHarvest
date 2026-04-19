//go:build !decrypt

package decrypt

const enabled = false

// DecryptChromiumProfile is a stub when the decrypt tag is not set.
func DecryptChromiumProfile(profileDir, browserName string) ([]DecryptedFinding, error) {
	return nil, ErrNotCompiledIn
}

// DecryptFirefoxProfile is a stub when the decrypt tag is not set.
func DecryptFirefoxProfile(profileDir, browserName string) ([]DecryptedFinding, error) {
	return nil, ErrNotCompiledIn
}

// EnableAppBoundV20 is a no-op in the stub build.
func EnableAppBoundV20() {}

// SetExternalChromiumKey is a no-op in the stub build.
func SetExternalChromiumKey(_ string) error { return ErrNotCompiledIn }

// SetDPAPIMasterKey is a no-op in the stub build.
func SetDPAPIMasterKey(_ string) error { return ErrNotCompiledIn }

// SetDomainFilter is a no-op in the stub build.
func SetDomainFilter(_ string) {}

// SetLoginsOnly is a no-op in the stub build.
func SetLoginsOnly(_ bool) {}

// SubprocessModeFlag for non-decrypt builds.
const SubprocessModeFlag = "--_phantom-v20"

// ExtractAndPrintAppBoundKey is a no-op in the stub build.
func ExtractAndPrintAppBoundKey(_, _ string) {}

// MemScanEnabled is always false in the stub build.
var MemScanEnabled bool

// EnableMemScan is a no-op in the stub build.
func EnableMemScan() {}

// ExtractBrowserTokens is a no-op in the stub build.
func ExtractBrowserTokens() ([]DecryptedFinding, error) { return nil, ErrNotCompiledIn }
