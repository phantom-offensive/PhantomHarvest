//go:build decrypt && !windows

package decrypt

// SubprocessModeFlag is the internal flag for crash-isolated v20 extraction.
// On non-Windows platforms there is no app-bound encryption, so this is only
// used to satisfy references in main.go at compile time.
const SubprocessModeFlag = "--_phantom-v20"

// ExtractAndPrintAppBoundKey is a no-op on non-Windows platforms.
func ExtractAndPrintAppBoundKey(_, _ string) {}

// ScanChromeProcessMemory is a no-op on non-Windows platforms.
func ScanChromeProcessMemory(_, _ string) ([]byte, error) {
	return nil, nil
}

// ExtractBrowserTokens is a no-op on non-Windows platforms for now — the
// ReadProcessMemory path is Windows-specific. Linux/macOS equivalents
// would go through /proc/<pid>/mem or task_for_pid() respectively.
func ExtractBrowserTokens() ([]DecryptedFinding, error) {
	return nil, nil
}
