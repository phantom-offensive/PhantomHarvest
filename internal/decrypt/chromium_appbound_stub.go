//go:build decrypt && !windows

package decrypt

// SubprocessModeFlag is the internal flag for crash-isolated v20 extraction.
// On non-Windows platforms there is no app-bound encryption, so this is only
// used to satisfy references in main.go at compile time.
const SubprocessModeFlag = "--_phantom-v20"

// ExtractAndPrintAppBoundKey is a no-op on non-Windows platforms.
func ExtractAndPrintAppBoundKey(_, _ string) {}
