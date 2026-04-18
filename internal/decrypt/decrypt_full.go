//go:build decrypt

package decrypt

const enabled = true

// EnableAppBoundV20 flips the Chrome v20+ app-bound encryption bypass
// on for this process. The bypass is Windows-only and experimental —
// it may crash on some Chrome builds (access violation inside
// rpcrt4.dll that Go's recover() cannot catch). On Linux/macOS this is
// a no-op. Gate it behind a CLI flag so scans stay crash-proof by
// default.
func EnableAppBoundV20() { enableAppBoundV20() }

// MemScanEnabled gates Chrome process memory scanning for the v20 key.
// Off by default — scanning 20-30 chrome.exe processes reads hundreds of
// MB and takes 10-30 s. Enable with -v20-memscan.
var MemScanEnabled bool

// EnableMemScan turns on Chrome process memory scanning for v20 key extraction.
func EnableMemScan() { MemScanEnabled = true }
