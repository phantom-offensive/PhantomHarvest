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
