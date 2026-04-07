//go:build decrypt && windows

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/sys/windows"
)

// getChromiumMasterKey reads Local State and attempts to unwrap both the
// legacy v10 key (DPAPI-protected AES key in `os_crypt.encrypted_key`) and
// the v20 app-bound key (`os_crypt.app_bound_encrypted_key`, introduced in
// Chrome v127, unwrapped by calling the browser's IElevator COM service).
//
// Either lookup may fail independently — we return whatever we managed to
// obtain. Failing *both* is an error.
func getChromiumMasterKey(profileDir, browserName string) (*chromiumKeys, error) {
	out := &chromiumKeys{}
	var v10Err, v20Err error

	if raw, err := readLocalStateKey(profileDir); err == nil {
		if len(raw) < 5 || !bytes.Equal(raw[:5], []byte("DPAPI")) {
			v10Err = fmt.Errorf("encrypted_key missing DPAPI prefix")
		} else if key, err := dpapiUnprotect(raw[5:]); err != nil {
			v10Err = err
		} else {
			out.V10 = key
		}
	} else {
		v10Err = err
	}

	if key, err := getChromiumAppBoundKey(profileDir, browserName); err != nil {
		v20Err = err
	} else {
		out.V20 = key
	}

	if out.V10 == nil && out.V20 == nil {
		return nil, fmt.Errorf("both key unwrap attempts failed: v10=%v; v20=%v", v10Err, v20Err)
	}
	return out, nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, fmt.Errorf("%w: CryptUnprotectData", err)
	}
	defer windows.LocalFree(windows.Handle(unsafePtr(out.Data)))
	res := make([]byte, out.Size)
	copy(res, unsafeSlice(out.Data, int(out.Size)))
	return res, nil
}

// chromiumDecryptValue dispatches on the blob's version prefix.
//
//	"v10"/"v11"  → AES-256-GCM with the legacy DPAPI-wrapped key (keys.V10).
//	"v20"        → AES-256-GCM with the app-bound key obtained from
//	               IElevator (keys.V20). For v20, the first 32 bytes of
//	               plaintext are per-entry metadata and are stripped.
//	(no prefix)  → Legacy DPAPI-only format, used by ancient Chrome builds.
//
// Returns an error (rather than panicking) on empty or malformed blobs —
// Login Data has NULL password_value rows for every site the user told
// Chrome "never save" on.
func chromiumDecryptValue(blob []byte, keys *chromiumKeys) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob")
	}
	if len(blob) > 3 {
		prefix := string(blob[:3])
		if prefix == "v10" || prefix == "v11" {
			if keys.V10 == nil {
				return nil, fmt.Errorf("v10 entry but no v10 key available")
			}
			return aesGCMOpen(blob[3:], keys.V10, 0)
		}
		if prefix == "v20" {
			if keys.V20 == nil {
				return nil, fmt.Errorf("v20 entry but no v20 key (app-bound bypass unavailable)")
			}
			// v20 plaintext is prefixed with 32 bytes of per-entry
			// metadata (origin hash etc.) that we don't care about.
			return aesGCMOpen(blob[3:], keys.V20, 32)
		}
	}
	// Legacy: directly DPAPI-encrypted.
	return dpapiUnprotect(blob)
}

// aesGCMOpen decrypts a Chromium AES-GCM blob: 12-byte nonce, ciphertext,
// 16-byte tag. Strips `stripPrefix` bytes from the start of the plaintext
// (used for v20 per-entry metadata).
func aesGCMOpen(blob, key []byte, stripPrefix int) ([]byte, error) {
	if len(blob) < 12+16 {
		return nil, fmt.Errorf("blob too short")
	}
	nonce := blob[:12]
	ct := blob[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: AES-GCM open", err)
	}
	if stripPrefix > 0 && len(pt) >= stripPrefix {
		pt = pt[stripPrefix:]
	}
	return pt, nil
}
