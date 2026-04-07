//go:build decrypt && windows

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/sys/windows"
)

// getChromiumMasterKey reads Local State, strips the DPAPI prefix, and
// unwraps the AES key with CryptUnprotectData.
func getChromiumMasterKey(profileDir, browserName string) ([]byte, error) {
	raw, err := readLocalStateKey(profileDir)
	if err != nil {
		return nil, err
	}
	if len(raw) < 5 || !bytes.Equal(raw[:5], []byte("DPAPI")) {
		return nil, fmt.Errorf("encrypted_key missing DPAPI prefix")
	}
	return dpapiUnprotect(raw[5:])
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
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

// chromiumDecryptValue handles both v10/v11 (AES-GCM) and the legacy
// DPAPI-only format.
func chromiumDecryptValue(blob, key []byte) ([]byte, error) {
	if len(blob) > 3 && (bytes.Equal(blob[:3], []byte("v10")) || bytes.Equal(blob[:3], []byte("v11"))) {
		if len(blob) < 3+12+16 {
			return nil, fmt.Errorf("blob too short")
		}
		nonce := blob[3:15]
		ct := blob[15:]
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return gcm.Open(nil, nonce, ct, nil)
	}
	// Legacy: directly DPAPI-encrypted.
	return dpapiUnprotect(blob)
}
