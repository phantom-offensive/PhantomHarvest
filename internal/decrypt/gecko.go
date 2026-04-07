//go:build decrypt

package decrypt

import (
	"bytes"
	"crypto/des"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// asn1PBE matches the ASN.1 structure that Firefox uses for the PBE key
// and for each encryptedUsername / encryptedPassword in logins.json.
//
// SEQUENCE {
//   OCTET STRING keyID            (ignored — always the magic OID below for v1)
//   SEQUENCE {
//     OBJECT IDENTIFIER algo      (1.2.840.113549.1.12.5.1.3 = pbeWithSha1AndTripleDES-CBC)
//     SEQUENCE {
//       OCTET STRING salt
//       INTEGER iterations          // optional — Firefox writes this for nssPrivate
//     }
//   }
//   OCTET STRING ciphertext
// }
//
// For logins.json the structure is the same and the salt+iterations are the
// ones that protect the master key (not the login itself); the same 3DES key
// derived from the master password protects every login.

type pbeAlgo struct {
	OID    asn1.ObjectIdentifier
	Params struct {
		EntrySalt []byte
		Iter      int `asn1:"optional"`
	}
}

type pbeBlob struct {
	KeyID      []byte
	Algo       pbeAlgo
	Ciphertext []byte
}

// DecryptFirefoxProfile reads key4.db + logins.json and emits decrypted creds.
// Only handles the empty-master-password case (per spec). If a master password
// is set, an informational finding is emitted instead.
func DecryptFirefoxProfile(profileDir, browserName string) ([]DecryptedFinding, error) {
	keyDB := filepath.Join(profileDir, "key4.db")
	loginsPath := filepath.Join(profileDir, "logins.json")
	if _, err := os.Stat(keyDB); err != nil {
		return nil, fmt.Errorf("key4.db not found: %w", err)
	}
	if _, err := os.Stat(loginsPath); err != nil {
		return nil, fmt.Errorf("logins.json not found: %w", err)
	}

	masterKey, err := geckoExtractMasterKey(keyDB)
	if err != nil {
		return []DecryptedFinding{{
			Category:   "Browser",
			Type:       "decrypt_failed",
			File:       keyDB,
			Key:        browserName + " master key",
			Value:      fmt.Sprintf("(NSS unwrap failed — likely master password set: %v)", err),
			Confidence: ConfMedium,
		}}, nil
	}

	data, err := os.ReadFile(loginsPath)
	if err != nil {
		return nil, err
	}
	var lj struct {
		Logins []struct {
			Hostname          string `json:"hostname"`
			EncryptedUsername string `json:"encryptedUsername"`
			EncryptedPassword string `json:"encryptedPassword"`
		} `json:"logins"`
	}
	if err := json.Unmarshal(data, &lj); err != nil {
		return nil, err
	}

	var out []DecryptedFinding
	for _, l := range lj.Logins {
		userPT, err := geckoDecryptItem(l.EncryptedUsername, masterKey)
		if err != nil {
			continue
		}
		pwPT, err := geckoDecryptItem(l.EncryptedPassword, masterKey)
		if err != nil {
			continue
		}
		out = append(out, DecryptedFinding{
			Category:   "Browser",
			Type:       "saved_password",
			File:       loginsPath,
			Key:        fmt.Sprintf("%s | %s | %s", browserName, l.Hostname, string(userPT)),
			Value:      string(pwPT),
			Confidence: ConfHigh,
		})
	}
	return out, nil
}

// geckoExtractMasterKey opens key4.db, validates the empty master password
// against item2 in metaData, and unwraps a11 in nssPrivate to obtain the
// 3DES key used for logins.json items.
func geckoExtractMasterKey(keyDBPath string) ([]byte, error) {
	db, cleanup, err := openSQLiteCopy(keyDBPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var globalSalt, item2 []byte
	if err := db.QueryRow(`SELECT item1, item2 FROM metaData WHERE id = 'password'`).Scan(&globalSalt, &item2); err != nil {
		return nil, fmt.Errorf("%w: read metaData", err)
	}

	// Validate the master password by decrypting item2 — the plaintext should
	// be "password-check\x02\x02".
	checkPT, err := geckoPBEDecrypt(item2, globalSalt, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("%w: master password check", err)
	}
	if !bytes.HasPrefix(checkPT, []byte("password-check")) {
		return nil, fmt.Errorf("master password check failed (master password set?)")
	}

	var a11 []byte
	if err := db.QueryRow(`SELECT a11 FROM nssPrivate`).Scan(&a11); err != nil {
		return nil, fmt.Errorf("%w: read nssPrivate.a11", err)
	}
	keyPT, err := geckoPBEDecrypt(a11, globalSalt, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt a11", err)
	}
	// The 3DES master key for logins is the first 24 bytes of the decrypted blob.
	if len(keyPT) < 24 {
		return nil, fmt.Errorf("a11 plaintext too short")
	}
	return keyPT[:24], nil
}

// geckoPBEDecrypt parses a Firefox PBE blob and decrypts it using SHA1+3DES
// derivation with the supplied global salt and master password.
func geckoPBEDecrypt(blob, globalSalt, masterPW []byte) ([]byte, error) {
	var p pbeBlob
	if _, err := asn1.Unmarshal(blob, &p); err != nil {
		return nil, fmt.Errorf("%w: asn1", err)
	}
	// Derive intermediate: HP = SHA1(globalSalt || masterPW)
	hp := sha1.Sum(append(append([]byte{}, globalSalt...), masterPW...))
	// CHP = SHA1(HP || entrySalt)
	chp := sha1.Sum(append(append([]byte{}, hp[:]...), p.Algo.Params.EntrySalt...))
	// PES = entrySalt padded with zeros to 20 bytes
	pes := make([]byte, 20)
	copy(pes, p.Algo.Params.EntrySalt)
	// k1 = HMAC-SHA1(CHP, PES || entrySalt)
	k1 := hmacSHA1(chp[:], append(pes, p.Algo.Params.EntrySalt...))
	// tk = HMAC-SHA1(CHP, PES)
	tk := hmacSHA1(chp[:], pes)
	// k2 = HMAC-SHA1(CHP, tk || entrySalt)
	k2 := hmacSHA1(chp[:], append(tk, p.Algo.Params.EntrySalt...))
	k := append(k1, k2...) // 40 bytes
	key := k[:24]
	iv := k[len(k)-8:]

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(p.Ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not block aligned")
	}
	out := make([]byte, len(p.Ciphertext))
	mode := newCBCDec(block, iv)
	mode.CryptBlocks(out, p.Ciphertext)
	return pkcs7UnpadGeneric(out), nil
}

// geckoDecryptItem decodes a base64 logins.json field and 3DES-CBC decrypts
// it with the master key. The IV is carried in the inner ASN.1 structure.
func geckoDecryptItem(b64 string, masterKey []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	var p pbeBlob
	if _, err := asn1.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	// For logins.json the inner "EntrySalt" field actually carries the IV.
	iv := p.Algo.Params.EntrySalt
	block, err := des.NewTripleDESCipher(masterKey)
	if err != nil {
		return nil, err
	}
	if len(p.Ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not block aligned")
	}
	out := make([]byte, len(p.Ciphertext))
	newCBCDec(block, iv).CryptBlocks(out, p.Ciphertext)
	return pkcs7UnpadGeneric(out), nil
}

func pkcs7UnpadGeneric(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad <= 0 || pad > len(b) {
		return b
	}
	return b[:len(b)-pad]
}
