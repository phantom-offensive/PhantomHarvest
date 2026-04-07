//go:build decrypt

package decrypt

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
)

func hmacSHA1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func newCBCDec(block cipher.Block, iv []byte) cipher.BlockMode {
	// 3DES IV is 8 bytes; copy/clip defensively.
	bs := block.BlockSize()
	use := make([]byte, bs)
	copy(use, iv)
	return cipher.NewCBCDecrypter(block, use)
}
