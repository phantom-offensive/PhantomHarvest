//go:build decrypt && windows

package decrypt

import "unsafe"

func unsafePtr(p *byte) uintptr      { return uintptr(unsafe.Pointer(p)) }
func unsafeSlice(p *byte, n int) []byte {
	return unsafe.Slice(p, n)
}
