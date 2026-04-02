package obfuscate

// D decodes an XOR-obfuscated byte slice at runtime.
// Key is rotated across the data.
func D(data []byte, key byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key ^ byte(i%7)
	}
	return string(out)
}

// E encodes a string for embedding in source code.
// Use this during development to generate obfuscated byte slices.
func E(s string, key byte) []byte {
	out := make([]byte, len(s))
	for i, b := range []byte(s) {
		out[i] = b ^ key ^ byte(i%7)
	}
	return out
}
