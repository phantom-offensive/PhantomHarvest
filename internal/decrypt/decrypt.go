//go:build !decrypt

package decrypt

const enabled = false

// DecryptChromiumProfile is a stub when the decrypt tag is not set.
func DecryptChromiumProfile(profileDir, browserName string) ([]DecryptedFinding, error) {
	return nil, ErrNotCompiledIn
}

// DecryptFirefoxProfile is a stub when the decrypt tag is not set.
func DecryptFirefoxProfile(profileDir, browserName string) ([]DecryptedFinding, error) {
	return nil, ErrNotCompiledIn
}
