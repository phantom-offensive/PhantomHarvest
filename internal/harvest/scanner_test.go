package harvest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerFindsAWSKeyInEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("write temp .env: %v", err)
	}

	scanner := NewScanner(dir, 5)
	results := scanner.Run()

	found := false
	for _, f := range results {
		if strings.Contains(f.Value, "AKIA") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find AKIA finding in %d results", len(results))
	}
}
