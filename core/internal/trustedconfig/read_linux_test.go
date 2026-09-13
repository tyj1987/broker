//go:build linux

package trustedconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileAtReturnsExactTrustedBytes(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "etc")
	directory := filepath.Join(parent, "providers")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "signer.json")
	value := []byte("{\"version\":1}\n")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	got, err := ReadFileAt(path, directory, uid, 1024)
	if err != nil || string(got) != string(value) {
		t.Fatalf("ReadFileAt = %q, %v", got, err)
	}
}

func TestReadFileAtRejectsBoundaryViolations(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "providers")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "signer.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	tests := []struct {
		name    string
		prepare func() (string, string, uint32, int64)
	}{
		{"relative", func() (string, string, uint32, int64) { return "signer.json", directory, uid, 10 }},
		{"wrong-directory", func() (string, string, uint32, int64) { return path, root, uid, 10 }},
		{"wrong-owner", func() (string, string, uint32, int64) { return path, directory, uid + 1, 10 }},
		{"oversized", func() (string, string, uint32, int64) { return path, directory, uid, 1 }},
		{"writable-directory", func() (string, string, uint32, int64) {
			_ = os.Chmod(directory, 0o722)
			return path, directory, uid, 10
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_ = os.Chmod(directory, 0o700)
			candidate, trusted, owner, maximum := test.prepare()
			if value, err := ReadFileAt(candidate, trusted, owner, maximum); err == nil || value != nil {
				t.Fatal("accepted unsafe boundary")
			}
		})
	}
}
