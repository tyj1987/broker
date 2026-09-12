//go:build linux

package auditstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenTrustedServiceConfigAtValidatesOwnerModeAndBoundary(t *testing.T) {
	trustedParent := t.TempDir()
	trustedDirectory := filepath.Join(trustedParent, "audit")
	if err := os.Mkdir(trustedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	trustedUID := uint32(os.Geteuid())
	path := filepath.Join(trustedDirectory, "store.json")
	if err := os.WriteFile(path, []byte(validServiceConfigJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openTrustedServiceConfigAt(path, trustedDirectory, trustedUID)
	if err != nil {
		t.Fatalf("openTrustedServiceConfigAt() error = %v", err)
	}
	_ = file.Close()
	wrongUID := trustedUID + 1
	if wrongUID == trustedUID {
		wrongUID = trustedUID - 1
	}
	if _, err = openTrustedServiceConfigAt(path, trustedDirectory, wrongUID); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("wrong owner error = %v", err)
	}

	outside := filepath.Join(trustedParent, "outside.json")
	if err = os.WriteFile(outside, []byte(validServiceConfigJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = openTrustedServiceConfigAt(outside, trustedDirectory, trustedUID); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("outside error = %v", err)
	}
	if err = os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err = openTrustedServiceConfigAt(path, trustedDirectory, trustedUID); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("writable config error = %v", err)
	}
	if err = os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(trustedDirectory, 0o720); err != nil {
		t.Fatal(err)
	}
	if _, err = openTrustedServiceConfigAt(path, trustedDirectory, trustedUID); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("writable directory error = %v", err)
	}
}

func TestOpenTrustedServiceConfigAtRejectsSymlink(t *testing.T) {
	trustedParent := t.TempDir()
	trustedDirectory := filepath.Join(trustedParent, "audit")
	if err := os.Mkdir(trustedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(trustedDirectory, "target.json")
	if err := os.WriteFile(target, []byte(validServiceConfigJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(trustedDirectory, "store.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := openTrustedServiceConfigAt(link, trustedDirectory, uint32(os.Geteuid())); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestOpenTrustedServiceConfigAtRejectsMissingEmptyAndUnreadableFiles(t *testing.T) {
	trustedParent := t.TempDir()
	trustedDirectory := filepath.Join(trustedParent, "audit")
	if err := os.Mkdir(trustedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	trustedUID := uint32(os.Geteuid())
	missing := filepath.Join(trustedDirectory, "missing.json")
	if _, err := openTrustedServiceConfigAt(missing, trustedDirectory, trustedUID); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("missing error = %v", err)
	}
	empty := filepath.Join(trustedDirectory, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTrustedServiceConfigAt(empty, trustedDirectory, trustedUID); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("empty error = %v", err)
	}
	if os.Geteuid() != 0 {
		if err := os.WriteFile(empty, []byte(validServiceConfigJSON()), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(empty, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := openTrustedServiceConfigAt(empty, trustedDirectory, trustedUID); !errors.Is(err, ErrServiceConfigInvalid) {
			t.Fatalf("unreadable error = %v", err)
		}
	}
}

func TestOpenTrustedServiceConfigRejectsPathOutsideProductionBoundary(t *testing.T) {
	file, err := openTrustedServiceConfig("/not-the-production-boundary/store.json")
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("outside production boundary error = %v", err)
	}
	if trustedConfigFileInfo(nil, uint32(os.Geteuid())) {
		t.Fatal("nil file metadata accepted")
	}
}
