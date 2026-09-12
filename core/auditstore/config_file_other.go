//go:build !linux

package auditstore

import (
	"os"
	"path/filepath"
)

func openTrustedServiceConfig(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrServiceConfigInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() < 1 || before.Size() > MaxServiceConfigBytes {
		return nil, ErrServiceConfigInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() < 1 || after.Size() > MaxServiceConfigBytes ||
		!os.SameFile(before, after) {
		_ = file.Close()
		return nil, ErrServiceConfigInvalid
	}
	return file, nil
}
