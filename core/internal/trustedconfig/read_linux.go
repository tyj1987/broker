//go:build linux

package trustedconfig

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrInvalid = errors.New("trusted configuration is invalid")

// ReadFileAt reads one regular, non-symlink configuration file after verifying
// the complete fixed directory boundary and file ownership. The returned bytes
// are the exact bytes read from the verified descriptor.
func ReadFileAt(path, trustedDirectory string, trustedUID uint32, maximumBytes int64) ([]byte, error) {
	if maximumBytes < 1 || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Dir(path) != trustedDirectory || !filepath.IsAbs(trustedDirectory) ||
		filepath.Clean(trustedDirectory) != trustedDirectory {
		return nil, ErrInvalid
	}
	for _, directory := range []string{filepath.Dir(trustedDirectory), trustedDirectory} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o022 != 0 || ownerUID(info) != trustedUID {
			return nil, ErrInvalid
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !validFile(before, trustedUID, maximumBytes) {
		return nil, ErrInvalid
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, ErrInvalid
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !validFile(after, trustedUID, maximumBytes) || !os.SameFile(before, after) {
		return nil, ErrInvalid
	}
	value := make([]byte, after.Size())
	if _, err = io.ReadFull(file, value); err != nil || len(value) == 0 {
		return nil, ErrInvalid
	}
	return value, nil
}

func validFile(info os.FileInfo, trustedUID uint32, maximumBytes int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm()&0o022 == 0 && info.Size() >= 1 && info.Size() <= maximumBytes &&
		ownerUID(info) == trustedUID
}

func ownerUID(info os.FileInfo) uint32 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return ^uint32(0)
	}
	return stat.Uid
}
