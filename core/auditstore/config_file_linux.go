//go:build linux

package auditstore

import (
	"os"
	"path/filepath"
	"syscall"
)

const productionConfigDirectory = "/etc/secret-broker/audit"

func openTrustedServiceConfig(path string) (*os.File, error) {
	return openTrustedServiceConfigAt(path, productionConfigDirectory, 0)
}

func openTrustedServiceConfigAt(path, trustedDirectory string, trustedUID uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != trustedDirectory ||
		!filepath.IsAbs(trustedDirectory) || filepath.Clean(trustedDirectory) != trustedDirectory {
		return nil, ErrServiceConfigInvalid
	}
	for _, directory := range []string{filepath.Dir(trustedDirectory), trustedDirectory} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o022 != 0 || fileUID(info) != trustedUID {
			return nil, ErrServiceConfigInvalid
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !trustedConfigFileInfo(before, trustedUID) {
		return nil, ErrServiceConfigInvalid
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrServiceConfigInvalid
	}
	after, err := file.Stat()
	if err != nil || !trustedConfigFileInfo(after, trustedUID) || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, ErrServiceConfigInvalid
	}
	return file, nil
}

func trustedConfigFileInfo(info os.FileInfo, trustedUID uint32) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm()&0o022 == 0 && info.Size() >= 1 && info.Size() <= MaxServiceConfigBytes &&
		fileUID(info) == trustedUID
}
