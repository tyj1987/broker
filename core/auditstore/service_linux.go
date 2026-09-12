//go:build linux

package auditstore

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type managedUnixListener struct {
	*net.UnixListener
	path string
	info os.FileInfo
	lock *os.File
	once sync.Once
}

func listenServiceSocket(socketPath string) (net.Listener, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		filepath.Base(socketPath) != "store.sock" {
		return nil, ErrServiceSocketInvalid
	}
	parent := filepath.Dir(socketPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0o022 != 0 || fileUID(parentInfo) != uint32(os.Geteuid()) {
		return nil, ErrServiceSocketInvalid
	}
	lock, err := acquireServiceLock(filepath.Join(parent, "store.lock"))
	if err != nil {
		return nil, ErrServiceSocketInvalid
	}
	releaseLock := func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}
	if existing, statErr := os.Lstat(socketPath); statErr == nil {
		if existing.Mode()&os.ModeSocket == 0 || existing.Mode()&os.ModeSymlink != 0 ||
			fileUID(existing) != uint32(os.Geteuid()) {
			releaseLock()
			return nil, ErrServiceSocketInvalid
		}
		probe, probeErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if probeErr == nil {
			_ = probe.Close()
			releaseLock()
			return nil, ErrServiceSocketInvalid
		}
		if !errors.Is(probeErr, syscall.ECONNREFUSED) {
			releaseLock()
			return nil, ErrServiceSocketInvalid
		}
		current, currentErr := os.Lstat(socketPath)
		if currentErr != nil || !os.SameFile(existing, current) || os.Remove(socketPath) != nil {
			releaseLock()
			return nil, ErrServiceSocketInvalid
		}
	} else if !os.IsNotExist(statErr) {
		releaseLock()
		return nil, ErrServiceSocketInvalid
	}

	address := &net.UnixAddr{Name: socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		releaseLock()
		return nil, ErrServiceSocketInvalid
	}
	listener.SetUnlinkOnClose(false)
	created, err := os.Lstat(socketPath)
	if err != nil || created.Mode()&os.ModeSocket == 0 || created.Mode()&os.ModeSymlink != 0 ||
		fileUID(created) != uint32(os.Geteuid()) {
		_ = listener.Close()
		releaseLock()
		return nil, ErrServiceSocketInvalid
	}
	cleanup := func() {
		_ = listener.Close()
		current, statErr := os.Lstat(socketPath)
		if statErr == nil && os.SameFile(created, current) {
			_ = os.Remove(socketPath)
		}
		releaseLock()
	}
	if err = os.Chmod(socketPath, 0o660); err != nil {
		cleanup()
		return nil, ErrServiceSocketInvalid
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o660 || fileUID(info) != uint32(os.Geteuid()) || !os.SameFile(created, info) {
		cleanup()
		return nil, ErrServiceSocketInvalid
	}
	return &managedUnixListener{UnixListener: listener, path: socketPath, info: info, lock: lock}, nil
}

func (listener *managedUnixListener) Close() error {
	var closeErr error
	listener.once.Do(func() {
		closeErr = listener.UnixListener.Close()
		current, err := os.Lstat(listener.path)
		if err == nil && os.SameFile(listener.info, current) {
			_ = os.Remove(listener.path)
		}
		_ = syscall.Flock(int(listener.lock.Fd()), syscall.LOCK_UN)
		_ = listener.lock.Close()
	})
	return closeErr
}

func acquireServiceLock(path string) (*os.File, error) {
	var before os.FileInfo
	before, err := os.Lstat(path)
	if err == nil {
		if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
			before.Mode().Perm()&0o022 != 0 || fileUID(before) != uint32(os.Geteuid()) {
			return nil, ErrServiceSocketInvalid
		}
	} else if !os.IsNotExist(err) {
		return nil, ErrServiceSocketInvalid
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrServiceSocketInvalid
	}
	lock := os.NewFile(uintptr(fd), path)
	if lock == nil {
		_ = syscall.Close(fd)
		return nil, ErrServiceSocketInvalid
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 ||
		fileUID(info) != uint32(os.Geteuid()) || (before != nil && !os.SameFile(before, info)) {
		_ = lock.Close()
		return nil, ErrServiceSocketInvalid
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, ErrServiceSocketInvalid
	}
	return lock, nil
}

func fileUID(info os.FileInfo) uint32 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return ^uint32(0)
	}
	return stat.Uid
}
