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
	if existing, statErr := os.Lstat(socketPath); statErr == nil {
		if existing.Mode()&os.ModeSocket == 0 || existing.Mode()&os.ModeSymlink != 0 ||
			fileUID(existing) != uint32(os.Geteuid()) {
			return rejectLockedServiceSocket(lock)
		}
		probe, probeErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if probeErr == nil {
			_ = probe.Close()
			return rejectLockedServiceSocket(lock)
		}
		if !errors.Is(probeErr, syscall.ECONNREFUSED) {
			return rejectLockedServiceSocket(lock)
		}
		current, currentErr := os.Lstat(socketPath)
		if currentErr != nil || !os.SameFile(existing, current) || os.Remove(socketPath) != nil {
			return rejectLockedServiceSocket(lock)
		}
	} else if !os.IsNotExist(statErr) {
		return rejectLockedServiceSocket(lock)
	}

	address := &net.UnixAddr{Name: socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return rejectLockedServiceSocket(lock)
	}
	listener.SetUnlinkOnClose(false)
	created, err := os.Lstat(socketPath)
	if err != nil || created.Mode()&os.ModeSocket == 0 || created.Mode()&os.ModeSymlink != 0 ||
		fileUID(created) != uint32(os.Geteuid()) {
		return rejectCreatedServiceSocket(listener, socketPath, nil, lock)
	}
	if err = os.Chmod(socketPath, 0o660); err != nil {
		return rejectCreatedServiceSocket(listener, socketPath, created, lock)
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o660 || fileUID(info) != uint32(os.Geteuid()) || !os.SameFile(created, info) {
		return rejectCreatedServiceSocket(listener, socketPath, created, lock)
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
		closeServiceLock(listener.lock)
	})
	return closeErr
}

func rejectLockedServiceSocket(lock *os.File) (net.Listener, error) {
	closeServiceLock(lock)
	return nil, ErrServiceSocketInvalid
}

func rejectCreatedServiceSocket(listener *net.UnixListener, path string, created os.FileInfo, lock *os.File) (net.Listener, error) {
	_ = listener.Close()
	current, err := os.Lstat(path)
	if created != nil && err == nil && os.SameFile(created, current) {
		_ = os.Remove(path)
	}
	closeServiceLock(lock)
	return nil, ErrServiceSocketInvalid
}

func closeServiceLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
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
