//go:build linux

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

var releaseExecutable = regexp.MustCompile(`^/opt/secret-broker/releases/[a-f0-9]{40}/bin/secret-broker-audit-recovery$`)

func validateIdentity(uid, gid int, groups []int, lookup func(string) (*user.User, error), groupLookup func(string) (*user.Group, error)) error {
	if uid <= 0 || gid <= 0 || lookup == nil || groupLookup == nil {
		return errUnavailable
	}
	own, err := lookup("broker-audit-recovery")
	if err != nil || own == nil || own.Uid != strconv.Itoa(uid) || own.Gid != strconv.Itoa(gid) {
		return errUnavailable
	}
	storeGroup, err := groupLookup("broker-audit-store")
	if err != nil || storeGroup == nil {
		return errUnavailable
	}
	storeGID, err := strconv.Atoi(storeGroup.Gid)
	if err != nil || storeGID <= 0 || storeGID == gid {
		return errUnavailable
	}
	seenStore := false
	for _, group := range groups {
		if group != gid && group != storeGID {
			return errUnavailable
		}
		if group == storeGID {
			seenStore = true
		}
	}
	if !seenStore {
		return errUnavailable
	}
	for _, name := range []string{"broker", "broker-audit-signer", "broker-audit-store", "broker-audit-exporter"} {
		account, err := lookup(name)
		if err != nil || account == nil || account.Uid == own.Uid {
			return errUnavailable
		}
	}
	return nil
}

func trustedPath(path string, executable bool, stat func(string) (os.FileInfo, error)) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || stat == nil {
		return errUnavailable
	}
	first := true
	for {
		info, err := stat(path)
		if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errUnavailable
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 {
			return errUnavailable
		}
		if first {
			if !info.Mode().IsRegular() || (executable && info.Mode().Perm()&0111 == 0) {
				return errUnavailable
			}
		} else if !info.IsDir() {
			return errUnavailable
		}
		if path == "/" {
			break
		}
		first = false
		path = filepath.Dir(path)
	}
	return nil
}

func prepareWith(uid, gid int, groups []int,
	lookup func(string) (*user.User, error), groupLookup func(string) (*user.Group, error),
	executable func() (string, error), stat func(string) (os.FileInfo, error)) (string, error) {
	if validateIdentity(uid, gid, groups, lookup, groupLookup) != nil || executable == nil {
		return "", errUnavailable
	}
	own, err := executable()
	if err != nil || !releaseExecutable.MatchString(own) {
		return "", errUnavailable
	}
	script := filepath.Join(filepath.Dir(filepath.Dir(own)), "recovery-runtime", "bin", "audit-recovery-service-check.js")
	for _, target := range []struct {
		path       string
		executable bool
	}{{own, true}, {nodeRuntime, true}, {script, false}} {
		if trustedPath(target.path, target.executable, stat) != nil {
			return "", errUnavailable
		}
	}
	return script, nil
}

func prepareRecovery() (string, error) {
	groups, err := os.Getgroups()
	if err != nil || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return "", errUnavailable
	}
	return prepareWith(os.Geteuid(), os.Getegid(), groups, user.Lookup, user.LookupGroup, os.Executable, os.Lstat)
}
