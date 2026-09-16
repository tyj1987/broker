//go:build linux

package main

import (
	"os"
	"os/user"
	"strings"
	"syscall"
	"testing"
	"time"
)

func look(name string) (*user.User, error) {
	if name == "broker-audit-exporter" {
		return &user.User{Uid: "1234", Gid: "1234"}, nil
	}
	return &user.User{Uid: "2000", Gid: "2000"}, nil
}
func group(name string) (*user.Group, error) {
	if name == "broker-audit-signer" {
		return &user.Group{Gid: "1203"}, nil
	}
	return &user.Group{Gid: "1202"}, nil
}
func TestIdentityMustBeSeparateAndExplicit(t *testing.T) {
	if validateIdentity(1234, 1234, []int{1234, 1202, 1203}, look, group) != nil {
		t.Fatal("valid identity")
	}
	for _, c := range []struct {
		u, g   int
		groups []int
	}{{0, 1234, []int{1202, 1203}}, {1234, 0, []int{1202, 1203}}, {1, 1234, []int{1202, 1203}}, {1234, 1, []int{1202, 1203}}, {1234, 1234, nil}, {1234, 1234, []int{1202, 0}}, {1234, 1234, []int{1202, 9999}}} {
		if validateIdentity(c.u, c.g, c.groups, look, group) == nil {
			t.Fatal("bad identity")
		}
	}
	for _, bad := range []func(string) (*user.User, error){nil, func(string) (*user.User, error) { return nil, errUnavailable }, func(string) (*user.User, error) { return nil, nil }, func(string) (*user.User, error) { return &user.User{Uid: "1234", Gid: "1234"}, nil }} {
		if validateIdentity(1234, 1234, []int{1202, 1203}, bad, group) == nil {
			t.Fatal("lookup accepted")
		}
	}
	for _, bad := range []func(string) (*user.Group, error){nil, func(string) (*user.Group, error) { return nil, errUnavailable }, func(string) (*user.Group, error) { return nil, nil }, func(string) (*user.Group, error) { return &user.Group{Gid: "bad"}, nil }, func(string) (*user.Group, error) { return &user.Group{Gid: "0"}, nil }, func(string) (*user.Group, error) { return &user.Group{Gid: "1234"}, nil }} {
		if validateIdentity(1234, 1234, []int{1202, 1203}, look, bad) == nil {
			t.Fatal("group accepted")
		}
	}
	if _, err := prepareExporter(); err == nil {
		t.Fatal("test process cannot be production identity")
	}
}

type fakeInfo struct {
	mode    os.FileMode
	owner   uint32
	missing bool
}

func (f fakeInfo) Name() string       { return "file" }
func (f fakeInfo) Size() int64        { return 1 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any {
	if f.missing {
		return nil
	}
	return &syscall.Stat_t{Uid: f.owner}
}
func TestImmutablePathsRejectLinksAndWritableAncestors(t *testing.T) {
	good := func(p string) (os.FileInfo, error) {
		if p == "/safe/file" {
			return fakeInfo{mode: 0500}, nil
		}
		return fakeInfo{mode: os.ModeDir | 0555}, nil
	}
	if trustedPath("/safe/file", true, good) != nil {
		t.Fatal("good file")
	}
	for _, p := range []string{"relative", "/safe/../file"} {
		if trustedPath(p, true, good) == nil {
			t.Fatal("bad path")
		}
	}
	if trustedPath("/safe/file", true, nil) == nil {
		t.Fatal("nil stat")
	}
	for _, bad := range []fakeInfo{{mode: 0777}, {mode: 0500, owner: 2}, {mode: os.ModeSymlink | 0777}, {mode: os.ModeDir | 0555}, {mode: 0400}, {mode: 0500, missing: true}} {
		fn := func(p string) (os.FileInfo, error) {
			if p == "/safe/file" {
				return bad, nil
			}
			return good(p)
		}
		if trustedPath("/safe/file", true, fn) == nil {
			t.Fatal("unsafe file")
		}
	}
	for _, bad := range []fakeInfo{{mode: os.ModeDir | 0777}, {mode: 0400}, {mode: os.ModeDir | 0555, owner: 2}} {
		fn := func(p string) (os.FileInfo, error) {
			if p == "/safe" {
				return bad, nil
			}
			return good(p)
		}
		if trustedPath("/safe/file", true, fn) == nil {
			t.Fatal("unsafe parent")
		}
	}
	if trustedPath("/safe/file", false, func(string) (os.FileInfo, error) { return nil, errUnavailable }) == nil {
		t.Fatal("stat error")
	}
	if trustedPath("/safe/file", false, func(string) (os.FileInfo, error) { return nil, nil }) == nil {
		t.Fatal("nil info")
	}
	if !releaseExecutable.MatchString("/opt/secret-broker/releases/" + strings.Repeat("a", 40) + "/bin/secret-broker-audit-exporter") {
		t.Fatal("valid release rejected")
	}
	for _, p := range []string{"/tmp/exporter", "/opt/secret-broker/broker/bin/secret-broker-audit-exporter", "/opt/secret-broker/releases/" + strings.Repeat("A", 40) + "/bin/secret-broker-audit-exporter"} {
		if releaseExecutable.MatchString(p) {
			t.Fatal("bad release")
		}
	}
}

func TestPreparationBindsNativeAndNodeCodeToOneRelease(t *testing.T) {
	own := "/opt/secret-broker/releases/" + strings.Repeat("a", 40) + "/bin/secret-broker-audit-exporter"
	script := "/opt/secret-broker/releases/" + strings.Repeat("a", 40) + "/exporter-runtime/bin/audit-exporter-service-check.js"
	exe := func() (string, error) { return own, nil }
	stat := func(p string) (os.FileInfo, error) {
		if p == own || p == nodeRuntime {
			return fakeInfo{mode: 0500}, nil
		}
		if p == script {
			return fakeInfo{mode: 0440}, nil
		}
		return fakeInfo{mode: os.ModeDir | 0555}, nil
	}
	got, err := prepareWith(1234, 1234, []int{1202, 1203}, look, group, exe, stat)
	if err != nil || got != script {
		t.Fatal("valid release")
	}
	for _, bad := range []func() (string, error){nil, func() (string, error) { return "", errUnavailable }, func() (string, error) { return "/tmp/other", nil }} {
		if _, err = prepareWith(1234, 1234, []int{1202, 1203}, look, group, bad, stat); err == nil {
			t.Fatal("invalid exe")
		}
	}
	for _, target := range []string{own, nodeRuntime, script} {
		badStat := func(p string) (os.FileInfo, error) {
			if p == target {
				return fakeInfo{mode: 0777}, nil
			}
			return stat(p)
		}
		if _, err = prepareWith(1234, 1234, []int{1202, 1203}, look, group, exe, badStat); err == nil {
			t.Fatal("writable release")
		}
	}
}

func TestSignerAndStoreGroupsCannotAlias(t *testing.T) {
	alias := func(string) (*user.Group, error) { return &user.Group{Gid: "1202"}, nil }
	if validateIdentity(1234, 1234, []int{1202}, look, alias) == nil {
		t.Fatal("group alias accepted")
	}
	for _, groups := range [][]int{{1202}, {1203}, {1202, 1203, 2000}} {
		if validateIdentity(1234, 1234, groups, look, group) == nil {
			t.Fatal("unsafe supplementary groups")
		}
	}
}
