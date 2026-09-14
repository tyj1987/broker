//go:build linux

package main

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestLinuxProcessAndNamedIdentityLookup(t *testing.T) {
	if currentEUID() != uint32(os.Geteuid()) {
		t.Fatal("effective uid is not bound to the kernel identity")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	want, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || want == 0 {
		t.Skip("test runner does not expose a non-root numeric user identity")
	}
	got, err := lookupUID(account.Username)
	if err != nil || got != uint32(want) {
		t.Fatalf("lookupUID = %d, %v; want %d", got, err, want)
	}
}
