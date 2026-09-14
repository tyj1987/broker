//go:build !linux

package main

import "testing"

func TestCurrentEUIDFailsClosedOutsideLinux(t *testing.T) {
	if currentEUID() != 0 {
		t.Fatal("non-Linux command must fail closed on process identity")
	}
}
