//go:build !linux

package main

func currentEUID() uint32 { return 0 }
