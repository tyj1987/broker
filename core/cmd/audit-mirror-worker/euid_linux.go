//go:build linux

package main

import "os"

func currentEUID() uint32 { return uint32(os.Geteuid()) }
