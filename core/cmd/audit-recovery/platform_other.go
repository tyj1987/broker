//go:build !linux

package main

// Production peer-credential and systemd boundaries are Linux-only.
func prepareRecovery() (string, error) { return "", errUnavailable }
