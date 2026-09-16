//go:build !linux

package main

// Production peer-credential and systemd boundaries are Linux-only.
func prepareExporter() (string, error) { return "", errUnavailable }
