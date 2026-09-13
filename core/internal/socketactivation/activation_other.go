//go:build !linux

package socketactivation

import (
	"errors"
	"net"
)

var ErrInvalid = errors.New("socket activation is invalid")

func Listener(string, string) (net.Listener, error) {
	return nil, ErrInvalid
}
