//go:build !linux

package trustedconfig

import "errors"

var ErrInvalid = errors.New("trusted configuration is invalid")

func ReadFileAt(string, string, uint32, int64) ([]byte, error) {
	return nil, ErrInvalid
}
