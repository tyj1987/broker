//go:build !linux

package auditmirror

import (
	"errors"
)

func NewOSPeerAuthorizer(uint32) (PeerAuthorizer, error) {
	return nil, errors.New("audit mirror peer authentication requires linux")
}

func newOSDialer(uint32) (dialContextFunc, error) {
	return nil, errors.New("audit mirror unix peer authentication requires linux")
}
