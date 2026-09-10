//go:build !linux

package providercredential

import "errors"

func NewOSPeerAuthorizer(uint32) (PeerAuthorizer, error) {
	return nil, errors.New("peer credential authorization requires linux")
}
