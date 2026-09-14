//go:build !linux

package auditstore

import "errors"

func NewOSPeerAuthorizer(uint32, uint32) (PeerAuthorizer, error) {
	return nil, errors.New("peer credential authorization requires linux")
}
