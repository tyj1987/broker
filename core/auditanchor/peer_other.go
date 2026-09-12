//go:build !linux

package auditanchor

import "errors"

func NewOSPeerAuthorizer(uint32) (PeerAuthorizer, error) {
	return nil, errors.New("peer credential authorization requires linux")
}
