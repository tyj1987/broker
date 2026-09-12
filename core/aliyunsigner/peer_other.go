//go:build !linux

package aliyunsigner

import "errors"

func NewOSPeerAuthorizer(uint32) (PeerAuthorizer, error) {
	return nil, errors.New("peer credential authorization requires linux")
}
