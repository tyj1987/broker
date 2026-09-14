//go:build linux

package aliyunsigner

import (
	"context"
	"errors"
	"net"
	"syscall"
)

type linuxPeerAuthorizer struct{ uid uint32 }

func NewOSPeerAuthorizer(uid uint32) (PeerAuthorizer, error) {
	if uid == 0 {
		return nil, errors.New("broker peer uid must be non-root")
	}
	return &linuxPeerAuthorizer{uid: uid}, nil
}

func (authorizer *linuxPeerAuthorizer) AuthorizePeer(_ context.Context, connection net.Conn) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("peer transport is not a unix socket")
	}
	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		return errors.New("peer credentials are unavailable")
	}
	var credentials *syscall.Ucred
	var credentialError error
	if err := rawConnection.Control(func(descriptor uintptr) {
		credentials, credentialError = syscall.GetsockoptUcred(
			int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED,
		)
	}); err != nil || credentialError != nil || credentials == nil {
		return errors.New("peer credentials are unavailable")
	}
	if credentials.Uid != authorizer.uid {
		return errors.New("peer uid is denied")
	}
	return nil
}
