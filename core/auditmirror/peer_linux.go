//go:build linux

package auditmirror

import (
	"context"
	"errors"
	"net"
	"syscall"
)

type linuxPeerAuthorizer struct{ storeUID uint32 }

func NewOSPeerAuthorizer(storeUID uint32) (PeerAuthorizer, error) {
	if storeUID == 0 {
		return nil, errors.New("audit mirror store identity must be non-root")
	}
	return &linuxPeerAuthorizer{storeUID: storeUID}, nil
}

func (authorizer *linuxPeerAuthorizer) AuthorizePeer(_ context.Context, connection net.Conn) error {
	credentials, err := unixPeerCredentials(connection)
	if err != nil || credentials.Uid != authorizer.storeUID {
		return errors.New("audit mirror peer denied")
	}
	return nil
}

func unixPeerCredentials(connection net.Conn) (*syscall.Ucred, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, errors.New("peer transport is not a unix socket")
	}
	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		return nil, errors.New("peer credentials are unavailable")
	}
	var credentials *syscall.Ucred
	var credentialError error
	if err := rawConnection.Control(func(descriptor uintptr) {
		credentials, credentialError = syscall.GetsockoptUcred(
			int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED,
		)
	}); err != nil || credentialError != nil || credentials == nil {
		return nil, errors.New("peer credentials are unavailable")
	}
	return credentials, nil
}
