//go:build linux

package auditstore

import (
	"context"
	"errors"
	"net"
	"syscall"
)

type linuxPeerAuthorizer struct {
	exporterUID uint32
	recoveryUID uint32
}

func NewOSPeerAuthorizer(exporterUID, recoveryUID uint32) (PeerAuthorizer, error) {
	if exporterUID == 0 || recoveryUID == 0 || exporterUID == recoveryUID {
		return nil, errors.New("audit store peer identities must be distinct and non-root")
	}
	return &linuxPeerAuthorizer{exporterUID: exporterUID, recoveryUID: recoveryUID}, nil
}

func (authorizer *linuxPeerAuthorizer) AuthorizePeer(_ context.Context, connection net.Conn) (PeerRole, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return "", errors.New("peer transport is not a unix socket")
	}
	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		return "", errors.New("peer credentials are unavailable")
	}
	var credentials *syscall.Ucred
	var credentialError error
	if err := rawConnection.Control(func(descriptor uintptr) {
		credentials, credentialError = syscall.GetsockoptUcred(
			int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED,
		)
	}); err != nil || credentialError != nil || credentials == nil {
		return "", errors.New("peer credentials are unavailable")
	}
	switch credentials.Uid {
	case authorizer.exporterUID:
		return ExporterRole, nil
	case authorizer.recoveryUID:
		return RecoveryRole, nil
	default:
		return "", errors.New("peer uid is denied")
	}
}
