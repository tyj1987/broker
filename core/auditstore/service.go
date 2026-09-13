package auditstore

import (
	"context"
	"errors"
)

const DefaultSocketPath = "/run/secret-broker-audit-store/store.sock"

var ErrServiceSocketInvalid = errors.New("audit store service socket is invalid")

func ServeRuntime(
	ctx context.Context,
	runtime *Runtime,
	exporterUID uint32,
	recoveryUID uint32,
	socketPath string,
) error {
	if ctx == nil || runtime == nil || runtime.Repository == nil || runtime.Verifier == nil ||
		!idPattern.MatchString(runtime.StreamID) || socketPath == "" {
		return ErrServiceRuntimeInvalid
	}
	peers, err := NewOSPeerAuthorizer(exporterUID, recoveryUID)
	if err != nil {
		return ErrServiceRuntimeInvalid
	}
	server, err := NewServer(Config{StreamID: runtime.StreamID}, runtime.Repository, runtime.Verifier, peers)
	if err != nil {
		return ErrServiceRuntimeInvalid
	}
	listener, err := listenServiceSocket(socketPath)
	if err != nil {
		return ErrServiceSocketInvalid
	}
	defer listener.Close()
	return server.Serve(ctx, listener)
}
