//go:build linux

package auditmirror

import (
	"context"
	"errors"
	"net"
)

func newOSDialer(workerUID uint32) (dialContextFunc, error) {
	return newOSDialerForPath(workerUID, DefaultSocketPath)
}

func newOSDialerForPath(workerUID uint32, expectedPath string) (dialContextFunc, error) {
	if workerUID == 0 {
		return nil, errors.New("audit mirror worker identity must be non-root")
	}
	dialer := &net.Dialer{Timeout: DefaultDeadline}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx == nil || network != "unix" || address != expectedPath {
			return nil, errors.New("audit mirror transport denied")
		}
		connection, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, errors.New("audit mirror unavailable")
		}
		credentials, err := unixPeerCredentials(connection)
		if err != nil || credentials.Uid != workerUID {
			_ = connection.Close()
			return nil, errors.New("audit mirror peer denied")
		}
		return connection, nil
	}, nil
}
