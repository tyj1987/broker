//go:build !linux

package auditstore

import "net"

func listenServiceSocket(string) (net.Listener, error) {
	return nil, ErrServiceSocketInvalid
}
