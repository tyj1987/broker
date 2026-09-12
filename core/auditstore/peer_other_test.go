//go:build !linux

package auditstore

import "testing"

func TestOSPeerAuthorizerFailsClosedOffLinux(t *testing.T) {
	if authorizer, err := NewOSPeerAuthorizer(1000, 1001); err == nil || authorizer != nil {
		t.Fatal("unsupported peer credential implementation was accepted")
	}
}
