//go:build !linux

package githubsigner

import "testing"

func TestOSPeerAuthorizerFailsClosedOffLinux(t *testing.T) {
	if authorizer, err := NewOSPeerAuthorizer(1000); err == nil || authorizer != nil {
		t.Fatal("unsupported peer credential implementation was accepted")
	}
}
