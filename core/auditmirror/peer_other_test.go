//go:build !linux

package auditmirror

import "testing"

func TestOSPeerTransportFailsClosedOutsideLinux(t *testing.T) {
	binding := testBinding(t)
	if authorizer, err := NewOSPeerAuthorizer(1001); authorizer != nil || err == nil {
		t.Fatalf("authorizer = %#v, %v", authorizer, err)
	}
	if client, err := NewOSUnixClient(binding, 1002); client != nil || err == nil {
		t.Fatalf("client = %#v, %v", client, err)
	}
}
