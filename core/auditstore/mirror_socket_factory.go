package auditstore

import (
	"context"

	"github.com/tyj1987/broker/core/auditmirror"
)

// AuthenticatedMirrorClientFactory connects only to auditmirror's fixed Unix
// socket and requires the kernel to authenticate the independently configured
// non-root worker UID. It carries no COS endpoint, bucket or credential.
type AuthenticatedMirrorClientFactory struct {
	WorkerUID uint32
}

func (factory AuthenticatedMirrorClientFactory) NewMirror(
	ctx context.Context,
	binding auditmirror.Binding,
) (auditmirror.Client, error) {
	if ctx == nil || ctx.Err() != nil || factory.WorkerUID == 0 {
		return nil, ErrServiceIdentityUnavailable
	}
	client, err := auditmirror.NewOSUnixClient(binding, factory.WorkerUID)
	if err != nil {
		return nil, ErrServiceIdentityUnavailable
	}
	return client, nil
}

var _ MirrorClientFactory = AuthenticatedMirrorClientFactory{}
