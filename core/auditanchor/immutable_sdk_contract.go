package auditanchor

import "errors"

const ImmutableListMaxKeys = 1000

type ObjectKeyPage struct {
	Keys      []string
	NextAfter string
	Truncated bool
}

var (
	ErrImmutableSDKRequestRejected = errors.New("immutable store SDK request rejected")
	ErrImmutableSDKUnavailable     = errors.New("immutable store SDK unavailable")
	ErrImmutableSDKResponseInvalid = errors.New("immutable store SDK response invalid")
	ErrImmutableObjectNotFound     = errors.New("immutable store object not found")
)
