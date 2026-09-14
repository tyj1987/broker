package auditcos

import (
	"context"
	"errors"
	"regexp"

	tencentcos "github.com/tencentyun/cos-go-sdk-v5"
	"github.com/tyj1987/broker/core/auditmirrorworker"
)

const immutableVersionProbeLimit = 2

var cosVersionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$`)

// CreateVersionedObject is the mirror worker's create-only COS operation. It
// accepts an already-bound typed request, captures the provider's exact version
// ID and rejects any history that is not a single, current immutable version.
func (client *COSSDKImmutableClient) CreateVersionedObject(ctx context.Context, request COSCreateObjectRequest) (auditmirrorworker.COSCreateResult, error) {
	if !validCOSCreateCall(ctx, client, request) {
		return auditmirrorworker.COSCreateResult{}, ErrImmutableSDKRequestRejected
	}
	versionID, err := client.ResolveObjectVersion(ctx, request.Bucket, request.Key)
	if err == nil {
		return auditmirrorworker.COSCreateResult{Status: "exists", VersionID: versionID}, nil
	}
	if !errors.Is(err, ErrImmutableObjectNotFound) {
		return auditmirrorworker.COSCreateResult{}, err
	}
	if ctx.Err() != nil {
		return auditmirrorworker.COSCreateResult{}, ErrImmutableSDKRequestRejected
	}
	response, err := client.putObject(ctx, request)
	if err != nil {
		return auditmirrorworker.COSCreateResult{}, ErrImmutableSDKUnavailable
	}
	if !validCOSResponse(response) {
		return auditmirrorworker.COSCreateResult{}, ErrImmutableSDKResponseInvalid
	}
	versionID = response.Header.Get("x-cos-version-id")
	if !validCOSVersionID(versionID) {
		return auditmirrorworker.COSCreateResult{}, ErrImmutableSDKResponseInvalid
	}
	resolved, err := client.ResolveObjectVersion(ctx, request.Bucket, request.Key)
	if err != nil {
		return auditmirrorworker.COSCreateResult{}, normalizeVersionBindingError(err)
	}
	if resolved != versionID {
		return auditmirrorworker.COSCreateResult{}, ErrImmutableSDKResponseInvalid
	}
	return auditmirrorworker.COSCreateResult{Status: "created", VersionID: versionID}, nil
}

// ResolveObjectVersion returns a version only when the complete exact-key
// history is unambiguous: one non-null current version, no delete marker and no
// truncated continuation. This turns external overwrites into a fail-closed
// integrity error instead of guessing that the latest object is authoritative.
func (client *COSSDKImmutableClient) ResolveObjectVersion(ctx context.Context, bucket, key string) (string, error) {
	if !validSDKCall(ctx, bucket, cosClientBucket(client), client != nil && client.bucketAPI != nil) || !validSDKObjectKey(key) {
		return "", ErrImmutableSDKRequestRejected
	}
	result, response, err := client.bucketAPI.GetObjectVersions(ctx, &tencentcos.BucketGetObjectVersionsOptions{
		Prefix: key, MaxKeys: immutableVersionProbeLimit,
	})
	if err != nil {
		return "", ErrImmutableSDKUnavailable
	}
	if ctx.Err() != nil {
		return "", ErrImmutableSDKRequestRejected
	}
	if !validExactVersionResult(result, response, bucket, key) {
		return "", ErrImmutableSDKResponseInvalid
	}
	if len(result.Version) == 0 {
		return "", ErrImmutableObjectNotFound
	}
	return result.Version[0].VersionId, nil
}

// ReadObjectVersion binds both the COS request and response to the exact
// version selected by ResolveObjectVersion.
func (client *COSSDKImmutableClient) ReadObjectVersion(ctx context.Context, bucket, key, versionID string) ([]byte, error) {
	if !validSDKCall(ctx, bucket, cosClientBucket(client), client != nil && client.objectAPI != nil) ||
		!validSDKObjectKey(key) || !validCOSVersionID(versionID) {
		return nil, ErrImmutableSDKRequestRejected
	}
	response, err := client.objectAPI.Get(ctx, key, nil, versionID)
	if err != nil {
		if tencentcos.IsNotFoundError(err) {
			return nil, ErrImmutableObjectNotFound
		}
		return nil, ErrImmutableSDKUnavailable
	}
	if !validCOSResponse(response) || response.Header.Get("x-cos-version-id") != versionID {
		return nil, ErrImmutableSDKResponseInvalid
	}
	return readBoundedSDKBody(response.Body)
}

// ReadObjectRetentionVersion verifies that the requested version is the only
// exact-key version immediately before and after reading COS retention. COS's
// retention API does not accept a version selector, so any concurrent or
// historical ambiguity is rejected rather than attributed to a guessed
// version.
func (client *COSSDKImmutableClient) ReadObjectRetentionVersion(ctx context.Context, bucket, key, versionID string) (COSObjectRetention, error) {
	if !validCOSVersionID(versionID) {
		return COSObjectRetention{}, ErrImmutableSDKRequestRejected
	}
	before, err := client.ResolveObjectVersion(ctx, bucket, key)
	if err != nil || before != versionID {
		return COSObjectRetention{}, normalizeVersionBindingError(err)
	}
	retention, err := client.ReadObjectRetention(ctx, bucket, key)
	if err != nil {
		return COSObjectRetention{}, err
	}
	after, err := client.ResolveObjectVersion(ctx, bucket, key)
	if err != nil || after != versionID {
		return COSObjectRetention{}, normalizeVersionBindingError(err)
	}
	return retention, nil
}

func validExactVersionResult(result *tencentcos.BucketGetObjectVersionsResult, response *tencentcos.Response, bucket, key string) bool {
	if result == nil || !validCOSResponse(response) || result.Name != bucket || result.Prefix != key ||
		result.KeyMarker != "" || result.VersionIdMarker != "" || result.MaxKeys != immutableVersionProbeLimit ||
		result.Delimiter != "" || result.EncodingType != "" || result.IsTruncated || result.NextKeyMarker != "" ||
		result.NextVersionIdMarker != "" || len(result.CommonPrefixes) != 0 || len(result.DeleteMarker) != 0 ||
		len(result.Version) > 1 {
		return false
	}
	if len(result.Version) == 0 {
		return true
	}
	version := result.Version[0]
	return version.Key == key && version.IsLatest && validCOSVersionID(version.VersionId) &&
		version.Size > 0 && version.Size <= AuditObjectMaxBytes && version.StorageClass == "STANDARD"
}

func validCOSVersionID(value string) bool {
	return value != "null" && cosVersionIDPattern.MatchString(value)
}

func normalizeVersionBindingError(err error) error {
	if errors.Is(err, ErrImmutableSDKRequestRejected) {
		return ErrImmutableSDKRequestRejected
	}
	if errors.Is(err, ErrImmutableSDKUnavailable) {
		return ErrImmutableSDKUnavailable
	}
	return ErrImmutableSDKResponseInvalid
}

var _ auditmirrorworker.COSClient = (*COSSDKImmutableClient)(nil)
