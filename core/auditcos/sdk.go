package auditcos

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	tencentcos "github.com/tencentyun/cos-go-sdk-v5"
	"github.com/tyj1987/broker/core/auditanchor"
)

const (
	ImmutableListMaxKeys = auditanchor.ImmutableListMaxKeys
	AuditObjectMaxBytes  = auditanchor.AuditObjectMaxBytes
)

type ObjectKeyPage = auditanchor.ObjectKeyPage
type COSObjectLockState = auditanchor.COSObjectLockState
type COSCreateObjectRequest = auditanchor.COSCreateObjectRequest
type COSObjectRetention = auditanchor.COSObjectRetention
type ObjectCreateResult = auditanchor.ObjectCreateResult

const COSComplianceMode = auditanchor.COSComplianceMode

var (
	ErrImmutableSDKRequestRejected = auditanchor.ErrImmutableSDKRequestRejected
	ErrImmutableSDKUnavailable     = auditanchor.ErrImmutableSDKUnavailable
	ErrImmutableSDKResponseInvalid = auditanchor.ErrImmutableSDKResponseInvalid
	ErrImmutableObjectNotFound     = auditanchor.ErrImmutableObjectNotFound
	bucketPattern                  = regexp.MustCompile(`^([a-z0-9]|[a-z0-9][a-z0-9-]{0,48}[a-z0-9])-[0-9]{5,20}$`)
	regionPattern                  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
)

type cosBucketSDKAPI interface {
	GetObjectLockConfiguration(context.Context) (*tencentcos.BucketGetObjectLockResult, *tencentcos.Response, error)
	GetVersioning(context.Context) (*tencentcos.BucketGetVersionResult, *tencentcos.Response, error)
	Get(context.Context, *tencentcos.BucketGetOptions) (*tencentcos.BucketGetResult, *tencentcos.Response, error)
	GetObjectVersions(context.Context, *tencentcos.BucketGetObjectVersionsOptions) (*tencentcos.BucketGetObjectVersionsResult, *tencentcos.Response, error)
}

type cosObjectSDKAPI interface {
	Get(context.Context, string, *tencentcos.ObjectGetOptions, ...string) (*tencentcos.Response, error)
	Put(context.Context, string, io.Reader, *tencentcos.ObjectPutOptions) (*tencentcos.Response, error)
	GetRetention(context.Context, string, *tencentcos.ObjectGetRetentionOptions) (*tencentcos.ObjectGetRetentionResult, *tencentcos.Response, error)
}

// COSSDKImmutableClient is bound to one Tencent COS bucket. Existing objects
// are detected before creation and every new object receives COMPLIANCE
// retention in the same PutObject request. The primary OSS create-only write
// remains the cross-cloud serialization point.
type COSSDKImmutableClient struct {
	bucket    string
	bucketAPI cosBucketSDKAPI
	objectAPI cosObjectSDKAPI
}

func NewCOSSDKImmutableClient(bucket, region string, client *tencentcos.Client) (*COSSDKImmutableClient, error) {
	if client == nil || client.Bucket == nil || client.Object == nil ||
		!validCOSBucketEndpoint(bucket, region, client.BaseURL) {
		return nil, ErrImmutableSDKRequestRejected
	}
	return newCOSSDKImmutableClient(bucket, client.Bucket, client.Object)
}

func validCOSBucketEndpoint(bucket, region string, baseURL *tencentcos.BaseURL) bool {
	if !validCOSBucketAndRegion(bucket, region) || baseURL == nil || baseURL.BucketURL == nil {
		return false
	}
	endpoint := baseURL.BucketURL
	expectedHost := expectedCOSBucketHost(bucket, region)
	return endpoint.Scheme == "https" && endpoint.Host == expectedHost && endpoint.Hostname() == expectedHost &&
		endpoint.Port() == "" && endpoint.User == nil && (endpoint.Path == "" || endpoint.Path == "/") &&
		endpoint.RawPath == "" && endpoint.RawQuery == "" && endpoint.Fragment == "" && endpoint.Opaque == "" &&
		!endpoint.ForceQuery && endpoint.IsAbs()
}

func expectedCOSBucketHost(bucket, region string) string {
	if !validCOSBucketAndRegion(bucket, region) {
		return ""
	}
	return bucket + ".cos." + region + "." + cosEndpointSuffix
}

func validCOSBucketAndRegion(bucket, region string) bool {
	return validCOSBucket(bucket) && regionPattern.MatchString(region)
}

func validCOSBucket(bucket string) bool {
	return len(bucket) <= 60 && bucketPattern.MatchString(bucket)
}

func newCOSSDKImmutableClient(bucket string, bucketAPI cosBucketSDKAPI, objectAPI cosObjectSDKAPI) (*COSSDKImmutableClient, error) {
	if !validCOSBucket(bucket) || bucketAPI == nil || objectAPI == nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	return &COSSDKImmutableClient{bucket: bucket, bucketAPI: bucketAPI, objectAPI: objectAPI}, nil
}

func (client *COSSDKImmutableClient) InspectObjectLock(ctx context.Context, bucket string) (COSObjectLockState, error) {
	if !validSDKCall(ctx, bucket, cosClientBucket(client), client != nil && client.bucketAPI != nil) {
		return COSObjectLockState{}, ErrImmutableSDKRequestRejected
	}
	lock, lockResponse, err := client.bucketAPI.GetObjectLockConfiguration(ctx)
	if err != nil {
		return COSObjectLockState{}, ErrImmutableSDKUnavailable
	}
	if lock == nil || !validCOSResponse(lockResponse) {
		return COSObjectLockState{}, ErrImmutableSDKResponseInvalid
	}
	if ctx.Err() != nil {
		return COSObjectLockState{}, ErrImmutableSDKRequestRejected
	}
	versioning, versioningResponse, err := client.bucketAPI.GetVersioning(ctx)
	if err != nil {
		return COSObjectLockState{}, ErrImmutableSDKUnavailable
	}
	if versioning == nil || !validCOSResponse(versioningResponse) {
		return COSObjectLockState{}, ErrImmutableSDKResponseInvalid
	}
	return COSObjectLockState{
		Enabled:         lock.ObjectLockEnabled == "Enabled",
		VersioningState: versioning.Status,
	}, nil
}

func (client *COSSDKImmutableClient) CreateObject(ctx context.Context, request COSCreateObjectRequest) (ObjectCreateResult, error) {
	if !validCOSCreateCall(ctx, client, request) {
		return ObjectCreateResult{}, ErrImmutableSDKRequestRejected
	}
	existing, err := client.objectAPI.Get(ctx, request.Key, nil)
	if err == nil {
		if !validCOSResponse(existing) || existing.Body == nil || existing.Body.Close() != nil {
			return ObjectCreateResult{}, ErrImmutableSDKResponseInvalid
		}
		return ObjectCreateResult{Status: "exists"}, nil
	}
	if !tencentcos.IsNotFoundError(err) {
		return ObjectCreateResult{}, ErrImmutableSDKUnavailable
	}
	if ctx.Err() != nil {
		return ObjectCreateResult{}, ErrImmutableSDKRequestRejected
	}
	response, err := client.putObject(ctx, request)
	if err != nil {
		return ObjectCreateResult{}, ErrImmutableSDKUnavailable
	}
	if !validCOSResponse(response) {
		return ObjectCreateResult{}, ErrImmutableSDKResponseInvalid
	}
	return ObjectCreateResult{Status: "created"}, nil
}

func validCOSCreateCall(ctx context.Context, client *COSSDKImmutableClient, request COSCreateObjectRequest) bool {
	return validSDKCall(ctx, request.Bucket, cosClientBucket(client), client != nil && client.objectAPI != nil) &&
		validSDKObjectKey(request.Key) && len(request.Body) > 0 && len(request.Body) <= AuditObjectMaxBytes &&
		request.ContentType == "application/json" && request.StorageClass == "STANDARD" &&
		request.LockMode == COSComplianceMode && request.RetainUntil.Location() == time.UTC &&
		!request.RetainUntil.IsZero() && request.RetainUntil.Nanosecond() == 0
}

func (client *COSSDKImmutableClient) putObject(ctx context.Context, request COSCreateObjectRequest) (*tencentcos.Response, error) {
	headers := make(http.Header)
	headers.Set("x-cos-object-lock-mode", request.LockMode)
	headers.Set("x-cos-object-lock-retain-until-date", request.RetainUntil.Format(time.RFC3339))
	return client.objectAPI.Put(ctx, request.Key, bytes.NewReader(bytes.Clone(request.Body)), &tencentcos.ObjectPutOptions{
		ObjectPutHeaderOptions: &tencentcos.ObjectPutHeaderOptions{
			ContentType: request.ContentType, ContentLength: int64(len(request.Body)),
			XCosStorageClass: request.StorageClass, XOptionHeader: &headers,
		},
	})
}

func (client *COSSDKImmutableClient) ReadObject(ctx context.Context, bucket, key string) ([]byte, error) {
	if !validSDKCall(ctx, bucket, cosClientBucket(client), client != nil && client.objectAPI != nil) || !validSDKObjectKey(key) {
		return nil, ErrImmutableSDKRequestRejected
	}
	response, err := client.objectAPI.Get(ctx, key, nil)
	if err != nil {
		if tencentcos.IsNotFoundError(err) {
			return nil, ErrImmutableObjectNotFound
		}
		return nil, ErrImmutableSDKUnavailable
	}
	if response == nil {
		return nil, ErrImmutableSDKResponseInvalid
	}
	value, readErr := readBoundedSDKBody(response.Body)
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode != http.StatusOK {
		return nil, ErrImmutableSDKResponseInvalid
	}
	return value, nil
}

func (client *COSSDKImmutableClient) ReadObjectRetention(ctx context.Context, bucket, key string) (COSObjectRetention, error) {
	if !validSDKCall(ctx, bucket, cosClientBucket(client), client != nil && client.objectAPI != nil) || !validSDKObjectKey(key) {
		return COSObjectRetention{}, ErrImmutableSDKRequestRejected
	}
	result, response, err := client.objectAPI.GetRetention(ctx, key, nil)
	if err != nil {
		return COSObjectRetention{}, ErrImmutableSDKUnavailable
	}
	if result == nil || !validCOSResponse(response) {
		return COSObjectRetention{}, ErrImmutableSDKResponseInvalid
	}
	retainUntil, err := time.Parse(time.RFC3339, result.RetainUntilDate)
	if err != nil {
		return COSObjectRetention{}, ErrImmutableSDKResponseInvalid
	}
	return COSObjectRetention{Mode: result.Mode, RetainUntil: retainUntil}, nil
}

// ListObjectKeys exposes one fixed-bucket COS listing page and uses Marker only
// as the opaque-free resume position. The method never accepts an endpoint,
// delimiter, header or provider-specific query option from its caller.
func (client *COSSDKImmutableClient) ListObjectKeys(ctx context.Context, bucket, prefix, after string, limit int) (ObjectKeyPage, error) {
	if !validSDKListCall(ctx, bucket, cosClientBucket(client), prefix, after, limit, client != nil && client.bucketAPI != nil) {
		return ObjectKeyPage{}, ErrImmutableSDKRequestRejected
	}
	result, response, err := client.bucketAPI.Get(ctx, &tencentcos.BucketGetOptions{
		Prefix: prefix, Marker: after, MaxKeys: limit,
	})
	if err != nil {
		return ObjectKeyPage{}, ErrImmutableSDKUnavailable
	}
	if ctx.Err() != nil {
		return ObjectKeyPage{}, ErrImmutableSDKRequestRejected
	}
	if result == nil || !validCOSResponse(response) || result.Name != bucket || result.Prefix != prefix ||
		result.Marker != after || result.MaxKeys != limit || len(result.Contents) > limit ||
		len(result.CommonPrefixes) != 0 || result.Delimiter != "" || result.EncodingType != "" {
		return ObjectKeyPage{}, ErrImmutableSDKResponseInvalid
	}
	keys, valid := validatedCOSObjectKeys(result.Contents, prefix, after)
	if !valid || (result.IsTruncated && (len(keys) == 0 || result.NextMarker == "")) ||
		(!result.IsTruncated && result.NextMarker != "") {
		return ObjectKeyPage{}, ErrImmutableSDKResponseInvalid
	}
	page := ObjectKeyPage{Keys: keys, Truncated: result.IsTruncated}
	if page.Truncated {
		page.NextAfter = keys[len(keys)-1]
	}
	return page, nil
}

func validSDKCall(ctx context.Context, bucket, expected string, available bool) bool {
	return ctx != nil && ctx.Err() == nil && available && bucket == expected && validCOSBucket(bucket)
}

func validSDKListCall(ctx context.Context, bucket, expected, prefix, after string, limit int, available bool) bool {
	return validSDKCall(ctx, bucket, expected, available) && validSDKObjectPrefix(prefix) &&
		(after == "" || validSDKObjectKey(after) && strings.HasPrefix(after, prefix)) &&
		limit >= 1 && limit <= ImmutableListMaxKeys
}

func validSDKObjectPrefix(prefix string) bool {
	return len(prefix) >= 2 && len(prefix) <= 1000 && strings.HasSuffix(prefix, "/") &&
		!strings.HasPrefix(prefix, "/") && !strings.Contains(prefix, "\\") &&
		!strings.Contains(prefix, "..") && !strings.Contains(prefix, "//")
}

func validatedCOSObjectKeys(contents []tencentcos.Object, prefix, after string) ([]string, bool) {
	keys := make([]string, 0, len(contents))
	for _, object := range contents {
		if object.Size < 1 || object.Size > AuditObjectMaxBytes ||
			!appendValidatedObjectKey(&keys, object.Key, prefix, after) {
			return nil, false
		}
	}
	return keys, true
}

func appendValidatedObjectKey(keys *[]string, key, prefix, after string) bool {
	if !validSDKObjectKey(key) || !strings.HasPrefix(key, prefix) || key <= after ||
		(len(*keys) > 0 && key <= (*keys)[len(*keys)-1]) {
		return false
	}
	*keys = append(*keys, key)
	return true
}

func equalOptional(value *string, expected string) bool {
	return expected == "" && (value == nil || *value == "") || value != nil && *value == expected
}

func validSDKObjectKey(key string) bool {
	return len(key) > 0 && len(key) <= 1024 && !strings.HasPrefix(key, "/") &&
		!strings.Contains(key, "\\") && !strings.Contains(key, "..") && !strings.Contains(key, "//")
}

func validCOSResponse(response *tencentcos.Response) bool {
	return response != nil && response.Response != nil && response.StatusCode == http.StatusOK
}

func readBoundedSDKBody(body io.ReadCloser) ([]byte, error) {
	if body == nil {
		return nil, ErrImmutableSDKResponseInvalid
	}
	value, readErr := io.ReadAll(io.LimitReader(body, AuditObjectMaxBytes+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrImmutableSDKUnavailable
	}
	if len(value) > AuditObjectMaxBytes {
		return nil, ErrImmutableSDKResponseInvalid
	}
	return value, nil
}

func cosClientBucket(client *COSSDKImmutableClient) string {
	if client == nil {
		return ""
	}
	return client.bucket
}

func ptr[T any](value T) *T { return &value }

func enabled(value *bool) bool { return value != nil && *value }
