package auditanchor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	alioss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	tencentcos "github.com/tencentyun/cos-go-sdk-v5"
)

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

type ossSDKAPI interface {
	GetBucketWorm(context.Context, *alioss.GetBucketWormRequest, ...func(*alioss.Options)) (*alioss.GetBucketWormResult, error)
	GetBucketVersioning(context.Context, *alioss.GetBucketVersioningRequest, ...func(*alioss.Options)) (*alioss.GetBucketVersioningResult, error)
	ListObjectsV2(context.Context, *alioss.ListObjectsV2Request, ...func(*alioss.Options)) (*alioss.ListObjectsV2Result, error)
	PutObject(context.Context, *alioss.PutObjectRequest, ...func(*alioss.Options)) (*alioss.PutObjectResult, error)
	GetObject(context.Context, *alioss.GetObjectRequest, ...func(*alioss.Options)) (*alioss.GetObjectResult, error)
}

// OSSSDKImmutableClient is the narrow Alibaba OSS SDK v2 transport exposed to
// the immutable-store workload. It deliberately has no delete, copy, ACL,
// versioning or retention-policy mutation method.
type OSSSDKImmutableClient struct {
	bucket string
	api    ossSDKAPI
}

func NewOSSSDKImmutableClient(bucket, region string, config *alioss.Config) (*OSSSDKImmutableClient, error) {
	if !validOSSClientConfig(region, config) {
		return nil, ErrImmutableSDKRequestRejected
	}
	safeConfig := config.Copy()
	safeConfig.Region = ptr(region)
	safeConfig.Endpoint = nil
	safeConfig.DisableSSL = ptr(false)
	safeConfig.InsecureSkipVerify = ptr(false)
	safeConfig.EnabledRedirect = ptr(false)
	safeConfig.UsePathStyle = ptr(false)
	safeConfig.UseCName = ptr(false)
	safeConfig.UseVirtualHostedAlias = ptr(false)
	safeConfig.UseDualStackEndpoint = ptr(false)
	safeConfig.UseAccelerateEndpoint = ptr(false)
	safeConfig.UseInternalEndpoint = ptr(enabled(config.UseInternalEndpoint))
	safeConfig.ProxyHost = nil
	safeConfig.ProxyFromEnvironment = ptr(false)
	return newOSSSDKImmutableClient(bucket, alioss.NewClient(&safeConfig))
}

func validOSSClientConfig(region string, config *alioss.Config) bool {
	if !bucketPattern.MatchString(region) || config == nil || config.Region == nil || *config.Region != region ||
		config.Endpoint != nil || enabled(config.DisableSSL) || enabled(config.InsecureSkipVerify) ||
		enabled(config.EnabledRedirect) || enabled(config.UsePathStyle) || enabled(config.UseCName) ||
		enabled(config.UseVirtualHostedAlias) || enabled(config.UseDualStackEndpoint) ||
		enabled(config.UseAccelerateEndpoint) || enabled(config.ProxyFromEnvironment) ||
		(config.ProxyHost != nil && *config.ProxyHost != "") {
		return false
	}
	return true
}

func newOSSSDKImmutableClient(bucket string, api ossSDKAPI) (*OSSSDKImmutableClient, error) {
	if !bucketPattern.MatchString(bucket) || api == nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	return &OSSSDKImmutableClient{bucket: bucket, api: api}, nil
}

func (client *OSSSDKImmutableClient) InspectBucketWORM(ctx context.Context, bucket string) (OSSBucketWORMState, error) {
	if !validSDKCall(ctx, bucket, clientBucket(client), client != nil && client.api != nil) {
		return OSSBucketWORMState{}, ErrImmutableSDKRequestRejected
	}
	worm, err := client.api.GetBucketWorm(ctx, &alioss.GetBucketWormRequest{Bucket: ptr(bucket)})
	if err != nil {
		return OSSBucketWORMState{}, ErrImmutableSDKUnavailable
	}
	if worm == nil || worm.StatusCode != http.StatusOK || worm.WormConfiguration == nil ||
		worm.WormConfiguration.RetentionPeriodInDays == nil {
		return OSSBucketWORMState{}, ErrImmutableSDKResponseInvalid
	}
	if ctx.Err() != nil {
		return OSSBucketWORMState{}, ErrImmutableSDKRequestRejected
	}
	versioning, err := client.api.GetBucketVersioning(ctx, &alioss.GetBucketVersioningRequest{Bucket: ptr(bucket)})
	if err != nil {
		return OSSBucketWORMState{}, ErrImmutableSDKUnavailable
	}
	if versioning == nil || versioning.StatusCode != http.StatusOK {
		return OSSBucketWORMState{}, ErrImmutableSDKResponseInvalid
	}
	versioningState := "Disabled"
	if versioning.VersionStatus != nil && *versioning.VersionStatus != "" {
		versioningState = *versioning.VersionStatus
	}
	return OSSBucketWORMState{
		Status:          string(worm.WormConfiguration.State),
		RetentionDays:   int(*worm.WormConfiguration.RetentionPeriodInDays),
		VersioningState: versioningState,
	}, nil
}

func (client *OSSSDKImmutableClient) CreateObject(ctx context.Context, request OSSCreateObjectRequest) (ObjectCreateResult, error) {
	if !validSDKCall(ctx, request.Bucket, clientBucket(client), client != nil && client.api != nil) ||
		!validSDKObjectKey(request.Key) || len(request.Body) == 0 || len(request.Body) > AuditObjectMaxBytes ||
		request.ContentType != "application/json" || !request.ForbidOverwrite {
		return ObjectCreateResult{}, ErrImmutableSDKRequestRejected
	}
	result, err := client.api.PutObject(ctx, &alioss.PutObjectRequest{
		Bucket:          ptr(request.Bucket),
		Key:             ptr(request.Key),
		Body:            bytes.NewReader(bytes.Clone(request.Body)),
		ContentLength:   ptr(int64(len(request.Body))),
		ContentType:     ptr(request.ContentType),
		ForbidOverwrite: ptr("true"),
	})
	if err != nil {
		var serviceError *alioss.ServiceError
		if errors.As(err, &serviceError) && serviceError.StatusCode == http.StatusConflict &&
			serviceError.Code == "FileAlreadyExists" {
			return ObjectCreateResult{Status: "exists"}, nil
		}
		return ObjectCreateResult{}, ErrImmutableSDKUnavailable
	}
	if result == nil || result.StatusCode != http.StatusOK || result.VersionId != nil {
		return ObjectCreateResult{}, ErrImmutableSDKResponseInvalid
	}
	return ObjectCreateResult{Status: "created"}, nil
}

func (client *OSSSDKImmutableClient) ReadObject(ctx context.Context, bucket, key string) ([]byte, error) {
	if !validSDKCall(ctx, bucket, clientBucket(client), client != nil && client.api != nil) || !validSDKObjectKey(key) {
		return nil, ErrImmutableSDKRequestRejected
	}
	result, err := client.api.GetObject(ctx, &alioss.GetObjectRequest{
		Bucket: ptr(bucket), Key: ptr(key), Range: ptr("bytes=0-16384"),
	})
	if err != nil {
		var serviceError *alioss.ServiceError
		if errors.As(err, &serviceError) && serviceError.StatusCode == http.StatusNotFound {
			return nil, ErrImmutableObjectNotFound
		}
		return nil, ErrImmutableSDKUnavailable
	}
	if result == nil {
		return nil, ErrImmutableSDKResponseInvalid
	}
	return readBoundedSDKBody(result.Body, result.StatusCode)
}

// ListObjectKeys exposes one strictly bounded, lexicographically ordered page
// below the configured audit prefix. The provider continuation token is not
// exposed; callers resume from the last returned key through StartAfter.
func (client *OSSSDKImmutableClient) ListObjectKeys(ctx context.Context, bucket, prefix, after string, limit int) (ObjectKeyPage, error) {
	if !validSDKListCall(ctx, bucket, clientBucket(client), prefix, after, limit, client != nil && client.api != nil) {
		return ObjectKeyPage{}, ErrImmutableSDKRequestRejected
	}
	request := &alioss.ListObjectsV2Request{
		Bucket: ptr(bucket), Prefix: ptr(prefix), MaxKeys: int32(limit), FetchOwner: false,
	}
	if after != "" {
		request.StartAfter = ptr(after)
	}
	result, err := client.api.ListObjectsV2(ctx, request)
	if err != nil {
		return ObjectKeyPage{}, ErrImmutableSDKUnavailable
	}
	if ctx.Err() != nil {
		return ObjectKeyPage{}, ErrImmutableSDKRequestRejected
	}
	if result == nil || result.StatusCode != http.StatusOK || !equalOptional(result.Name, bucket) ||
		!equalOptional(result.Prefix, prefix) || !equalOptional(result.StartAfter, after) ||
		result.MaxKeys != int32(limit) || result.KeyCount != len(result.Contents) ||
		len(result.Contents) > limit || len(result.CommonPrefixes) != 0 ||
		(result.Delimiter != nil && *result.Delimiter != "") {
		return ObjectKeyPage{}, ErrImmutableSDKResponseInvalid
	}
	keys, valid := validatedObjectKeys(result.Contents, prefix, after)
	if !valid || (result.IsTruncated && len(keys) == 0) ||
		(result.IsTruncated && (result.NextContinuationToken == nil || *result.NextContinuationToken == "")) ||
		(!result.IsTruncated && result.NextContinuationToken != nil && *result.NextContinuationToken != "") {
		return ObjectKeyPage{}, ErrImmutableSDKResponseInvalid
	}
	page := ObjectKeyPage{Keys: keys, Truncated: result.IsTruncated}
	if page.Truncated {
		page.NextAfter = keys[len(keys)-1]
	}
	return page, nil
}

type cosBucketSDKAPI interface {
	GetObjectLockConfiguration(context.Context) (*tencentcos.BucketGetObjectLockResult, *tencentcos.Response, error)
	GetVersioning(context.Context) (*tencentcos.BucketGetVersionResult, *tencentcos.Response, error)
	Get(context.Context, *tencentcos.BucketGetOptions) (*tencentcos.BucketGetResult, *tencentcos.Response, error)
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
	if !bucketPattern.MatchString(bucket) || !bucketPattern.MatchString(region) || baseURL == nil || baseURL.BucketURL == nil {
		return false
	}
	endpoint := baseURL.BucketURL
	expectedHost := bucket + ".cos." + region + ".myqcloud.com"
	return endpoint.Scheme == "https" && endpoint.Host == expectedHost && endpoint.Hostname() == expectedHost &&
		endpoint.Port() == "" && endpoint.User == nil && (endpoint.Path == "" || endpoint.Path == "/") &&
		endpoint.RawPath == "" && endpoint.RawQuery == "" && endpoint.Fragment == "" && endpoint.Opaque == "" &&
		!endpoint.ForceQuery && endpoint.IsAbs()
}

func newCOSSDKImmutableClient(bucket string, bucketAPI cosBucketSDKAPI, objectAPI cosObjectSDKAPI) (*COSSDKImmutableClient, error) {
	if !bucketPattern.MatchString(bucket) || bucketAPI == nil || objectAPI == nil {
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
	if !validSDKCall(ctx, request.Bucket, cosClientBucket(client), client != nil && client.objectAPI != nil) ||
		!validSDKObjectKey(request.Key) || len(request.Body) == 0 || len(request.Body) > AuditObjectMaxBytes ||
		request.ContentType != "application/json" || request.StorageClass != "STANDARD" ||
		request.LockMode != COSComplianceMode || request.RetainUntil.Location() != time.UTC || request.RetainUntil.IsZero() {
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
	headers := make(http.Header)
	headers.Set("x-cos-object-lock-mode", request.LockMode)
	headers.Set("x-cos-object-lock-retain-until-date", request.RetainUntil.Format(time.RFC3339))
	response, err := client.objectAPI.Put(ctx, request.Key, bytes.NewReader(bytes.Clone(request.Body)), &tencentcos.ObjectPutOptions{
		ObjectPutHeaderOptions: &tencentcos.ObjectPutHeaderOptions{
			ContentType: request.ContentType, ContentLength: int64(len(request.Body)),
			XCosStorageClass: request.StorageClass, XOptionHeader: &headers,
		},
	})
	if err != nil {
		return ObjectCreateResult{}, ErrImmutableSDKUnavailable
	}
	if !validCOSResponse(response) {
		return ObjectCreateResult{}, ErrImmutableSDKResponseInvalid
	}
	return ObjectCreateResult{Status: "created"}, nil
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
	return readBoundedSDKBody(response.Body, response.StatusCode)
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
	return ctx != nil && ctx.Err() == nil && available && bucket == expected && bucketPattern.MatchString(bucket)
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

func validatedObjectKeys(contents []alioss.ObjectProperties, prefix, after string) ([]string, bool) {
	keys := make([]string, 0, len(contents))
	for _, object := range contents {
		if object.Key == nil || object.Size < 1 || object.Size > AuditObjectMaxBytes ||
			!appendValidatedObjectKey(&keys, *object.Key, prefix, after) {
			return nil, false
		}
	}
	return keys, true
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

func readBoundedSDKBody(body io.ReadCloser, status int) ([]byte, error) {
	if body == nil || status != http.StatusOK {
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

func clientBucket(client *OSSSDKImmutableClient) string {
	if client == nil {
		return ""
	}
	return client.bucket
}

func cosClientBucket(client *COSSDKImmutableClient) string {
	if client == nil {
		return ""
	}
	return client.bucket
}

func ptr[T any](value T) *T { return &value }

func enabled(value *bool) bool { return value != nil && *value }
