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

var (
	ErrImmutableSDKRequestRejected = errors.New("immutable store SDK request rejected")
	ErrImmutableSDKUnavailable     = errors.New("immutable store SDK unavailable")
	ErrImmutableSDKResponseInvalid = errors.New("immutable store SDK response invalid")
)

type ossSDKAPI interface {
	GetBucketWorm(context.Context, *alioss.GetBucketWormRequest, ...func(*alioss.Options)) (*alioss.GetBucketWormResult, error)
	GetBucketVersioning(context.Context, *alioss.GetBucketVersioningRequest, ...func(*alioss.Options)) (*alioss.GetBucketVersioningResult, error)
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

func NewOSSSDKImmutableClient(bucket string, client *alioss.Client) (*OSSSDKImmutableClient, error) {
	if client == nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	return newOSSSDKImmutableClient(bucket, client)
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
		return nil, ErrImmutableSDKUnavailable
	}
	if result == nil {
		return nil, ErrImmutableSDKResponseInvalid
	}
	return readBoundedSDKBody(result.Body, result.StatusCode)
}

type cosBucketSDKAPI interface {
	GetObjectLockConfiguration(context.Context) (*tencentcos.BucketGetObjectLockResult, *tencentcos.Response, error)
	GetVersioning(context.Context) (*tencentcos.BucketGetVersionResult, *tencentcos.Response, error)
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

func NewCOSSDKImmutableClient(bucket string, client *tencentcos.Client) (*COSSDKImmutableClient, error) {
	if client == nil || client.Bucket == nil || client.Object == nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	return newCOSSDKImmutableClient(bucket, client.Bucket, client.Object)
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

func validSDKCall(ctx context.Context, bucket, expected string, available bool) bool {
	return ctx != nil && ctx.Err() == nil && available && bucket == expected && bucketPattern.MatchString(bucket)
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
