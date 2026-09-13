package auditoss

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	alioss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/tyj1987/broker/core/auditanchor"
)

const (
	ImmutableListMaxKeys = auditanchor.ImmutableListMaxKeys
	AuditObjectMaxBytes  = auditanchor.AuditObjectMaxBytes
)

type ObjectKeyPage = auditanchor.ObjectKeyPage
type OSSBucketWORMState = auditanchor.OSSBucketWORMState
type OSSCreateObjectRequest = auditanchor.OSSCreateObjectRequest
type ObjectCreateResult = auditanchor.ObjectCreateResult

var (
	ErrImmutableSDKRequestRejected = auditanchor.ErrImmutableSDKRequestRejected
	ErrImmutableSDKUnavailable     = auditanchor.ErrImmutableSDKUnavailable
	ErrImmutableSDKResponseInvalid = auditanchor.ErrImmutableSDKResponseInvalid
	ErrImmutableObjectNotFound     = auditanchor.ErrImmutableObjectNotFound
	ossContentRangePattern         = regexp.MustCompile(`^bytes ([0-9]+)-([0-9]+)/([0-9]+)$`)
	bucketPattern                  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
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
	value, readErr := readBoundedSDKBody(result.Body)
	if readErr != nil {
		return nil, readErr
	}
	if !validOSSReadResponse(result, len(value)) {
		return nil, ErrImmutableSDKResponseInvalid
	}
	return value, nil
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

func validOSSReadResponse(result *alioss.GetObjectResult, bodyLength int) bool {
	if result == nil || bodyLength < 1 || bodyLength > AuditObjectMaxBytes ||
		result.ContentLength != int64(bodyLength) || result.VersionId != nil {
		return false
	}
	if result.StatusCode == http.StatusOK {
		return result.ContentRange == nil
	}
	if result.StatusCode != http.StatusPartialContent || result.ContentRange == nil {
		return false
	}
	parts := ossContentRangePattern.FindStringSubmatch(*result.ContentRange)
	if len(parts) != 4 {
		return false
	}
	start, startErr := strconv.ParseInt(parts[1], 10, 64)
	end, endErr := strconv.ParseInt(parts[2], 10, 64)
	total, totalErr := strconv.ParseInt(parts[3], 10, 64)
	length := int64(bodyLength)
	return startErr == nil && endErr == nil && totalErr == nil && start == 0 &&
		end == length-1 && total == length
}

func clientBucket(client *OSSSDKImmutableClient) string {
	if client == nil {
		return ""
	}
	return client.bucket
}

func ptr[T any](value T) *T { return &value }

func enabled(value *bool) bool { return value != nil && *value }
