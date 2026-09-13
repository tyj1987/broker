package auditcos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	tencentcos "github.com/tencentyun/cos-go-sdk-v5"
	"github.com/tyj1987/broker/core/auditmirrorworker"
)

func exactVersionResult(versionID string) *tencentcos.BucketGetObjectVersionsResult {
	return &tencentcos.BucketGetObjectVersionsResult{
		Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit,
		Version: []tencentcos.ListVersionsResultVersion{{
			Key: sdkTestKey, VersionId: versionID, IsLatest: true, Size: 512, StorageClass: "STANDARD",
		}},
	}
}

func versionReply(result *tencentcos.BucketGetObjectVersionsResult) cosVersionReply {
	return cosVersionReply{result: result, response: cosResponse(http.StatusOK, nil)}
}

func TestCOSVersionResolutionBindsExactHistory(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	client := newTestCOSClient(t, bucket, object)
	versionID, err := client.ResolveObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey)
	if err != nil || versionID != "version-1" || len(bucket.versionOptions) != 1 {
		t.Fatalf("ResolveObjectVersion() = %q, %v, calls=%d", versionID, err, len(bucket.versionOptions))
	}
	options := bucket.versionOptions[0]
	if options == nil || options.Prefix != sdkTestKey || options.MaxKeys != immutableVersionProbeLimit ||
		options.Delimiter != "" || options.EncodingType != "" || options.KeyMarker != "" ||
		options.VersionIdMarker != "" || options.XOptionHeader != nil {
		t.Fatalf("unexpected version options: %#v", options)
	}

	bucket, object = validCOSSDKFakes()
	bucket.objectVersions = []cosVersionReply{versionReply(&tencentcos.BucketGetObjectVersionsResult{
		Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit,
	})}
	if versionID, err := newTestCOSClient(t, bucket, object).ResolveObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey); versionID != "" || !errors.Is(err, ErrImmutableObjectNotFound) {
		t.Fatalf("missing object = %q, %v", versionID, err)
	}
}

func TestCOSVersionResolutionRejectsAmbiguousOrUnboundHistory(t *testing.T) {
	mutations := map[string]func(*tencentcos.BucketGetObjectVersionsResult, *tencentcos.Response){
		"nil_result": func(_ *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {},
		"wrong_status": func(_ *tencentcos.BucketGetObjectVersionsResult, response *tencentcos.Response) {
			response.StatusCode = http.StatusCreated
		},
		"wrong_bucket": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Name = "other-bucket"
		},
		"wrong_prefix": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Prefix = "other/key"
		},
		"key_marker": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.KeyMarker = "marker"
		},
		"version_marker": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.VersionIdMarker = "version"
		},
		"wrong_limit": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) { result.MaxKeys = 1 },
		"delimiter":   func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) { result.Delimiter = "/" },
		"encoding": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.EncodingType = "url"
		},
		"truncated": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.IsTruncated = true
		},
		"next_key": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.NextKeyMarker = sdkTestKey
		},
		"next_version": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.NextVersionIdMarker = "next"
		},
		"common_prefix": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.CommonPrefixes = []string{"x/"}
		},
		"delete_marker": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.DeleteMarker = []tencentcos.ListVersionsResultDeleteMarker{{Key: sdkTestKey, VersionId: "delete-1", IsLatest: true}}
		},
		"multiple_versions": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Version = append(result.Version, result.Version[0])
		},
		"wrong_key": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Version[0].Key = sdkTestKey + "-other"
		},
		"not_latest": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Version[0].IsLatest = false
		},
		"null_version": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Version[0].VersionId = "null"
		},
		"empty_object": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Version[0].Size = 0
		},
		"oversized": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Version[0].Size = AuditObjectMaxBytes + 1
		},
		"storage_class": func(result *tencentcos.BucketGetObjectVersionsResult, _ *tencentcos.Response) {
			result.Version[0].StorageClass = "ARCHIVE"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bucket, object := validCOSSDKFakes()
			result := exactVersionResult("version-1")
			response := cosResponse(http.StatusOK, nil)
			if name == "nil_result" {
				result = nil
			} else {
				mutate(result, response)
			}
			bucket.objectVersions = []cosVersionReply{{result: result, response: response}}
			if _, err := newTestCOSClient(t, bucket, object).ResolveObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey); !errors.Is(err, ErrImmutableSDKResponseInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	bucket, object := validCOSSDKFakes()
	bucket.objectVersions = []cosVersionReply{{err: errors.New("provider detail")}}
	if _, err := newTestCOSClient(t, bucket, object).ResolveObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey); !errors.Is(err, ErrImmutableSDKUnavailable) {
		t.Fatalf("provider error = %v", err)
	}
	bucket, object = validCOSSDKFakes()
	lateContext, lateCancel := context.WithCancel(context.Background())
	bucket.afterVersions = lateCancel
	if _, err := newTestCOSClient(t, bucket, object).ResolveObjectVersion(lateContext, cosSDKTestBucket, sdkTestKey); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("late cancellation error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := newTestCOSClient(t, bucket, object)
	for _, call := range []func() error{
		func() error { _, err := client.ResolveObjectVersion(ctx, cosSDKTestBucket, sdkTestKey); return err },
		func() error {
			_, err := client.ResolveObjectVersion(context.Background(), "other-bucket", sdkTestKey)
			return err
		},
		func() error {
			_, err := client.ResolveObjectVersion(context.Background(), cosSDKTestBucket, "bad//key")
			return err
		},
		func() error {
			_, err := (*COSSDKImmutableClient)(nil).ResolveObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey)
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrImmutableSDKRequestRejected) {
			t.Fatalf("request error = %v", err)
		}
	}
}

func TestCOSVersionedCreateReturnsAndRechecksProviderVersion(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	client := newTestCOSClient(t, bucket, object)
	result, err := client.CreateVersionedObject(context.Background(), validCOSCreateRequest())
	if err != nil || result != (auditmirrorworker.COSCreateResult{Status: "exists", VersionID: "version-1"}) || object.putKey != "" {
		t.Fatalf("existing = %#v, %v, put=%q", result, err, object.putKey)
	}

	bucket, object = validCOSSDKFakes()
	bucket.objectVersions = []cosVersionReply{
		versionReply(&tencentcos.BucketGetObjectVersionsResult{Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit}),
		versionReply(exactVersionResult("version-2")),
	}
	object.putResponse.Header.Set("x-cos-version-id", "version-2")
	request := validCOSCreateRequest()
	result, err = newTestCOSClient(t, bucket, object).CreateVersionedObject(context.Background(), request)
	if err != nil || result != (auditmirrorworker.COSCreateResult{Status: "created", VersionID: "version-2"}) || len(bucket.versionOptions) != 2 {
		t.Fatalf("created = %#v, %v, probes=%d", result, err, len(bucket.versionOptions))
	}
	if object.putKey != sdkTestKey || !bytes.Equal(object.putBody, request.Body) {
		t.Fatalf("unexpected put: key=%q body=%q", object.putKey, object.putBody)
	}
}

func TestCOSVersionedCreateFailsClosed(t *testing.T) {
	tests := map[string]func(*fakeCOSBucketSDK, *fakeCOSObjectSDK){
		"lookup_unavailable": func(bucket *fakeCOSBucketSDK, _ *fakeCOSObjectSDK) {
			bucket.objectVersions = []cosVersionReply{{err: errors.New("detail")}}
		},
		"put_unavailable": func(bucket *fakeCOSBucketSDK, object *fakeCOSObjectSDK) {
			bucket.objectVersions = []cosVersionReply{versionReply(&tencentcos.BucketGetObjectVersionsResult{Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit})}
			object.putErr = errors.New("detail")
		},
		"put_response": func(bucket *fakeCOSBucketSDK, object *fakeCOSObjectSDK) {
			bucket.objectVersions = []cosVersionReply{versionReply(&tencentcos.BucketGetObjectVersionsResult{Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit})}
			object.putResponse = nil
		},
		"missing_version_header": func(bucket *fakeCOSBucketSDK, object *fakeCOSObjectSDK) {
			bucket.objectVersions = []cosVersionReply{versionReply(&tencentcos.BucketGetObjectVersionsResult{Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit})}
			object.putResponse.Header.Del("x-cos-version-id")
		},
		"post_put_mismatch": func(bucket *fakeCOSBucketSDK, object *fakeCOSObjectSDK) {
			bucket.objectVersions = []cosVersionReply{
				versionReply(&tencentcos.BucketGetObjectVersionsResult{Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit}),
				versionReply(exactVersionResult("other-version")),
			}
			object.putResponse.Header.Set("x-cos-version-id", "version-2")
		},
		"post_put_unavailable": func(bucket *fakeCOSBucketSDK, object *fakeCOSObjectSDK) {
			bucket.objectVersions = []cosVersionReply{
				versionReply(&tencentcos.BucketGetObjectVersionsResult{Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit}),
				{err: errors.New("detail")},
			}
			object.putResponse.Header.Set("x-cos-version-id", "version-2")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			bucket, object := validCOSSDKFakes()
			mutate(bucket, object)
			if _, err := newTestCOSClient(t, bucket, object).CreateVersionedObject(context.Background(), validCOSCreateRequest()); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
	bucket, object := validCOSSDKFakes()
	request := validCOSCreateRequest()
	request.Body = nil
	if _, err := newTestCOSClient(t, bucket, object).CreateVersionedObject(context.Background(), request); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid request error = %v", err)
	}
}

func TestCOSExactVersionReadBindsRequestAndResponse(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	object.getResponse.Header.Set("x-cos-version-id", "version-1")
	client := newTestCOSClient(t, bucket, object)
	value, err := client.ReadObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey, "version-1")
	if err != nil || string(value) != "anchor" || len(object.getVersionIDs) != 1 ||
		len(object.getVersionIDs[0]) != 1 || object.getVersionIDs[0][0] != "version-1" {
		t.Fatalf("ReadObjectVersion() = %q, %v, ids=%#v", value, err, object.getVersionIDs)
	}

	cases := map[string]func(*fakeCOSObjectSDK){
		"provider":      func(value *fakeCOSObjectSDK) { value.getErr = errors.New("detail") },
		"not_found":     func(value *fakeCOSObjectSDK) { value.getErr = cosNotFound(); value.getResponse = nil },
		"nil_response":  func(value *fakeCOSObjectSDK) { value.getResponse = nil },
		"wrong_version": func(value *fakeCOSObjectSDK) { value.getResponse.Header.Set("x-cos-version-id", "other") },
		"oversized": func(value *fakeCOSObjectSDK) {
			value.getResponse = cosResponse(http.StatusOK, io.NopCloser(bytes.NewReader(make([]byte, AuditObjectMaxBytes+1))))
			value.getResponse.Header.Set("x-cos-version-id", "version-1")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, o := validCOSSDKFakes()
			o.getResponse.Header.Set("x-cos-version-id", "version-1")
			mutate(o)
			if _, err := newTestCOSClient(t, b, o).ReadObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey, "version-1"); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
	if _, err := client.ReadObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey, "null"); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid version error = %v", err)
	}
}

func TestCOSVersionRetentionRejectsBindingChanges(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	client := newTestCOSClient(t, bucket, object)
	retention, err := client.ReadObjectRetentionVersion(context.Background(), cosSDKTestBucket, sdkTestKey, "version-1")
	if err != nil || retention.Mode != COSComplianceMode || len(bucket.versionOptions) != 2 {
		t.Fatalf("retention = %#v, %v, probes=%d", retention, err, len(bucket.versionOptions))
	}

	bucket, object = validCOSSDKFakes()
	object.afterRetention = func() {
		bucket.objectVersions = append(bucket.objectVersions, versionReply(exactVersionResult("version-2")))
	}
	if _, err := newTestCOSClient(t, bucket, object).ReadObjectRetentionVersion(context.Background(), cosSDKTestBucket, sdkTestKey, "version-1"); !errors.Is(err, ErrImmutableSDKResponseInvalid) {
		t.Fatalf("changed binding error = %v", err)
	}

	if _, err := client.ReadObjectRetentionVersion(context.Background(), cosSDKTestBucket, sdkTestKey, "null"); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid version error = %v", err)
	}
	bucket, object = validCOSSDKFakes()
	bucket.objectVersions = []cosVersionReply{{err: errors.New("detail")}}
	if _, err := newTestCOSClient(t, bucket, object).ReadObjectRetentionVersion(context.Background(), cosSDKTestBucket, sdkTestKey, "version-1"); !errors.Is(err, ErrImmutableSDKUnavailable) {
		t.Fatalf("provider error = %v", err)
	}
}
