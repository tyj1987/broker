package auditcos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	tencentcos "github.com/tencentyun/cos-go-sdk-v5"
)

const (
	cosSDKTestBucket = "broker-audit-mirror-1250000000"
	cosSDKTestRegion = "ap-guangzhou"
	sdkTestKey       = "audit-anchors/v1/stream/00000000000000000001-anchor.json"
)

type fakeCOSBucketSDK struct {
	lockResult      *tencentcos.BucketGetObjectLockResult
	lockResponse    *tencentcos.Response
	lockErr         error
	versionResult   *tencentcos.BucketGetVersionResult
	versionResponse *tencentcos.Response
	versionErr      error
	listResult      *tencentcos.BucketGetResult
	listResponse    *tencentcos.Response
	listErr         error
	listOptions     *tencentcos.BucketGetOptions
	objectVersions  []cosVersionReply
	versionOptions  []*tencentcos.BucketGetObjectVersionsOptions
	afterLock       func()
	afterList       func()
	afterVersions   func()
}

type cosVersionReply struct {
	result   *tencentcos.BucketGetObjectVersionsResult
	response *tencentcos.Response
	err      error
}

func (fake *fakeCOSBucketSDK) GetObjectLockConfiguration(context.Context) (*tencentcos.BucketGetObjectLockResult, *tencentcos.Response, error) {
	if fake.afterLock != nil {
		fake.afterLock()
	}
	return fake.lockResult, fake.lockResponse, fake.lockErr
}

func (fake *fakeCOSBucketSDK) GetVersioning(context.Context) (*tencentcos.BucketGetVersionResult, *tencentcos.Response, error) {
	return fake.versionResult, fake.versionResponse, fake.versionErr
}

func (fake *fakeCOSBucketSDK) Get(_ context.Context, options *tencentcos.BucketGetOptions) (*tencentcos.BucketGetResult, *tencentcos.Response, error) {
	fake.listOptions = options
	if fake.afterList != nil {
		fake.afterList()
	}
	return fake.listResult, fake.listResponse, fake.listErr
}

func (fake *fakeCOSBucketSDK) GetObjectVersions(_ context.Context, options *tencentcos.BucketGetObjectVersionsOptions) (*tencentcos.BucketGetObjectVersionsResult, *tencentcos.Response, error) {
	fake.versionOptions = append(fake.versionOptions, options)
	if fake.afterVersions != nil {
		fake.afterVersions()
	}
	if len(fake.objectVersions) == 0 {
		return nil, nil, errors.New("missing fake version response")
	}
	index := len(fake.versionOptions) - 1
	if index >= len(fake.objectVersions) {
		index = len(fake.objectVersions) - 1
	}
	reply := fake.objectVersions[index]
	return reply.result, reply.response, reply.err
}

type fakeCOSObjectSDK struct {
	getResponse       *tencentcos.Response
	getErr            error
	putResponse       *tencentcos.Response
	putErr            error
	retentionResult   *tencentcos.ObjectGetRetentionResult
	retentionResponse *tencentcos.Response
	retentionErr      error
	getKey            string
	getOptions        *tencentcos.ObjectGetOptions
	putKey            string
	putBody           []byte
	putOptions        *tencentcos.ObjectPutOptions
	retentionKey      string
	afterGet          func()
	afterRetention    func()
	getVersionIDs     [][]string
}

func (fake *fakeCOSObjectSDK) Get(_ context.Context, key string, options *tencentcos.ObjectGetOptions, versionIDs ...string) (*tencentcos.Response, error) {
	fake.getKey, fake.getOptions = key, options
	fake.getVersionIDs = append(fake.getVersionIDs, append([]string(nil), versionIDs...))
	if fake.afterGet != nil {
		fake.afterGet()
	}
	return fake.getResponse, fake.getErr
}

func (fake *fakeCOSObjectSDK) Put(_ context.Context, key string, body io.Reader, options *tencentcos.ObjectPutOptions) (*tencentcos.Response, error) {
	fake.putKey, fake.putOptions = key, options
	fake.putBody, _ = io.ReadAll(body)
	return fake.putResponse, fake.putErr
}

func (fake *fakeCOSObjectSDK) GetRetention(_ context.Context, key string, _ *tencentcos.ObjectGetRetentionOptions) (*tencentcos.ObjectGetRetentionResult, *tencentcos.Response, error) {
	fake.retentionKey = key
	if fake.afterRetention != nil {
		fake.afterRetention()
	}
	return fake.retentionResult, fake.retentionResponse, fake.retentionErr
}

func cosResponse(status int, body io.ReadCloser) *tencentcos.Response {
	return &tencentcos.Response{Response: &http.Response{StatusCode: status, Body: body, Header: make(http.Header)}}
}

func cosNotFound() error {
	return &tencentcos.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound}}
}

func validCOSSDKFakes() (*fakeCOSBucketSDK, *fakeCOSObjectSDK) {
	versionID := "version-1"
	versionResult := &tencentcos.BucketGetObjectVersionsResult{
		Name: cosSDKTestBucket, Prefix: sdkTestKey, MaxKeys: immutableVersionProbeLimit,
		Version: []tencentcos.ListVersionsResultVersion{{
			Key: sdkTestKey, VersionId: versionID, IsLatest: true, Size: 512, StorageClass: "STANDARD",
		}},
	}
	putResponse := cosResponse(http.StatusOK, nil)
	putResponse.Header.Set("x-cos-version-id", versionID)
	return &fakeCOSBucketSDK{
		lockResult:      &tencentcos.BucketGetObjectLockResult{ObjectLockEnabled: "Enabled"},
		lockResponse:    cosResponse(http.StatusOK, nil),
		versionResult:   &tencentcos.BucketGetVersionResult{Status: "Enabled"},
		versionResponse: cosResponse(http.StatusOK, nil),
		listResult: &tencentcos.BucketGetResult{
			Name: cosSDKTestBucket, Prefix: "audit-anchors/v1/stream/", MaxKeys: 2,
			Contents: []tencentcos.Object{{Key: sdkTestKey, Size: 512}},
		},
		listResponse:   cosResponse(http.StatusOK, nil),
		objectVersions: []cosVersionReply{{result: versionResult, response: cosResponse(http.StatusOK, nil)}},
	}, &fakeCOSObjectSDK{
		getResponse:       cosResponse(http.StatusOK, io.NopCloser(bytes.NewReader([]byte("anchor")))),
		putResponse:       putResponse,
		retentionResult:   &tencentcos.ObjectGetRetentionResult{Mode: COSComplianceMode, RetainUntilDate: "2027-09-12T12:05:00Z"},
		retentionResponse: cosResponse(http.StatusOK, nil),
	}
}

func newTestCOSClient(t *testing.T, bucket *fakeCOSBucketSDK, object *fakeCOSObjectSDK) *COSSDKImmutableClient {
	t.Helper()
	client, err := newCOSSDKImmutableClient(cosSDKTestBucket, bucket, object)
	if err != nil {
		t.Fatalf("newCOSSDKImmutableClient() error = %v", err)
	}
	return client
}

func TestCOSSDKInspectionAndCancellation(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	client := newTestCOSClient(t, bucket, object)
	state, err := client.InspectObjectLock(context.Background(), cosSDKTestBucket)
	if err != nil || state != (COSObjectLockState{Enabled: true, VersioningState: "Enabled"}) {
		t.Fatalf("InspectObjectLock() = %#v, %v", state, err)
	}

	cases := []struct {
		name   string
		mutate func(*fakeCOSBucketSDK)
		want   error
	}{
		{"lock unavailable", func(value *fakeCOSBucketSDK) { value.lockErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"lock nil", func(value *fakeCOSBucketSDK) { value.lockResult = nil }, ErrImmutableSDKResponseInvalid},
		{"lock response", func(value *fakeCOSBucketSDK) { value.lockResponse = cosResponse(http.StatusForbidden, nil) }, ErrImmutableSDKResponseInvalid},
		{"version unavailable", func(value *fakeCOSBucketSDK) { value.versionErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"version nil", func(value *fakeCOSBucketSDK) { value.versionResult = nil }, ErrImmutableSDKResponseInvalid},
		{"version response", func(value *fakeCOSBucketSDK) { value.versionResponse = nil }, ErrImmutableSDKResponseInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			b, o := validCOSSDKFakes()
			test.mutate(b)
			_, err := newTestCOSClient(t, b, o).InspectObjectLock(context.Background(), cosSDKTestBucket)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	bucket, object = validCOSSDKFakes()
	ctx, cancel := context.WithCancel(context.Background())
	bucket.afterLock = cancel
	_, err = newTestCOSClient(t, bucket, object).InspectObjectLock(ctx, cosSDKTestBucket)
	if !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func validCOSCreateRequest() COSCreateObjectRequest {
	return COSCreateObjectRequest{
		Bucket: cosSDKTestBucket, Key: sdkTestKey, Body: []byte("anchor"), ContentType: "application/json",
		StorageClass: "STANDARD", LockMode: COSComplianceMode,
		RetainUntil: time.Date(2027, 9, 12, 12, 5, 0, 0, time.UTC),
	}
}

func TestCOSSDKCreateExistingAndNewObject(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	closed := &testReadCloser{reader: bytes.NewReader(nil)}
	object.getResponse = cosResponse(http.StatusOK, closed)
	result, err := newTestCOSClient(t, bucket, object).CreateObject(context.Background(), validCOSCreateRequest())
	if err != nil || result.Status != "exists" || !closed.closed || object.putKey != "" {
		t.Fatalf("existing object = %#v, %v, closed=%t put=%q", result, err, closed.closed, object.putKey)
	}

	bucket, object = validCOSSDKFakes()
	object.getResponse, object.getErr = nil, cosNotFound()
	request := validCOSCreateRequest()
	result, err = newTestCOSClient(t, bucket, object).CreateObject(context.Background(), request)
	if err != nil || result.Status != "created" {
		t.Fatalf("new object = %#v, %v", result, err)
	}
	if object.getKey != sdkTestKey || object.getOptions != nil || object.putKey != sdkTestKey || !bytes.Equal(object.putBody, request.Body) {
		t.Fatalf("unexpected object calls: get=%q put=%q body=%q", object.getKey, object.putKey, object.putBody)
	}
	header := object.putOptions.ObjectPutHeaderOptions
	if header == nil || header.ContentType != "application/json" || header.ContentLength != int64(len(request.Body)) ||
		header.XCosStorageClass != "STANDARD" || header.XOptionHeader == nil ||
		header.XOptionHeader.Get("x-cos-object-lock-mode") != COSComplianceMode ||
		header.XOptionHeader.Get("x-cos-object-lock-retain-until-date") != request.RetainUntil.Format(time.RFC3339) {
		t.Fatalf("unexpected Put options: %#v", object.putOptions)
	}
	request.Body[0] = 'X'
	if object.putBody[0] != 'a' {
		t.Fatal("Put body aliases caller memory")
	}
}

func TestCOSSDKCreateFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeCOSObjectSDK)
		want   error
	}{
		{"existing response invalid", func(value *fakeCOSObjectSDK) { value.getResponse = nil }, ErrImmutableSDKResponseInvalid},
		{"existing body nil", func(value *fakeCOSObjectSDK) { value.getResponse = cosResponse(http.StatusOK, nil) }, ErrImmutableSDKResponseInvalid},
		{"existing close error", func(value *fakeCOSObjectSDK) {
			value.getResponse = cosResponse(http.StatusOK, &testReadCloser{closeErr: errors.New("close failed")})
		}, ErrImmutableSDKResponseInvalid},
		{"lookup unavailable", func(value *fakeCOSObjectSDK) { value.getResponse = nil; value.getErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"put unavailable", func(value *fakeCOSObjectSDK) {
			value.getResponse = nil
			value.getErr = cosNotFound()
			value.putErr = errors.New("provider detail")
		}, ErrImmutableSDKUnavailable},
		{"put response invalid", func(value *fakeCOSObjectSDK) {
			value.getResponse = nil
			value.getErr = cosNotFound()
			value.putResponse = nil
		}, ErrImmutableSDKResponseInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			bucket, object := validCOSSDKFakes()
			test.mutate(object)
			_, err := newTestCOSClient(t, bucket, object).CreateObject(context.Background(), validCOSCreateRequest())
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	bucket, object := validCOSSDKFakes()
	ctx, cancel := context.WithCancel(context.Background())
	object.getResponse, object.getErr, object.afterGet = nil, cosNotFound(), cancel
	_, err := newTestCOSClient(t, bucket, object).CreateObject(ctx, validCOSCreateRequest())
	if !errors.Is(err, ErrImmutableSDKRequestRejected) || object.putKey != "" {
		t.Fatalf("cancellation error = %v, put=%q", err, object.putKey)
	}
}

func TestCOSSDKReadAndRetention(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	client := newTestCOSClient(t, bucket, object)
	body, err := client.ReadObject(context.Background(), cosSDKTestBucket, sdkTestKey)
	if err != nil || string(body) != "anchor" || object.getKey != sdkTestKey {
		t.Fatalf("ReadObject() = %q, %v", body, err)
	}
	retention, err := client.ReadObjectRetention(context.Background(), cosSDKTestBucket, sdkTestKey)
	if err != nil || retention.Mode != COSComplianceMode || retention.RetainUntil.Location() != time.UTC || object.retentionKey != sdkTestKey {
		t.Fatalf("ReadObjectRetention() = %#v, %v", retention, err)
	}

	readCases := []struct {
		name   string
		mutate func(*fakeCOSObjectSDK)
		want   error
	}{
		{"provider error", func(value *fakeCOSObjectSDK) { value.getErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"not found", func(value *fakeCOSObjectSDK) { value.getResponse = nil; value.getErr = cosNotFound() }, ErrImmutableObjectNotFound},
		{"nil response", func(value *fakeCOSObjectSDK) { value.getResponse = nil }, ErrImmutableSDKResponseInvalid},
		{"wrong status", func(value *fakeCOSObjectSDK) {
			value.getResponse = cosResponse(http.StatusPartialContent, io.NopCloser(bytes.NewReader(nil)))
		}, ErrImmutableSDKResponseInvalid},
		{"oversized", func(value *fakeCOSObjectSDK) {
			value.getResponse = cosResponse(http.StatusOK, io.NopCloser(bytes.NewReader(make([]byte, AuditObjectMaxBytes+1))))
		}, ErrImmutableSDKResponseInvalid},
	}
	for _, test := range readCases {
		t.Run("read "+test.name, func(t *testing.T) {
			b, o := validCOSSDKFakes()
			test.mutate(o)
			_, err := newTestCOSClient(t, b, o).ReadObject(context.Background(), cosSDKTestBucket, sdkTestKey)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	retentionCases := []struct {
		name   string
		mutate func(*fakeCOSObjectSDK)
		want   error
	}{
		{"provider error", func(value *fakeCOSObjectSDK) { value.retentionErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"nil result", func(value *fakeCOSObjectSDK) { value.retentionResult = nil }, ErrImmutableSDKResponseInvalid},
		{"bad response", func(value *fakeCOSObjectSDK) { value.retentionResponse = nil }, ErrImmutableSDKResponseInvalid},
		{"bad date", func(value *fakeCOSObjectSDK) { value.retentionResult.RetainUntilDate = "not-a-date" }, ErrImmutableSDKResponseInvalid},
	}
	for _, test := range retentionCases {
		t.Run("retention "+test.name, func(t *testing.T) {
			b, o := validCOSSDKFakes()
			test.mutate(o)
			_, err := newTestCOSClient(t, b, o).ReadObjectRetention(context.Background(), cosSDKTestBucket, sdkTestKey)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCOSSDKRejectsUnboundRequestsAndInvalidConstruction(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	client := newTestCOSClient(t, bucket, object)
	badRequests := []func() error{
		func() error { _, err := client.InspectObjectLock(nil, cosSDKTestBucket); return err },
		func() error { _, err := client.InspectObjectLock(context.Background(), "other-bucket"); return err },
		func() error {
			_, err := (*COSSDKImmutableClient)(nil).InspectObjectLock(context.Background(), cosSDKTestBucket)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.Bucket = "other-bucket"
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.Key = "bad\\key"
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.Body = nil
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.Body = make([]byte, AuditObjectMaxBytes+1)
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.ContentType = "text/plain"
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.StorageClass = "ARCHIVE"
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.LockMode = "GOVERNANCE"
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.RetainUntil = time.Time{}
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.RetainUntil = request.RetainUntil.In(time.FixedZone("offset", 3600))
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validCOSCreateRequest()
			request.RetainUntil = request.RetainUntil.Add(time.Nanosecond)
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			_, err := client.ReadObject(context.Background(), cosSDKTestBucket, "bad//key")
			return err
		},
		func() error {
			_, err := client.ReadObjectRetention(context.Background(), cosSDKTestBucket, "../bad")
			return err
		},
		func() error {
			_, err := (*COSSDKImmutableClient)(nil).ReadObject(context.Background(), cosSDKTestBucket, sdkTestKey)
			return err
		},
		func() error {
			_, err := (*COSSDKImmutableClient)(nil).ReadObjectRetention(context.Background(), cosSDKTestBucket, sdkTestKey)
			return err
		},
	}
	for _, call := range badRequests {
		if err := call(); !errors.Is(err, ErrImmutableSDKRequestRejected) {
			t.Fatalf("unbound request error = %v", err)
		}
	}
	if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, cosSDKTestRegion, nil); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("nil constructor error = %v", err)
	}
	if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, cosSDKTestRegion, &tencentcos.Client{}); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("incomplete constructor error = %v", err)
	}
	endpoint, _ := url.Parse("https://" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".tencentcos.cn")
	realClient := tencentcos.NewClient(&tencentcos.BaseURL{BucketURL: endpoint}, &http.Client{})
	if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, cosSDKTestRegion, realClient); err != nil {
		t.Fatalf("public constructor error = %v", err)
	}
	for name, endpointValue := range map[string]string{
		"http":          "http://" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".tencentcos.cn",
		"wrong_bucket":  "https://other-1250000000.cos." + cosSDKTestRegion + ".tencentcos.cn",
		"wrong_region":  "https://" + cosSDKTestBucket + ".cos.ap-shanghai.tencentcos.cn",
		"legacy_domain": "https://" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".myqcloud.com",
		"userinfo":      "https://user@" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".tencentcos.cn",
		"port":          "https://" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".tencentcos.cn:443",
		"path":          "https://" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".tencentcos.cn/prefix",
		"query":         "https://" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".tencentcos.cn?x=1",
		"fragment":      "https://" + cosSDKTestBucket + ".cos." + cosSDKTestRegion + ".tencentcos.cn#x",
	} {
		t.Run("reject_endpoint_"+name, func(t *testing.T) {
			badEndpoint, parseErr := url.Parse(endpointValue)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			badClient := tencentcos.NewClient(&tencentcos.BaseURL{BucketURL: badEndpoint}, &http.Client{})
			if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, cosSDKTestRegion, badClient); !errors.Is(err, ErrImmutableSDKRequestRejected) {
				t.Fatalf("constructor error = %v", err)
			}
		})
	}
	if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, "BAD_REGION", realClient); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid region constructor error = %v", err)
	}
	if _, err := newCOSSDKImmutableClient("BAD_BUCKET", bucket, object); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid bucket constructor error = %v", err)
	}
	if _, err := newCOSSDKImmutableClient(cosSDKTestBucket, nil, object); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("nil bucket API constructor error = %v", err)
	}
	if _, err := newCOSSDKImmutableClient(cosSDKTestBucket, bucket, nil); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("nil object API constructor error = %v", err)
	}
}

func TestCOSSDKListObjectKeysUsesBoundedMarker(t *testing.T) {
	bucket, object := validCOSSDKFakes()
	second := "audit-anchors/v1/stream/00000000000000000002-anchor.json"
	bucket.listResult.Contents = []tencentcos.Object{{Key: sdkTestKey, Size: 512}, {Key: second, Size: 513}}
	bucket.listResult.IsTruncated = true
	bucket.listResult.NextMarker = "provider-marker"
	page, err := newTestCOSClient(t, bucket, object).ListObjectKeys(
		context.Background(), cosSDKTestBucket, "audit-anchors/v1/stream/", "", 2,
	)
	if err != nil || len(page.Keys) != 2 || page.Keys[1] != second || !page.Truncated || page.NextAfter != second {
		t.Fatalf("unexpected page: %#v, %v", page, err)
	}
	if bucket.listOptions == nil || bucket.listOptions.Prefix != "audit-anchors/v1/stream/" ||
		bucket.listOptions.Marker != "" || bucket.listOptions.MaxKeys != 2 || bucket.listOptions.Delimiter != "" ||
		bucket.listOptions.EncodingType != "" || bucket.listOptions.XOptionHeader != nil {
		t.Fatalf("unexpected list options: %#v", bucket.listOptions)
	}
}

func TestCOSSDKListObjectKeysFailsClosed(t *testing.T) {
	prefix := "audit-anchors/v1/stream/"
	bucket, object := validCOSSDKFakes()
	bucket.listErr = errors.New("provider detail")
	if _, err := newTestCOSClient(t, bucket, object).ListObjectKeys(context.Background(), cosSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKUnavailable) {
		t.Fatalf("provider error = %v", err)
	}
	bucket, object = validCOSSDKFakes()
	ctx, cancel := context.WithCancel(context.Background())
	bucket.afterList = cancel
	if _, err := newTestCOSClient(t, bucket, object).ListObjectKeys(ctx, cosSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("cancellation error = %v", err)
	}
	bucket, object = validCOSSDKFakes()
	bucket.listResult = nil
	if _, err := newTestCOSClient(t, bucket, object).ListObjectKeys(context.Background(), cosSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKResponseInvalid) {
		t.Fatalf("nil response error = %v", err)
	}

	mutations := map[string]func(*tencentcos.BucketGetResult, *tencentcos.Response){
		"wrong_bucket": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.Name = "other-bucket" },
		"wrong_prefix": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.Prefix = "other/" },
		"wrong_marker": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.Marker = "unexpected" },
		"wrong_limit":  func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.MaxKeys = 3 },
		"wrong_status": func(_ *tencentcos.BucketGetResult, response *tencentcos.Response) {
			response.StatusCode = http.StatusCreated
		},
		"outside_prefix": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.Contents[0].Key = "other/key" },
		"duplicate_key": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) {
			result.Contents = append(result.Contents, result.Contents[0])
		},
		"empty_object": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.Contents[0].Size = 0 },
		"oversized_object": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) {
			result.Contents[0].Size = AuditObjectMaxBytes + 1
		},
		"truncated_empty": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) {
			result.Contents = nil
			result.IsTruncated = true
		},
		"truncated_marker": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) {
			result.IsTruncated = true
			result.NextMarker = ""
		},
		"unexpected_marker": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.NextMarker = sdkTestKey },
		"common_prefix": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) {
			result.CommonPrefixes = []string{"x/"}
		},
		"delimiter": func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.Delimiter = "/" },
		"encoding":  func(result *tencentcos.BucketGetResult, _ *tencentcos.Response) { result.EncodingType = "url" },
	}
	for name, mutate := range mutations {
		t.Run("response_"+name, func(t *testing.T) {
			value, objectValue := validCOSSDKFakes()
			mutate(value.listResult, value.listResponse)
			if _, err := newTestCOSClient(t, value, objectValue).ListObjectKeys(context.Background(), cosSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKResponseInvalid) {
				t.Fatalf("response error = %v", err)
			}
		})
	}

	for name, call := range map[string]func(*COSSDKImmutableClient) error{
		"bucket": func(client *COSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), "other-bucket", prefix, "", 2)
			return err
		},
		"prefix": func(client *COSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), cosSDKTestBucket, "../audit/", "", 2)
			return err
		},
		"after": func(client *COSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), cosSDKTestBucket, prefix, "other/key", 2)
			return err
		},
		"limit": func(client *COSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), cosSDKTestBucket, prefix, "", ImmutableListMaxKeys+1)
			return err
		},
	} {
		t.Run("request_"+name, func(t *testing.T) {
			value, objectValue := validCOSSDKFakes()
			if err := call(newTestCOSClient(t, value, objectValue)); !errors.Is(err, ErrImmutableSDKRequestRejected) {
				t.Fatalf("request error = %v", err)
			}
		})
	}
}

func TestSDKObjectKeyValidation(t *testing.T) {
	for _, valid := range []string{"a", "audit/v1/object.json", string(bytes.Repeat([]byte{'a'}, 1024))} {
		if !validSDKObjectKey(valid) {
			t.Fatalf("valid key rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "/absolute", "double//slash", "dot..dot", "back\\slash", string(bytes.Repeat([]byte{'a'}, 1025))} {
		if validSDKObjectKey(invalid) {
			t.Fatalf("invalid key accepted: %q", invalid)
		}
	}
	if validCOSResponse(nil) || validCOSResponse(&tencentcos.Response{}) || validCOSResponse(cosResponse(http.StatusCreated, nil)) {
		t.Fatal("invalid COS response accepted")
	}
}

type testReadCloser struct {
	reader   io.Reader
	readErr  error
	closeErr error
	closed   bool
}

func (value *testReadCloser) Read(target []byte) (int, error) {
	if value.readErr != nil {
		return 0, value.readErr
	}
	if value.reader == nil {
		return 0, io.EOF
	}
	return value.reader.Read(target)
}

func (value *testReadCloser) Close() error {
	value.closed = true
	return value.closeErr
}
