package auditanchor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	alioss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	tencentcos "github.com/tencentyun/cos-go-sdk-v5"
)

const (
	ossSDKTestBucket = "broker-audit-primary"
	cosSDKTestBucket = "broker-audit-mirror-1250000000"
	sdkTestKey       = "audit-anchors/v1/stream/00000000000000000001-anchor.json"
)

type fakeOSSSDK struct {
	wormResult     *alioss.GetBucketWormResult
	wormErr        error
	versionResult  *alioss.GetBucketVersioningResult
	versionErr     error
	putResult      *alioss.PutObjectResult
	putErr         error
	getResult      *alioss.GetObjectResult
	getErr         error
	wormRequest    *alioss.GetBucketWormRequest
	versionRequest *alioss.GetBucketVersioningRequest
	putRequest     *alioss.PutObjectRequest
	getRequest     *alioss.GetObjectRequest
	afterWorm      func()
	afterVersion   func()
	afterPut       func()
	afterGet       func()
}

func (fake *fakeOSSSDK) GetBucketWorm(_ context.Context, request *alioss.GetBucketWormRequest, _ ...func(*alioss.Options)) (*alioss.GetBucketWormResult, error) {
	fake.wormRequest = request
	if fake.afterWorm != nil {
		fake.afterWorm()
	}
	return fake.wormResult, fake.wormErr
}

func (fake *fakeOSSSDK) GetBucketVersioning(_ context.Context, request *alioss.GetBucketVersioningRequest, _ ...func(*alioss.Options)) (*alioss.GetBucketVersioningResult, error) {
	fake.versionRequest = request
	if fake.afterVersion != nil {
		fake.afterVersion()
	}
	return fake.versionResult, fake.versionErr
}

func (fake *fakeOSSSDK) PutObject(_ context.Context, request *alioss.PutObjectRequest, _ ...func(*alioss.Options)) (*alioss.PutObjectResult, error) {
	fake.putRequest = request
	if fake.afterPut != nil {
		fake.afterPut()
	}
	return fake.putResult, fake.putErr
}

func (fake *fakeOSSSDK) GetObject(_ context.Context, request *alioss.GetObjectRequest, _ ...func(*alioss.Options)) (*alioss.GetObjectResult, error) {
	fake.getRequest = request
	if fake.afterGet != nil {
		fake.afterGet()
	}
	return fake.getResult, fake.getErr
}

func validOSSSDKFake() *fakeOSSSDK {
	return &fakeOSSSDK{
		wormResult: &alioss.GetBucketWormResult{
			WormConfiguration: &alioss.WormConfiguration{
				State: alioss.BucketWormStateType("Locked"), RetentionPeriodInDays: ptr(int32(365)),
			},
			ResultCommon: alioss.ResultCommon{StatusCode: http.StatusOK},
		},
		versionResult: &alioss.GetBucketVersioningResult{ResultCommon: alioss.ResultCommon{StatusCode: http.StatusOK}},
		putResult:     &alioss.PutObjectResult{ResultCommon: alioss.ResultCommon{StatusCode: http.StatusOK}},
		getResult: &alioss.GetObjectResult{
			Body:         io.NopCloser(bytes.NewReader([]byte("anchor"))),
			ResultCommon: alioss.ResultCommon{StatusCode: http.StatusOK},
		},
	}
}

func newTestOSSClient(t *testing.T, fake *fakeOSSSDK) *OSSSDKImmutableClient {
	t.Helper()
	client, err := newOSSSDKImmutableClient(ossSDKTestBucket, fake)
	if err != nil {
		t.Fatalf("newOSSSDKImmutableClient() error = %v", err)
	}
	return client
}

func TestOSSSDKInspectionUsesExactBucketAndFailsClosed(t *testing.T) {
	fake := validOSSSDKFake()
	client := newTestOSSClient(t, fake)
	state, err := client.InspectBucketWORM(context.Background(), ossSDKTestBucket)
	if err != nil {
		t.Fatalf("InspectBucketWORM() error = %v", err)
	}
	if state != (OSSBucketWORMState{Status: "Locked", RetentionDays: 365, VersioningState: "Disabled"}) {
		t.Fatalf("unexpected state: %#v", state)
	}
	if fake.wormRequest == nil || fake.wormRequest.Bucket == nil || *fake.wormRequest.Bucket != ossSDKTestBucket ||
		fake.versionRequest == nil || fake.versionRequest.Bucket == nil || *fake.versionRequest.Bucket != ossSDKTestBucket {
		t.Fatal("inspection did not bind both SDK calls to the configured bucket")
	}
	enabled := "Enabled"
	fake.versionResult.VersionStatus = &enabled
	state, err = client.InspectBucketWORM(context.Background(), ossSDKTestBucket)
	if err != nil || state.VersioningState != enabled {
		t.Fatalf("versioning state = %#v, %v", state, err)
	}

	cases := []struct {
		name   string
		mutate func(*fakeOSSSDK)
		want   error
	}{
		{"worm unavailable", func(value *fakeOSSSDK) { value.wormErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"worm missing", func(value *fakeOSSSDK) { value.wormResult = nil }, ErrImmutableSDKResponseInvalid},
		{"worm status", func(value *fakeOSSSDK) { value.wormResult.StatusCode = http.StatusForbidden }, ErrImmutableSDKResponseInvalid},
		{"worm configuration", func(value *fakeOSSSDK) { value.wormResult.WormConfiguration = nil }, ErrImmutableSDKResponseInvalid},
		{"worm retention", func(value *fakeOSSSDK) { value.wormResult.WormConfiguration.RetentionPeriodInDays = nil }, ErrImmutableSDKResponseInvalid},
		{"version unavailable", func(value *fakeOSSSDK) { value.versionErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"version missing", func(value *fakeOSSSDK) { value.versionResult = nil }, ErrImmutableSDKResponseInvalid},
		{"version status", func(value *fakeOSSSDK) { value.versionResult.StatusCode = http.StatusForbidden }, ErrImmutableSDKResponseInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := validOSSSDKFake()
			test.mutate(value)
			_, err := newTestOSSClient(t, value).InspectBucketWORM(context.Background(), ossSDKTestBucket)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOSSSDKInspectionStopsAfterCancellation(t *testing.T) {
	fake := validOSSSDKFake()
	ctx, cancel := context.WithCancel(context.Background())
	fake.afterWorm = cancel
	_, err := newTestOSSClient(t, fake).InspectBucketWORM(ctx, ossSDKTestBucket)
	if !errors.Is(err, ErrImmutableSDKRequestRejected) || fake.versionRequest != nil {
		t.Fatalf("cancellation error = %v; version request = %#v", err, fake.versionRequest)
	}
}

func TestOSSSDKCreateMapsOnlyImmutableConflict(t *testing.T) {
	fake := validOSSSDKFake()
	client := newTestOSSClient(t, fake)
	body := []byte(`{"version":1}`)
	result, err := client.CreateObject(context.Background(), OSSCreateObjectRequest{
		Bucket: ossSDKTestBucket, Key: sdkTestKey, Body: body,
		ContentType: "application/json", ForbidOverwrite: true,
	})
	if err != nil || result.Status != "created" {
		t.Fatalf("CreateObject() = %#v, %v", result, err)
	}
	request := fake.putRequest
	if request == nil || *request.Bucket != ossSDKTestBucket || *request.Key != sdkTestKey ||
		*request.ContentLength != int64(len(body)) || *request.ContentType != "application/json" ||
		*request.ForbidOverwrite != "true" {
		t.Fatalf("unexpected PutObject request: %#v", request)
	}
	stored, readErr := io.ReadAll(request.Body)
	if readErr != nil || !bytes.Equal(stored, body) {
		t.Fatalf("PutObject body = %q, %v", stored, readErr)
	}
	body[0] = 'X'
	if stored[0] != '{' {
		t.Fatal("request body aliases caller memory")
	}

	fake = validOSSSDKFake()
	fake.putErr = &alioss.ServiceError{StatusCode: http.StatusConflict, Code: "FileAlreadyExists"}
	result, err = newTestOSSClient(t, fake).CreateObject(context.Background(), validOSSCreateRequest())
	if err != nil || result.Status != "exists" {
		t.Fatalf("immutable conflict = %#v, %v", result, err)
	}
	fake.putErr = &alioss.ServiceError{StatusCode: http.StatusConflict, Code: "OtherConflict"}
	if _, err = newTestOSSClient(t, fake).CreateObject(context.Background(), validOSSCreateRequest()); !errors.Is(err, ErrImmutableSDKUnavailable) {
		t.Fatalf("other conflict error = %v", err)
	}
}

func validOSSCreateRequest() OSSCreateObjectRequest {
	return OSSCreateObjectRequest{Bucket: ossSDKTestBucket, Key: sdkTestKey, Body: []byte("anchor"), ContentType: "application/json", ForbidOverwrite: true}
}

func TestOSSSDKCreateAndReadRejectInvalidResponses(t *testing.T) {
	createCases := []struct {
		name   string
		mutate func(*fakeOSSSDK)
		want   error
	}{
		{"provider error", func(value *fakeOSSSDK) { value.putErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"nil response", func(value *fakeOSSSDK) { value.putResult = nil }, ErrImmutableSDKResponseInvalid},
		{"wrong status", func(value *fakeOSSSDK) { value.putResult.StatusCode = http.StatusCreated }, ErrImmutableSDKResponseInvalid},
		{"versioned response", func(value *fakeOSSSDK) { value.putResult.VersionId = ptr("unexpected") }, ErrImmutableSDKResponseInvalid},
	}
	for _, test := range createCases {
		t.Run("create "+test.name, func(t *testing.T) {
			fake := validOSSSDKFake()
			test.mutate(fake)
			_, err := newTestOSSClient(t, fake).CreateObject(context.Background(), validOSSCreateRequest())
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}

	fake := validOSSSDKFake()
	client := newTestOSSClient(t, fake)
	got, err := client.ReadObject(context.Background(), ossSDKTestBucket, sdkTestKey)
	if err != nil || string(got) != "anchor" || fake.getRequest == nil || *fake.getRequest.Range != "bytes=0-16384" {
		t.Fatalf("ReadObject() = %q, %v, request=%#v", got, err, fake.getRequest)
	}
	readCases := []struct {
		name   string
		mutate func(*fakeOSSSDK)
		want   error
	}{
		{"provider error", func(value *fakeOSSSDK) { value.getErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"nil response", func(value *fakeOSSSDK) { value.getResult = nil }, ErrImmutableSDKResponseInvalid},
		{"nil body", func(value *fakeOSSSDK) { value.getResult.Body = nil }, ErrImmutableSDKResponseInvalid},
		{"wrong status", func(value *fakeOSSSDK) { value.getResult.StatusCode = http.StatusPartialContent }, ErrImmutableSDKResponseInvalid},
		{"oversized", func(value *fakeOSSSDK) {
			value.getResult.Body = io.NopCloser(bytes.NewReader(make([]byte, AuditObjectMaxBytes+1)))
		}, ErrImmutableSDKResponseInvalid},
		{"read error", func(value *fakeOSSSDK) { value.getResult.Body = &testReadCloser{readErr: errors.New("read failed")} }, ErrImmutableSDKUnavailable},
		{"close error", func(value *fakeOSSSDK) {
			value.getResult.Body = &testReadCloser{reader: bytes.NewReader([]byte("anchor")), closeErr: errors.New("close failed")}
		}, ErrImmutableSDKUnavailable},
	}
	for _, test := range readCases {
		t.Run("read "+test.name, func(t *testing.T) {
			value := validOSSSDKFake()
			test.mutate(value)
			_, err := newTestOSSClient(t, value).ReadObject(context.Background(), ossSDKTestBucket, sdkTestKey)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOSSSDKRejectsUnboundRequests(t *testing.T) {
	client := newTestOSSClient(t, validOSSSDKFake())
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []func() error{
		func() error { _, err := client.InspectBucketWORM(nil, ossSDKTestBucket); return err },
		func() error { _, err := client.InspectBucketWORM(cancelled, ossSDKTestBucket); return err },
		func() error { _, err := client.InspectBucketWORM(context.Background(), "other-bucket"); return err },
		func() error {
			_, err := (*OSSSDKImmutableClient)(nil).InspectBucketWORM(context.Background(), ossSDKTestBucket)
			return err
		},
		func() error {
			request := validOSSCreateRequest()
			request.Key = "../escape"
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validOSSCreateRequest()
			request.Body = nil
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validOSSCreateRequest()
			request.Body = make([]byte, AuditObjectMaxBytes+1)
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validOSSCreateRequest()
			request.ContentType = "text/plain"
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			request := validOSSCreateRequest()
			request.ForbidOverwrite = false
			_, err := client.CreateObject(context.Background(), request)
			return err
		},
		func() error {
			_, err := client.ReadObject(context.Background(), ossSDKTestBucket, "/absolute")
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrImmutableSDKRequestRejected) {
			t.Fatalf("unbound request error = %v", err)
		}
	}
	if _, err := NewOSSSDKImmutableClient(ossSDKTestBucket, nil); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("public nil constructor error = %v", err)
	}
	if _, err := NewOSSSDKImmutableClient(ossSDKTestBucket, alioss.NewClient(alioss.LoadDefaultConfig())); err != nil {
		t.Fatalf("public constructor error = %v", err)
	}
	if _, err := newOSSSDKImmutableClient("BAD_BUCKET", validOSSSDKFake()); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid bucket constructor error = %v", err)
	}
}

type fakeCOSBucketSDK struct {
	lockResult      *tencentcos.BucketGetObjectLockResult
	lockResponse    *tencentcos.Response
	lockErr         error
	versionResult   *tencentcos.BucketGetVersionResult
	versionResponse *tencentcos.Response
	versionErr      error
	afterLock       func()
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
}

func (fake *fakeCOSObjectSDK) Get(_ context.Context, key string, options *tencentcos.ObjectGetOptions, _ ...string) (*tencentcos.Response, error) {
	fake.getKey, fake.getOptions = key, options
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
	return fake.retentionResult, fake.retentionResponse, fake.retentionErr
}

func cosResponse(status int, body io.ReadCloser) *tencentcos.Response {
	return &tencentcos.Response{Response: &http.Response{StatusCode: status, Body: body}}
}

func cosNotFound() error {
	return &tencentcos.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound}}
}

func validCOSSDKFakes() (*fakeCOSBucketSDK, *fakeCOSObjectSDK) {
	return &fakeCOSBucketSDK{
		lockResult:      &tencentcos.BucketGetObjectLockResult{ObjectLockEnabled: "Enabled"},
		lockResponse:    cosResponse(http.StatusOK, nil),
		versionResult:   &tencentcos.BucketGetVersionResult{Status: "Enabled"},
		versionResponse: cosResponse(http.StatusOK, nil),
	}, &fakeCOSObjectSDK{
		getResponse:       cosResponse(http.StatusOK, io.NopCloser(bytes.NewReader([]byte("anchor")))),
		putResponse:       cosResponse(http.StatusOK, nil),
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
	if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, nil); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("nil constructor error = %v", err)
	}
	if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, &tencentcos.Client{}); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("incomplete constructor error = %v", err)
	}
	endpoint, _ := url.Parse("https://example.invalid")
	realClient := tencentcos.NewClient(&tencentcos.BaseURL{BucketURL: endpoint}, &http.Client{})
	if _, err := NewCOSSDKImmutableClient(cosSDKTestBucket, realClient); err != nil {
		t.Fatalf("public constructor error = %v", err)
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
