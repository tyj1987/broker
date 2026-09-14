package auditoss

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	alioss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
)

const (
	ossSDKTestBucket = "broker-audit-primary"
	ossSDKTestRegion = "cn-hangzhou"
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
	listResult     *alioss.ListObjectsV2Result
	listErr        error
	wormRequest    *alioss.GetBucketWormRequest
	versionRequest *alioss.GetBucketVersioningRequest
	putRequest     *alioss.PutObjectRequest
	getRequest     *alioss.GetObjectRequest
	listRequest    *alioss.ListObjectsV2Request
	afterWorm      func()
	afterVersion   func()
	afterPut       func()
	afterGet       func()
	afterList      func()
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

func (fake *fakeOSSSDK) ListObjectsV2(_ context.Context, request *alioss.ListObjectsV2Request, _ ...func(*alioss.Options)) (*alioss.ListObjectsV2Result, error) {
	fake.listRequest = request
	if fake.afterList != nil {
		fake.afterList()
	}
	return fake.listResult, fake.listErr
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
			Body: io.NopCloser(bytes.NewReader([]byte("anchor"))), ContentLength: 6,
			ContentRange: ptr("bytes 0-5/6"),
			ResultCommon: alioss.ResultCommon{StatusCode: http.StatusPartialContent},
		},
		listResult: &alioss.ListObjectsV2Result{
			Name: ptr(ossSDKTestBucket), Prefix: ptr("audit-anchors/v1/stream/"), MaxKeys: 2,
			Contents: []alioss.ObjectProperties{{Key: ptr(sdkTestKey), Size: 512}}, KeyCount: 1,
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
	fake = validOSSSDKFake()
	fake.getResult.StatusCode = http.StatusOK
	fake.getResult.ContentRange = nil
	got, err = newTestOSSClient(t, fake).ReadObject(context.Background(), ossSDKTestBucket, sdkTestKey)
	if err != nil || string(got) != "anchor" {
		t.Fatalf("full ReadObject() = %q, %v", got, err)
	}
	readCases := []struct {
		name   string
		mutate func(*fakeOSSSDK)
		want   error
	}{
		{"provider error", func(value *fakeOSSSDK) { value.getErr = errors.New("provider detail") }, ErrImmutableSDKUnavailable},
		{"not found", func(value *fakeOSSSDK) {
			value.getErr = &alioss.ServiceError{StatusCode: http.StatusNotFound, Code: "NoSuchKey"}
		}, ErrImmutableObjectNotFound},
		{"nil response", func(value *fakeOSSSDK) { value.getResult = nil }, ErrImmutableSDKResponseInvalid},
		{"nil body", func(value *fakeOSSSDK) { value.getResult.Body = nil }, ErrImmutableSDKResponseInvalid},
		{"wrong status", func(value *fakeOSSSDK) { value.getResult.StatusCode = http.StatusCreated }, ErrImmutableSDKResponseInvalid},
		{"missing content range", func(value *fakeOSSSDK) { value.getResult.ContentRange = nil }, ErrImmutableSDKResponseInvalid},
		{"malformed content range", func(value *fakeOSSSDK) { value.getResult.ContentRange = ptr("bytes 0-5/*") }, ErrImmutableSDKResponseInvalid},
		{"partial object", func(value *fakeOSSSDK) {
			value.getResult.Body = io.NopCloser(bytes.NewReader([]byte("ancho")))
			value.getResult.ContentLength = 5
			value.getResult.ContentRange = ptr("bytes 0-4/6")
		}, ErrImmutableSDKResponseInvalid},
		{"nonzero range start", func(value *fakeOSSSDK) { value.getResult.ContentRange = ptr("bytes 1-6/6") }, ErrImmutableSDKResponseInvalid},
		{"content length mismatch", func(value *fakeOSSSDK) { value.getResult.ContentLength = 5 }, ErrImmutableSDKResponseInvalid},
		{"versioned response", func(value *fakeOSSSDK) { value.getResult.VersionId = ptr("unexpected") }, ErrImmutableSDKResponseInvalid},
		{"unexpected range on 200", func(value *fakeOSSSDK) { value.getResult.StatusCode = http.StatusOK }, ErrImmutableSDKResponseInvalid},
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

	t.Run("invalid response body is closed", func(t *testing.T) {
		value := validOSSSDKFake()
		body := &testReadCloser{reader: bytes.NewReader([]byte("anchor"))}
		value.getResult.Body = body
		value.getResult.StatusCode = http.StatusCreated
		if _, err := newTestOSSClient(t, value).ReadObject(context.Background(), ossSDKTestBucket, sdkTestKey); !errors.Is(err, ErrImmutableSDKResponseInvalid) || !body.closed {
			t.Fatalf("error = %v, closed=%t", err, body.closed)
		}
	})
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
	if _, err := NewOSSSDKImmutableClient(ossSDKTestBucket, ossSDKTestRegion, nil); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("public nil constructor error = %v", err)
	}
	validConfig := alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion)
	if _, err := NewOSSSDKImmutableClient(ossSDKTestBucket, ossSDKTestRegion, validConfig); err != nil {
		t.Fatalf("public constructor error = %v", err)
	}
	unsafeConfigs := map[string]*alioss.Config{
		"missing_region":         alioss.LoadDefaultConfig(),
		"wrong_region":           alioss.LoadDefaultConfig().WithRegion("cn-shanghai"),
		"custom_endpoint":        alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithEndpoint("https://example.invalid"),
		"disable_tls":            alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithDisableSSL(true),
		"skip_tls_verify":        alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithInsecureSkipVerify(true),
		"redirects":              alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithEnabledRedirect(true),
		"path_style":             alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithUsePathStyle(true),
		"cname":                  alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithUseCName(true),
		"virtual_hosted_alias":   alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithUseVirtualHostedAlias(true),
		"dual_stack":             alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithUseDualStackEndpoint(true),
		"accelerate":             alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithUseAccelerateEndpoint(true),
		"proxy_from_environment": alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithProxyFromEnvironment(true),
		"proxy_host":             alioss.LoadDefaultConfig().WithRegion(ossSDKTestRegion).WithProxyHost("https://example.invalid"),
	}
	for name, unsafeConfig := range unsafeConfigs {
		t.Run("reject_config_"+name, func(t *testing.T) {
			if _, err := NewOSSSDKImmutableClient(ossSDKTestBucket, ossSDKTestRegion, unsafeConfig); !errors.Is(err, ErrImmutableSDKRequestRejected) {
				t.Fatalf("constructor error = %v", err)
			}
		})
	}
	if _, err := NewOSSSDKImmutableClient(ossSDKTestBucket, "BAD_REGION", validConfig); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid region constructor error = %v", err)
	}
	if _, err := newOSSSDKImmutableClient("BAD_BUCKET", validOSSSDKFake()); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("invalid bucket constructor error = %v", err)
	}
}

func TestOSSSDKListObjectKeysUsesBoundedStartAfter(t *testing.T) {
	fake := validOSSSDKFake()
	second := "audit-anchors/v1/stream/00000000000000000002-anchor.json"
	fake.listResult.Contents = []alioss.ObjectProperties{
		{Key: ptr(sdkTestKey), Size: 512}, {Key: ptr(second), Size: 513},
	}
	fake.listResult.KeyCount = 2
	fake.listResult.IsTruncated = true
	fake.listResult.NextContinuationToken = ptr("provider-token")
	page, err := newTestOSSClient(t, fake).ListObjectKeys(
		context.Background(), ossSDKTestBucket, "audit-anchors/v1/stream/", "", 2,
	)
	if err != nil {
		t.Fatalf("ListObjectKeys() error = %v", err)
	}
	if len(page.Keys) != 2 || page.Keys[0] != sdkTestKey || page.Keys[1] != second ||
		!page.Truncated || page.NextAfter != second {
		t.Fatalf("unexpected page: %#v", page)
	}
	request := fake.listRequest
	if request == nil || request.Bucket == nil || *request.Bucket != ossSDKTestBucket ||
		request.Prefix == nil || *request.Prefix != "audit-anchors/v1/stream/" ||
		request.StartAfter != nil || request.MaxKeys != 2 || request.FetchOwner ||
		request.Delimiter != nil || request.ContinuationToken != nil || request.RequestPayer != nil {
		t.Fatalf("unexpected list request: %#v", request)
	}

	fake.listResult = &alioss.ListObjectsV2Result{
		Name: ptr(ossSDKTestBucket), Prefix: ptr("audit-anchors/v1/stream/"), StartAfter: ptr(sdkTestKey),
		MaxKeys: 2, Contents: []alioss.ObjectProperties{{Key: ptr(second), Size: 513}}, KeyCount: 1,
		ResultCommon: alioss.ResultCommon{StatusCode: http.StatusOK},
	}
	page, err = newTestOSSClient(t, fake).ListObjectKeys(
		context.Background(), ossSDKTestBucket, "audit-anchors/v1/stream/", sdkTestKey, 2,
	)
	if err != nil || len(page.Keys) != 1 || page.Keys[0] != second || page.Truncated || page.NextAfter != "" ||
		fake.listRequest.StartAfter == nil || *fake.listRequest.StartAfter != sdkTestKey {
		t.Fatalf("unexpected resumed page: %#v, %v", page, err)
	}
}

func TestOSSSDKListObjectKeysFailsClosed(t *testing.T) {
	prefix := "audit-anchors/v1/stream/"
	for name, call := range map[string]func(*OSSSDKImmutableClient) error{
		"bucket": func(client *OSSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), "other-bucket", prefix, "", 2)
			return err
		},
		"prefix": func(client *OSSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), ossSDKTestBucket, "../audit/", "", 2)
			return err
		},
		"after": func(client *OSSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), ossSDKTestBucket, prefix, "other/key", 2)
			return err
		},
		"limit_zero": func(client *OSSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), ossSDKTestBucket, prefix, "", 0)
			return err
		},
		"limit_large": func(client *OSSSDKImmutableClient) error {
			_, err := client.ListObjectKeys(context.Background(), ossSDKTestBucket, prefix, "", ImmutableListMaxKeys+1)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(newTestOSSClient(t, validOSSSDKFake())); !errors.Is(err, ErrImmutableSDKRequestRejected) {
				t.Fatalf("request error = %v", err)
			}
		})
	}

	fake := validOSSSDKFake()
	fake.listErr = errors.New("provider detail")
	if _, err := newTestOSSClient(t, fake).ListObjectKeys(context.Background(), ossSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKUnavailable) {
		t.Fatalf("provider error = %v", err)
	}
	fake = validOSSSDKFake()
	ctx, cancel := context.WithCancel(context.Background())
	fake.afterList = cancel
	if _, err := newTestOSSClient(t, fake).ListObjectKeys(ctx, ossSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("cancellation error = %v", err)
	}
	fake = validOSSSDKFake()
	fake.listResult = nil
	if _, err := newTestOSSClient(t, fake).ListObjectKeys(context.Background(), ossSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKResponseInvalid) {
		t.Fatalf("nil response error = %v", err)
	}

	mutations := map[string]func(*alioss.ListObjectsV2Result){
		"nil_key":        func(result *alioss.ListObjectsV2Result) { result.Contents[0].Key = nil },
		"wrong_bucket":   func(result *alioss.ListObjectsV2Result) { result.Name = ptr("other-bucket") },
		"wrong_prefix":   func(result *alioss.ListObjectsV2Result) { result.Prefix = ptr("other/") },
		"wrong_limit":    func(result *alioss.ListObjectsV2Result) { result.MaxKeys = 3 },
		"wrong_count":    func(result *alioss.ListObjectsV2Result) { result.KeyCount = 2 },
		"wrong_status":   func(result *alioss.ListObjectsV2Result) { result.StatusCode = http.StatusCreated },
		"outside_prefix": func(result *alioss.ListObjectsV2Result) { result.Contents[0].Key = ptr("other/key") },
		"duplicate_key": func(result *alioss.ListObjectsV2Result) {
			result.Contents = append(result.Contents, result.Contents[0])
			result.KeyCount = 2
		},
		"empty_object":     func(result *alioss.ListObjectsV2Result) { result.Contents[0].Size = 0 },
		"oversized_object": func(result *alioss.ListObjectsV2Result) { result.Contents[0].Size = AuditObjectMaxBytes + 1 },
		"truncated_empty": func(result *alioss.ListObjectsV2Result) {
			result.Contents = nil
			result.KeyCount = 0
			result.IsTruncated = true
			result.NextContinuationToken = ptr("token")
		},
		"truncated_token":  func(result *alioss.ListObjectsV2Result) { result.IsTruncated = true },
		"unexpected_token": func(result *alioss.ListObjectsV2Result) { result.NextContinuationToken = ptr("token") },
		"common_prefix": func(result *alioss.ListObjectsV2Result) {
			result.CommonPrefixes = []alioss.CommonPrefix{{Prefix: ptr("x/")}}
		},
		"delimiter": func(result *alioss.ListObjectsV2Result) { result.Delimiter = ptr("/") },
	}
	for name, mutate := range mutations {
		t.Run("response_"+name, func(t *testing.T) {
			value := validOSSSDKFake()
			mutate(value.listResult)
			if _, err := newTestOSSClient(t, value).ListObjectKeys(context.Background(), ossSDKTestBucket, prefix, "", 2); !errors.Is(err, ErrImmutableSDKResponseInvalid) {
				t.Fatalf("response error = %v", err)
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
