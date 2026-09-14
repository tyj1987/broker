package auditmirror

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testBinding(t *testing.T) Binding {
	t.Helper()
	generation := sha256.Sum256([]byte("trusted-key-generation"))
	binding, err := NewBinding("audit.prod", "anchors/v1", "tencent-mirror", generation)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestBindingIsImmutableAndFixedToApprovedRetention(t *testing.T) {
	binding := testBinding(t)
	if binding.Version() != ContractVersion || binding.StreamID() != "audit.prod" ||
		binding.Prefix() != "anchors/v1" || binding.ProfileID() != "tencent-mirror" ||
		binding.RequiredRetentionDays() != 365 || binding.TrustGeneration() == [sha256.Size]byte{} {
		t.Fatalf("unexpected binding: %#v", binding)
	}
	if _, err := NewBinding("Audit:Prod", "anchors/v1", "Tencent:DR", binding.TrustGeneration()); err != nil {
		t.Fatalf("binding grammar diverged from audit-store: %v", err)
	}
}

func TestBindingRejectsUntrustedTopology(t *testing.T) {
	generation := sha256.Sum256([]byte("generation"))
	tests := []struct {
		stream, prefix, profile string
		generation              [sha256.Size]byte
	}{
		{"", "anchors/v1", "tencent-mirror", generation},
		{"audit/prod", "anchors/v1", "tencent-mirror", generation},
		{"audit.prod", "/anchors", "tencent-mirror", generation},
		{"audit.prod", "anchors//v1", "tencent-mirror", generation},
		{"audit.prod", "anchors/../v1", "tencent-mirror", generation},
		{"audit.prod", "anchors/v1", "", generation},
		{"audit.prod", "anchors/v1", "tencent-mirror", [sha256.Size]byte{}},
	}
	for _, test := range tests {
		if binding, err := NewBinding(test.stream, test.prefix, test.profile, test.generation); binding != (Binding{}) || !errors.Is(err, ErrContractRejected) {
			t.Fatalf("accepted binding %#v: %#v, %v", test, binding, err)
		}
	}
}

func TestRequestsAreBoundValidatedAndCloneEnvelope(t *testing.T) {
	binding := testBinding(t)
	otherGeneration := sha256.Sum256([]byte("other-generation"))
	other, err := NewBinding(binding.StreamID(), binding.Prefix(), binding.ProfileID(), otherGeneration)
	if err != nil {
		t.Fatal(err)
	}
	otherPrefix, err := NewBinding(binding.StreamID(), "anchors/v2", binding.ProfileID(), binding.TrustGeneration())
	if err != nil {
		t.Fatal(err)
	}
	otherProfile, err := NewBinding(binding.StreamID(), binding.Prefix(), "tencent-mirror-v2", binding.TrustGeneration())
	if err != nil {
		t.Fatal(err)
	}

	inspect, err := NewInspectRequest(binding)
	if err != nil || !inspect.ValidFor(binding) || inspect.ValidFor(other) || inspect.ValidFor(otherPrefix) || inspect.ValidFor(otherProfile) {
		t.Fatalf("inspect request binding failed: %v", err)
	}
	envelope := []byte(`{"sequence":1}`)
	issuedAt := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	create, err := NewCreateRequest(binding, 1, envelope, issuedAt)
	if err != nil || !create.ValidFor(binding) || create.ValidFor(other) || create.ValidFor(otherPrefix) || create.ValidFor(otherProfile) {
		t.Fatalf("create request binding failed: %v", err)
	}
	if !create.ValidAt(binding, issuedAt.Add(MaxIssuedAtSkew)) ||
		create.ValidAt(binding, issuedAt.Add(MaxIssuedAtSkew+time.Nanosecond)) ||
		!create.ValidAt(binding, issuedAt.Add(-MaxIssuedAtSkew)) ||
		create.ValidAt(binding, issuedAt.Add(-MaxIssuedAtSkew-time.Nanosecond)) ||
		!create.ExpectedRetainUntil().Equal(issuedAt.Add(365*24*time.Hour+RetentionGrace)) {
		t.Fatal("create request time binding failed")
	}
	worstCaseWrite := issuedAt.Add(MaxIssuedAtSkew + MaxMirrorWriteDuration)
	if create.ExpectedRetainUntil().Sub(worstCaseWrite) < 365*24*time.Hour {
		t.Fatal("retention grace does not cover clock skew and bounded mirror write")
	}
	envelope[0] = 'x'
	first := create.Envelope()
	if string(first) != `{"sequence":1}` {
		t.Fatalf("constructor retained caller buffer: %q", first)
	}
	first[0] = 'x'
	if string(create.Envelope()) != `{"sequence":1}` || create.Sequence() != 1 {
		t.Fatal("request exposed mutable envelope storage")
	}
	read, err := NewReadRequest(binding, 1)
	if err != nil || !read.ValidFor(binding) || read.ValidFor(other) || read.Sequence() != 1 {
		t.Fatalf("read request binding failed: %v", err)
	}
	list, err := NewListRequest(binding, 1, 25)
	if err != nil || !list.ValidFor(binding) || list.ValidFor(other) || list.After() != 1 || list.Limit() != 25 {
		t.Fatalf("list request binding failed: %v", err)
	}
}

func TestRequestConstructorsFailClosed(t *testing.T) {
	binding := testBinding(t)
	tooLarge := make([]byte, MaxEnvelopeBytes+1)
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name string
		err  error
	}{
		{"create zero sequence", func() error { _, err := NewCreateRequest(binding, 0, []byte("x"), now); return err }()},
		{"create excessive sequence", func() error { _, err := NewCreateRequest(binding, MaxSequence+1, []byte("x"), now); return err }()},
		{"create empty", func() error { _, err := NewCreateRequest(binding, 1, nil, now); return err }()},
		{"create oversized", func() error { _, err := NewCreateRequest(binding, 1, tooLarge, now); return err }()},
		{"create local time", func() error {
			_, err := NewCreateRequest(binding, 1, []byte("x"), now.In(time.FixedZone("UTC-like", 0)))
			return err
		}()},
		{"create subsecond time", func() error {
			_, err := NewCreateRequest(binding, 1, []byte("x"), now.Add(time.Nanosecond))
			return err
		}()},
		{"read zero", func() error { _, err := NewReadRequest(binding, 0); return err }()},
		{"read excessive", func() error { _, err := NewReadRequest(binding, MaxSequence+1); return err }()},
		{"list negative cursor", func() error { _, err := NewListRequest(binding, -1, 1); return err }()},
		{"list excessive cursor", func() error { _, err := NewListRequest(binding, MaxSequence+1, 1); return err }()},
		{"list zero limit", func() error { _, err := NewListRequest(binding, 0, 0); return err }()},
		{"list oversized limit", func() error { _, err := NewListRequest(binding, 0, MaxListLimit+1); return err }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !errors.Is(test.err, ErrContractRejected) {
				t.Fatalf("error = %v", test.err)
			}
		})
	}
}

func TestInputContractHasNoCloudOrMutationPrimitive(t *testing.T) {
	forbidden := []string{"bucket", "objectkey", "endpoint", "header", "credential", "secret", "delete", "overwrite"}
	inputs := []reflect.Type{
		reflect.TypeOf(Binding{}), reflect.TypeOf(requestBinding{}),
		reflect.TypeOf(InspectRequest{}), reflect.TypeOf(CreateRequest{}),
		reflect.TypeOf(ReadRequest{}), reflect.TypeOf(ListRequest{}),
	}
	var inspect func(reflect.Type, string)
	inspect = func(value reflect.Type, path string) {
		if value.Kind() == reflect.Array || value.Kind() == reflect.Slice || value.Kind() == reflect.Ptr {
			inspect(value.Elem(), path)
			return
		}
		if value.Kind() != reflect.Struct {
			return
		}
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			name := strings.ToLower(strings.ReplaceAll(field.Name, "_", ""))
			for _, denied := range forbidden {
				if strings.Contains(name, denied) {
					t.Fatalf("forbidden input capability %q at %s.%s", denied, path, field.Name)
				}
			}
			if field.Type.PkgPath() == reflect.TypeOf(Binding{}).PkgPath() {
				inspect(field.Type, path+"."+field.Name)
			}
		}
	}
	for _, input := range inputs {
		inspect(input, input.Name())
	}

	client := reflect.TypeOf((*Client)(nil)).Elem()
	for index := 0; index < client.NumMethod(); index++ {
		name := strings.ToLower(client.Method(index).Name)
		if strings.Contains(name, "delete") || strings.Contains(name, "overwrite") || strings.Contains(name, "mutat") {
			t.Fatalf("mutation method exposed: %s", client.Method(index).Name)
		}
	}
}
