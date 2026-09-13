// Package auditmirror defines the provider-neutral capability intended for an
// independently authenticated audit-mirror worker. It deliberately contains
// no cloud endpoint, bucket, object-key, header, credential, delete, overwrite,
// or retention-policy mutation primitive.
package auditmirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	ContractVersion        = 1
	RetentionDays          = 365
	MaxIssuedAtSkew        = 5 * time.Minute
	MaxMirrorWriteDuration = time.Minute
	RetentionGrace         = MaxIssuedAtSkew + MaxMirrorWriteDuration
	MaxSequence            = int64(9_007_199_254_740_991)
	MaxEnvelopeBytes       = 16 * 1024
	MaxListLimit           = 1000
)

var (
	ErrContractRejected = errors.New("audit mirror contract rejected")
	ErrUnavailable      = errors.New("audit mirror unavailable")
	ErrNotFound         = errors.New("audit mirror envelope not found")
	idPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	prefixPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9/-]{0,126}[a-z0-9]$`)
)

type Binding struct {
	version         int
	streamID        string
	prefix          string
	profileID       string
	trustGeneration [sha256.Size]byte
	retentionDays   int
}

func NewBinding(streamID, prefix, profileID string, trustGeneration [sha256.Size]byte) (Binding, error) {
	binding := Binding{
		version: ContractVersion, streamID: streamID, prefix: prefix,
		profileID: profileID, trustGeneration: trustGeneration, retentionDays: RetentionDays,
	}
	if !binding.valid() {
		return Binding{}, ErrContractRejected
	}
	return binding, nil
}

func (binding Binding) Version() int                       { return binding.version }
func (binding Binding) StreamID() string                   { return binding.streamID }
func (binding Binding) Prefix() string                     { return binding.prefix }
func (binding Binding) ProfileID() string                  { return binding.profileID }
func (binding Binding) TrustGeneration() [sha256.Size]byte { return binding.trustGeneration }
func (binding Binding) RequiredRetentionDays() int         { return binding.retentionDays }
func (binding Binding) valid() bool {
	return binding.version == ContractVersion && idPattern.MatchString(binding.streamID) &&
		idPattern.MatchString(binding.profileID) && prefixPattern.MatchString(binding.prefix) &&
		!strings.Contains(binding.prefix, "//") && !strings.Contains(binding.prefix, "..") &&
		binding.trustGeneration != [sha256.Size]byte{} && binding.retentionDays == RetentionDays
}

type requestBinding struct {
	version         int
	streamID        string
	prefix          string
	profileID       string
	trustGeneration [sha256.Size]byte
	retentionDays   int
}

func bound(binding Binding) requestBinding {
	return requestBinding{
		version: binding.version, streamID: binding.streamID, prefix: binding.prefix,
		profileID: binding.profileID, trustGeneration: binding.trustGeneration,
		retentionDays: binding.retentionDays,
	}
}

func (value requestBinding) validFor(binding Binding) bool {
	return binding.valid() && value.version == binding.version &&
		value.streamID == binding.streamID && value.prefix == binding.prefix &&
		value.profileID == binding.profileID &&
		value.trustGeneration == binding.trustGeneration &&
		value.retentionDays == binding.retentionDays
}

type InspectRequest struct{ binding requestBinding }

func NewInspectRequest(binding Binding) (InspectRequest, error) {
	if !binding.valid() {
		return InspectRequest{}, ErrContractRejected
	}
	return InspectRequest{binding: bound(binding)}, nil
}

func (request InspectRequest) ValidFor(binding Binding) bool {
	return request.binding.validFor(binding)
}

type CreateRequest struct {
	binding  requestBinding
	sequence int64
	envelope []byte
	issuedAt time.Time
}

func NewCreateRequest(binding Binding, sequence int64, envelope []byte, issuedAt time.Time) (CreateRequest, error) {
	if !binding.valid() || sequence < 1 || sequence > MaxSequence ||
		len(envelope) == 0 || len(envelope) > MaxEnvelopeBytes || !validUTC(issuedAt) {
		return CreateRequest{}, ErrContractRejected
	}
	return CreateRequest{
		binding: bound(binding), sequence: sequence,
		envelope: bytes.Clone(envelope), issuedAt: issuedAt,
	}, nil
}

func (request CreateRequest) ValidFor(binding Binding) bool {
	return request.binding.validFor(binding) && request.sequence > 0 && request.sequence <= MaxSequence &&
		len(request.envelope) > 0 && len(request.envelope) <= MaxEnvelopeBytes && validUTC(request.issuedAt)
}
func (request CreateRequest) ValidAt(binding Binding, workerNow time.Time) bool {
	if !request.ValidFor(binding) || !validUTC(workerNow) {
		return false
	}
	delta := workerNow.Sub(request.issuedAt)
	return delta >= -MaxIssuedAtSkew && delta <= MaxIssuedAtSkew
}
func (request CreateRequest) Sequence() int64     { return request.sequence }
func (request CreateRequest) Envelope() []byte    { return bytes.Clone(request.envelope) }
func (request CreateRequest) IssuedAt() time.Time { return request.issuedAt }
func (request CreateRequest) ExpectedRetainUntil() time.Time {
	return request.issuedAt.Add(time.Duration(RetentionDays)*24*time.Hour + RetentionGrace)
}

type ReadRequest struct {
	binding  requestBinding
	sequence int64
}

func NewReadRequest(binding Binding, sequence int64) (ReadRequest, error) {
	if !binding.valid() || sequence < 1 || sequence > MaxSequence {
		return ReadRequest{}, ErrContractRejected
	}
	return ReadRequest{binding: bound(binding), sequence: sequence}, nil
}

func (request ReadRequest) ValidFor(binding Binding) bool {
	return request.binding.validFor(binding) && request.sequence > 0 && request.sequence <= MaxSequence
}
func (request ReadRequest) Sequence() int64 { return request.sequence }

type ListRequest struct {
	binding requestBinding
	after   int64
	limit   int
}

func NewListRequest(binding Binding, after int64, limit int) (ListRequest, error) {
	if !binding.valid() || after < 0 || after > MaxSequence || limit < 1 || limit > MaxListLimit {
		return ListRequest{}, ErrContractRejected
	}
	return ListRequest{binding: bound(binding), after: after, limit: limit}, nil
}

func (request ListRequest) ValidFor(binding Binding) bool {
	return request.binding.validFor(binding) && request.after >= 0 && request.after <= MaxSequence &&
		request.limit >= 1 && request.limit <= MaxListLimit
}
func (request ListRequest) After() int64 { return request.after }
func (request ListRequest) Limit() int   { return request.limit }

type LockState struct {
	Compliance      bool              `json:"compliance"`
	Versioning      bool              `json:"versioning"`
	RetentionDays   int               `json:"retention_days"`
	TrustGeneration [sha256.Size]byte `json:"trust_generation"`
}

type CreateResult struct {
	Status string `json:"status"`
}
type ReadResult struct {
	Envelope []byte `json:"envelope"`
}
type ListResult struct {
	Sequences []int64 `json:"sequences"`
	NextAfter int64   `json:"next_after"`
	Truncated bool    `json:"truncated"`
}
type RetentionResult struct {
	Mode        string    `json:"mode"`
	RetainUntil time.Time `json:"retain_until"`
}

// Client implementations must authenticate an out-of-process worker. Before a
// first write the worker must call ValidAt with its own trusted clock, derive
// COMPLIANCE retention exclusively from ExpectedRetainUntil, and fail the write
// if provider completion exceeds MaxMirrorWriteDuration.
type Client interface {
	Inspect(context.Context, InspectRequest) (LockState, error)
	Create(context.Context, CreateRequest) (CreateResult, error)
	Read(context.Context, ReadRequest) (ReadResult, error)
	List(context.Context, ListRequest) (ListResult, error)
	Retention(context.Context, ReadRequest) (RetentionResult, error)
}

func validUTC(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 2020 && value.Year() <= 9998
}
