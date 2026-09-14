package auditchain

import (
	"context"
	"errors"
)

const MaxSafeInteger int64 = 9_007_199_254_740_991

var (
	ErrChainInvalid = errors.New("audit chain invalid")
	ErrChainChanged = errors.New("audit chain changed during verification")
	ErrChainLimit   = errors.New("audit chain verification limit exceeded")
	ErrChainRead    = errors.New("audit chain unavailable")
	GenesisHash     = [32]byte{}
)

type Limits struct {
	MaxFiles      int
	MaxEvents     int64
	MaxLineBytes  int
	MaxTotalBytes int64
	MaxDepth      int
}

func DefaultLimits() Limits {
	return Limits{
		MaxFiles:      1_024,
		MaxEvents:     2_000_000,
		MaxLineBytes:  256 * 1024,
		MaxTotalBytes: 512 * 1024 * 1024,
		MaxDepth:      64,
	}
}

func validLimits(limits Limits) bool {
	hard := Limits{
		MaxFiles:      4_096,
		MaxEvents:     10_000_000,
		MaxLineBytes:  1024 * 1024,
		MaxTotalBytes: 4 * 1024 * 1024 * 1024,
		MaxDepth:      128,
	}
	return limits.MaxFiles >= 1 && limits.MaxFiles <= hard.MaxFiles &&
		limits.MaxEvents >= 1 && limits.MaxEvents <= hard.MaxEvents &&
		limits.MaxLineBytes >= 1 && limits.MaxLineBytes <= hard.MaxLineBytes &&
		limits.MaxTotalBytes >= 1 && limits.MaxTotalBytes <= hard.MaxTotalBytes &&
		limits.MaxDepth >= 1 && limits.MaxDepth <= hard.MaxDepth
}

type State struct {
	Files    int64
	Count    int64
	LastHash [32]byte
}

type Proof struct {
	State
	AnchoredEventCount int64
	HashAtAnchor       *[32]byte
	FilesAtAnchor      *int64
}

func VerifyDirectory(ctx context.Context, directory string, limits Limits) (State, error) {
	result, err := scanDirectory(ctx, directory, limits, nil)
	return result.State, err
}

func LoadProof(ctx context.Context, directory string, anchoredEventCount int64, limits Limits) (Proof, error) {
	if anchoredEventCount < 0 || anchoredEventCount > MaxSafeInteger {
		return Proof{}, ErrChainInvalid
	}
	return scanDirectory(ctx, directory, limits, &anchoredEventCount)
}
