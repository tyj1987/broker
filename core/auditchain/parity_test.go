package auditchain

import (
	"context"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
)

// TestNodeParityFixture is an integration bridge used by the Node parity test.
// Its inputs contain only synthetic test metadata, and failures stay redacted.
func TestNodeParityFixture(t *testing.T) {
	directory := os.Getenv("BROKER_AUDIT_PARITY_DIR")
	if directory == "" {
		t.Skip("Node parity fixture is not configured")
	}
	count, err := strconv.ParseInt(os.Getenv("BROKER_AUDIT_PARITY_ANCHOR_COUNT"), 10, 64)
	if err != nil {
		t.Fatal("invalid parity fixture")
	}
	files, err := strconv.ParseInt(os.Getenv("BROKER_AUDIT_PARITY_ANCHOR_FILES"), 10, 64)
	if err != nil {
		t.Fatal("invalid parity fixture")
	}
	decoded, err := hex.DecodeString(os.Getenv("BROKER_AUDIT_PARITY_ANCHOR_HASH"))
	if err != nil || len(decoded) != digestBytes {
		t.Fatal("invalid parity fixture")
	}
	var expected [digestBytes]byte
	copy(expected[:], decoded)
	proof, err := LoadProof(context.Background(), directory, count, DefaultLimits())
	if err != nil || proof.HashAtAnchor == nil || *proof.HashAtAnchor != expected ||
		proof.FilesAtAnchor == nil || *proof.FilesAtAnchor != files {
		t.Fatal("audit chain parity verification failed")
	}
}
