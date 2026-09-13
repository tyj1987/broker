package auditchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
)

const digestBytes = sha256.Size

func canonicalEvent(raw []byte, maxDepth int) ([digestBytes]byte, [digestBytes]byte, error) {
	var storedHash [digestBytes]byte
	var previousHash [digestBytes]byte
	value := jsontext.Value(raw)
	if maxDepth < 1 || !value.IsValid() || value.Kind() != jsontext.KindBeginObject ||
		!withinDepth(raw, maxDepth) {
		return storedHash, previousHash, ErrChainInvalid
	}

	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.ReadToken(); err != nil || token.Kind() != jsontext.KindBeginObject {
		return storedHash, previousHash, ErrChainInvalid
	}
	withoutHash := []byte{'{'}
	memberCount := 0
	hasStoredHash := false
	hasPreviousHash := false
	for decoder.PeekKind() != jsontext.KindEndObject {
		nameToken, err := decoder.ReadToken()
		if err != nil || nameToken.Kind() != jsontext.KindString {
			return storedHash, previousHash, ErrChainInvalid
		}
		name := nameToken.String()
		rawMember, err := decoder.ReadValue()
		if err != nil {
			return storedHash, previousHash, ErrChainInvalid
		}
		member := bytes.Clone(rawMember)
		switch name {
		case "hash":
			if hasStoredHash || decodeDigest(member, &storedHash) != nil {
				return storedHash, previousHash, ErrChainInvalid
			}
			hasStoredHash = true
			continue
		case "prev_hash":
			if hasPreviousHash || decodeDigest(member, &previousHash) != nil {
				return storedHash, previousHash, ErrChainInvalid
			}
			hasPreviousHash = true
		}
		if memberCount > 0 {
			withoutHash = append(withoutHash, ',')
		}
		encodedName, err := json.Marshal(name)
		if err != nil {
			return storedHash, previousHash, ErrChainInvalid
		}
		withoutHash = append(withoutHash, encodedName...)
		withoutHash = append(withoutHash, ':')
		withoutHash = append(withoutHash, member...)
		memberCount++
	}
	if token, err := decoder.ReadToken(); err != nil || token.Kind() != jsontext.KindEndObject {
		return storedHash, previousHash, ErrChainInvalid
	}
	if _, err := decoder.ReadToken(); err != io.EOF || !hasStoredHash || !hasPreviousHash {
		return storedHash, previousHash, ErrChainInvalid
	}

	withoutHash = append(withoutHash, '}')
	canonical := jsontext.Value(withoutHash)
	if err := canonical.Canonicalize(); err != nil {
		return storedHash, previousHash, ErrChainInvalid
	}
	computed := sha256.Sum256(canonical)
	if computed != storedHash {
		return storedHash, previousHash, ErrChainInvalid
	}
	return storedHash, previousHash, nil
}

func withinDepth(raw []byte, maximum int) bool {
	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		if _, err := decoder.ReadToken(); err != nil {
			return err == io.EOF
		}
		if decoder.StackDepth() > maximum {
			return false
		}
	}
}

func decodeDigest(raw []byte, target *[digestBytes]byte) error {
	var value string
	if target == nil || json.Unmarshal(raw, &value) != nil || len(value) != digestBytes*2 {
		return ErrChainInvalid
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != digestBytes || hex.EncodeToString(decoded) != value {
		return ErrChainInvalid
	}
	copy(target[:], decoded)
	return nil
}
