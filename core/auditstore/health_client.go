package auditstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"time"
)

const healthRequestID = "production-preflight"

func QueryHealth(ctx context.Context, socketPath, streamID string) (Health, error) {
	dialer := net.Dialer{Timeout: readDeadline}
	return queryHealth(ctx, socketPath, streamID, dialer.DialContext)
}

func queryHealth(
	ctx context.Context,
	socketPath string,
	streamID string,
	dial func(context.Context, string, string) (net.Conn, error),
) (Health, error) {
	if ctx == nil || ctx.Err() != nil || socketPath == "" || !idPattern.MatchString(streamID) {
		return Health{}, ErrServiceRuntimeInvalid
	}
	if dial == nil {
		return Health{}, ErrServiceRuntimeInvalid
	}
	connection, err := dial(ctx, "unix", socketPath)
	if err != nil || connection == nil {
		return Health{}, ErrRepositoryUnavailable
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopCancellation()
	if ctx.Err() != nil {
		return Health{}, ErrRepositoryUnavailable
	}
	deadline := time.Now().UTC().Add(readDeadline)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err = connection.SetDeadline(deadline); err != nil {
		return Health{}, ErrRepositoryUnavailable
	}
	request, err := json.Marshal(wireRequest{
		Version: ProtocolVersion, Purpose: Purpose, RequestID: healthRequestID,
		Operation: "health", StreamID: streamID, Parameters: json.RawMessage(`{}`),
	})
	if err != nil || len(request)+1 > MaxRequestBytes {
		return Health{}, ErrServiceRuntimeInvalid
	}
	request = append(request, '\n')
	if ctx.Err() != nil {
		return Health{}, ErrRepositoryUnavailable
	}
	if written, writeErr := connection.Write(request); writeErr != nil || written != len(request) {
		return Health{}, ErrRepositoryUnavailable
	}
	if ctx.Err() != nil {
		return Health{}, ErrRepositoryUnavailable
	}
	line, readErr := io.ReadAll(io.LimitReader(connection, MaxResponseBytes+1))
	if ctx.Err() != nil || readErr != nil || len(line) < 2 || len(line) > MaxResponseBytes ||
		line[len(line)-1] != '\n' || bytes.Count(line, []byte{'\n'}) != 1 {
		return Health{}, ErrRepositoryUnavailable
	}
	line = bytes.TrimSuffix(line, []byte{'\n'})
	health, err := parseHealthResponse(line, streamID)
	if ctx.Err() != nil {
		return Health{}, ErrRepositoryUnavailable
	}
	return health, err
}

func parseHealthResponse(line []byte, streamID string) (Health, error) {
	if len(line) == 0 || len(line) >= MaxResponseBytes || !idPattern.MatchString(streamID) {
		return Health{}, ErrRepositoryInvalid
	}
	if rejectDuplicateJSONKeys(line) != nil {
		return Health{}, ErrRepositoryInvalid
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(line, &root) != nil {
		return Health{}, ErrRepositoryInvalid
	}
	if status, ok := root["status"]; !ok || string(status) != `"ok"` {
		return Health{}, ErrRepositoryUnavailable
	}
	if !exactNonNullObjectKeys(line, "version", "purpose", "request_id", "operation", "status", "stream_id", "result") ||
		!exactNonNullObjectKeys(root["result"], "status", "lock_contract", "mirror_state", "common_sequence", "reason_code") {
		return Health{}, ErrRepositoryInvalid
	}
	var response struct {
		Version   int    `json:"version"`
		Purpose   string `json:"purpose"`
		RequestID string `json:"request_id"`
		Operation string `json:"operation"`
		Status    string `json:"status"`
		StreamID  string `json:"stream_id"`
		Result    struct {
			Status         string `json:"status"`
			LockContract   string `json:"lock_contract"`
			MirrorState    string `json:"mirror_state"`
			CommonSequence int64  `json:"common_sequence"`
			ReasonCode     string `json:"reason_code"`
		} `json:"result"`
	}
	if decodeStrict(line, &response) != nil || response.Version != ProtocolVersion ||
		response.Purpose != Purpose || response.RequestID != healthRequestID ||
		response.Operation != "health" || response.Status != "ok" || response.StreamID != streamID {
		return Health{}, ErrRepositoryInvalid
	}
	health := Health{
		Status: response.Result.Status, LockContract: response.Result.LockContract,
		MirrorState: response.Result.MirrorState, CommonSequence: response.Result.CommonSequence,
		ReasonCode: response.Result.ReasonCode,
	}
	if !validHealthResult(health) {
		return Health{}, ErrRepositoryInvalid
	}
	return health, nil
}

func validHealthResult(health Health) bool {
	if health.CommonSequence < 0 || health.CommonSequence > MaxSafeInteger ||
		!reasonCodePattern.MatchString(health.ReasonCode) {
		return false
	}
	switch health.Status {
	case "ready":
		return health.LockContract == "verified" && health.MirrorState == "in_sync" && health.ReasonCode == "ok"
	case "repair_required":
		return health.LockContract == "verified" && health.MirrorState == "lagging" && health.ReasonCode != "ok"
	case "blocked":
		return (health.LockContract == "verified" || health.LockContract == "unverified") &&
			(health.MirrorState == "in_sync" || health.MirrorState == "lagging" || health.MirrorState == "invalid") &&
			health.ReasonCode != "ok"
	default:
		return false
	}
}

// ValidHealth reports whether a repository health value is safe to expose on
// the fixed protocol. It performs no I/O and accepts no provider detail.
func ValidHealth(health Health) bool {
	return validHealthResult(health)
}
