package auditstore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func validHealthResponse() string {
	return fmt.Sprintf(`{"version":1,"purpose":%q,"request_id":%q,"operation":"health","status":"ok","stream_id":"broker-production","result":{"status":"ready","lock_contract":"verified","mirror_state":"in_sync","common_sequence":7,"reason_code":"ok"}}`, Purpose, healthRequestID)
}

func TestQueryHealthUsesOneBoundedUnixExchange(t *testing.T) {
	client, server := net.Pipe()
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "unix" || address != "/fixed/store.sock" {
			t.Fatalf("dial = %q, %q", network, address)
		}
		return client, nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		request, err := bufio.NewReader(server).ReadBytes('\n')
		if err != nil || !strings.Contains(string(request), `"request_id":"production-preflight"`) ||
			!strings.Contains(string(request), `"operation":"health"`) {
			t.Errorf("request = %q, %v", request, err)
			return
		}
		_, _ = server.Write([]byte(validHealthResponse() + "\n"))
	}()
	health, err := queryHealth(context.Background(), "/fixed/store.sock", "broker-production", dial)
	if err != nil || health.Status != "ready" || health.CommonSequence != 7 {
		t.Fatalf("health = %#v, %v", health, err)
	}
	<-done
}

func TestQueryHealthUsesPublicUnixClient(t *testing.T) {
	placeholder, err := os.CreateTemp("", "broker-audit-health-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	path := placeholder.Name()
	_ = placeholder.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		if _, acceptErr = bufio.NewReader(connection).ReadBytes('\n'); acceptErr == nil {
			_, acceptErr = connection.Write([]byte(validHealthResponse() + "\n"))
		}
		serverDone <- acceptErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	health, err := QueryHealth(ctx, path, "broker-production")
	if err != nil || health.Status != "ready" {
		t.Fatalf("QueryHealth() = %#v, %v", health, err)
	}
	if err = <-serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestQueryHealthRejectsTransportAndFramingFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		ctx      context.Context
		path     string
		streamID string
		dial     func(context.Context, string, string) (net.Conn, error)
		err      error
	}{
		{"nil context", nil, "/fixed/store.sock", "broker-production", nil, ErrServiceRuntimeInvalid},
		{"empty path", context.Background(), "", "broker-production", nil, ErrServiceRuntimeInvalid},
		{"bad stream", context.Background(), "/fixed/store.sock", "bad stream", nil, ErrServiceRuntimeInvalid},
		{"nil dial", context.Background(), "/fixed/store.sock", "broker-production", nil, ErrServiceRuntimeInvalid},
		{"dial failure", context.Background(), "/fixed/store.sock", "broker-production", func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("provider detail")
		}, ErrRepositoryUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := queryHealth(test.ctx, test.path, test.streamID, test.dial); !errors.Is(err, test.err) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queryHealth(canceled, "/fixed/store.sock", "broker-production", func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	}); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatalf("canceled error = %v", err)
	}

	for name, response := range map[string]string{
		"missing newline": validHealthResponse(),
		"two frames":      validHealthResponse() + "\n{}\n",
		"oversized":       strings.Repeat("x", MaxResponseBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_, _ = bufio.NewReader(server).ReadBytes('\n')
				_, _ = server.Write([]byte(response))
			}()
			_, err := queryHealth(context.Background(), "/fixed/store.sock", "broker-production", func(context.Context, string, string) (net.Conn, error) {
				return client, nil
			})
			if !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestQueryHealthCancellationClosesConnectionAndRejectsLateReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client, server := net.Pipe()
	requestRead := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer server.Close()
		_, _ = bufio.NewReader(server).ReadBytes('\n')
		close(requestRead)
		<-ctx.Done()
		_, _ = server.Write([]byte(validHealthResponse() + "\n"))
	}()
	result := make(chan error, 1)
	go func() {
		_, err := queryHealth(ctx, "/fixed/store.sock", "broker-production", func(context.Context, string, string) (net.Conn, error) {
			return client, nil
		})
		result <- err
	}()
	<-requestRead
	cancel()
	if err := <-result; !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("canceled query error = %v", err)
	}
	<-serverDone
}

func TestQueryHealthCancellationAfterDialSendsNoRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client, server := net.Pipe()
	defer server.Close()
	_, err := queryHealth(ctx, "/fixed/store.sock", "broker-production", func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return client, nil
	})
	if !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("canceled query error = %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 1)
	if read, readErr := server.Read(buffer); read == 1 || readErr == nil {
		t.Fatalf("request sent after cancellation: read=%d error=%v", read, readErr)
	}
}

func TestParseHealthResponseAcceptsExactTypedResult(t *testing.T) {
	health, err := parseHealthResponse([]byte(validHealthResponse()), "broker-production")
	if err != nil || health.Status != "ready" || health.LockContract != "verified" ||
		health.MirrorState != "in_sync" || health.CommonSequence != 7 || health.ReasonCode != "ok" {
		t.Fatalf("health = %#v, %v", health, err)
	}
	for _, value := range []Health{
		{Status: "repair_required", LockContract: "verified", MirrorState: "lagging", CommonSequence: 6, ReasonCode: "mirror_lagging"},
		{Status: "blocked", LockContract: "unverified", MirrorState: "invalid", CommonSequence: 0, ReasonCode: "primary_lock_invalid"},
	} {
		if !ValidHealth(value) {
			t.Fatalf("valid health rejected: %#v", value)
		}
	}
}

func TestParseHealthResponseRejectsAmbiguousAndUnsafeResults(t *testing.T) {
	valid := validHealthResponse()
	cases := []string{
		"",
		"not-json",
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"request_id":"production-preflight"`, `"request_id":"other"`, 1),
		strings.Replace(valid, `"operation":"health"`, `"operation":"read_head"`, 1),
		strings.Replace(valid, `"status":"ok"`, `"status":"error"`, 1),
		strings.Replace(valid, `"stream_id":"broker-production"`, `"stream_id":"other"`, 1),
		strings.Replace(valid, `"status":"ready"`, `"status":"repair_required"`, 1),
		strings.Replace(valid, `"lock_contract":"verified"`, `"lock_contract":"unverified"`, 1),
		strings.Replace(valid, `"mirror_state":"in_sync"`, `"mirror_state":"lagging"`, 1),
		strings.Replace(valid, `"common_sequence":7`, `"common_sequence":-1`, 1),
		strings.Replace(valid, `"common_sequence":7`, `"common_sequence":null`, 1),
		strings.Replace(valid, `"reason_code":"ok"`, `"reason_code":"provider detail"`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"reason_code":"ok"`, `"reason_code":"ok","extra":true`, 1),
	}
	for _, value := range cases {
		if _, err := parseHealthResponse([]byte(value), "broker-production"); !errors.Is(err, ErrRepositoryInvalid) && !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("value %q error = %v", value, err)
		}
	}
	for _, value := range []Health{
		{},
		{Status: "ready", LockContract: "verified", MirrorState: "in_sync", CommonSequence: 0, ReasonCode: "not_ok"},
		{Status: "repair_required", LockContract: "verified", MirrorState: "lagging", CommonSequence: 0, ReasonCode: "ok"},
		{Status: "blocked", LockContract: "other", MirrorState: "invalid", CommonSequence: 0, ReasonCode: "blocked"},
	} {
		if ValidHealth(value) {
			t.Fatalf("invalid health accepted: %#v", value)
		}
	}
}
