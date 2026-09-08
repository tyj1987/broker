package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validPayload() map[string]any {
	return map[string]any{
		"subject": map[string]any{
			"id": "client", "role": "automation", "security_profile": "strict",
			"providers": []string{"github"}, "operations": []string{"repo.read"},
			"accounts": []string{"primary"}, "resources": []string{"tyj1987/broker"},
			"environments": []string{"production"}, "maximum_ttl_ms": 120000,
		},
		"request": map[string]any{
			"provider": "github", "operation": "repo.read", "account": "primary",
			"resource": "tyj1987/broker", "environment": "production",
			"requested_ttl_ms": 60000, "at": "2026-09-09T00:00:00Z",
		},
		"rule": map[string]any{
			"enabled": true, "roles": []string{"automation"}, "security_profiles": []string{"strict"},
			"providers": []string{"github"}, "operations": []string{"repo.read"},
			"accounts": []string{"primary"}, "resources": []string{"tyj1987/broker"},
			"environments": []string{"production"}, "maximum_ttl_ms": 90000,
		},
	}
}

func request(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	Handler().ServeHTTP(recorder, httptest.NewRequest(method, path, bytes.NewReader(body)))
	return recorder
}

func TestEvaluate(t *testing.T) {
	body, err := json.Marshal(validPayload())
	if err != nil {
		t.Fatal(err)
	}
	recorder := request(t, http.MethodPost, "/v1/evaluate", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", recorder.Code)
	}
	var value response
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if !value.Allow || value.Code != "allowed" || value.TTLMS != 60000 {
		t.Fatalf("unexpected decision %#v", value)
	}
}

func TestRejectsMalformedInputs(t *testing.T) {
	tests := map[string][]byte{
		"invalid json":  []byte("{"),
		"unknown field": []byte(`{"unknown":true}`),
		"trailing json": []byte(`{} {}`),
		"too large":     []byte(`{"padding":"` + strings.Repeat("x", maxRequestBytes) + `"}`),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if status := request(t, http.MethodPost, "/v1/evaluate", body).Code; status != http.StatusBadRequest {
				t.Fatalf("unexpected status %d", status)
			}
		})
	}
}

func TestRejectsInvalidTime(t *testing.T) {
	payload := validPayload()
	payload["request"].(map[string]any)["at"] = "not-a-time"
	body, _ := json.Marshal(payload)
	if status := request(t, http.MethodPost, "/v1/evaluate", body).Code; status != http.StatusBadRequest {
		t.Fatalf("unexpected status %d", status)
	}
}

func TestHealthAndDurationBounds(t *testing.T) {
	if status := request(t, http.MethodGet, "/health", nil).Code; status != http.StatusOK {
		t.Fatalf("unexpected health status %d", status)
	}
	if milliseconds(-1) != 0 || milliseconds(86_400_001) != 0 || milliseconds(1) == 0 {
		t.Fatal("duration bounds failed")
	}
}
