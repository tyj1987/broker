package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validPayload() map[string]any {
	return map[string]any{
		"subject": map[string]any{
			"id": "client", "role": "automation", "principal_type": "agent", "security_profile": "strict",
			"tools": []string{"github.repository.read@1.0.0"}, "target_kinds": []string{"github-repository"},
			"risk_levels": []string{"LOW"},
			"providers":   []string{"github"}, "operations": []string{"repo.read"},
			"accounts": []string{"primary"}, "resources": []string{"tyj1987/broker"},
			"environments": []string{"production"}, "maximum_ttl_ms": 120000,
		},
		"request": map[string]any{
			"tool": "github.repository.read@1.0.0", "target_kind": "github-repository", "risk_level": "LOW",
			"provider": "github", "operation": "repo.read", "account": "primary",
			"resource": "tyj1987/broker", "environment": "production",
			"requested_ttl_ms": 60000, "source_ip": "203.0.113.42", "at": "2026-09-09T00:00:00Z",
		},
		"rule": map[string]any{
			"enabled": true, "tools": []string{"github.repository.read@1.0.0"},
			"target_kinds": []string{"github-repository"}, "risk_levels": []string{"LOW"},
			"allow_agent_execute": true, "roles": []string{"automation"}, "security_profiles": []string{"strict"},
			"providers": []string{"github"}, "operations": []string{"repo.read"},
			"accounts": []string{"primary"}, "resources": []string{"tyj1987/broker"},
			"environments": []string{"production"}, "maximum_ttl_ms": 90000,
			"source_cidrs": []string{"203.0.113.0/24"},
			"not_before":   "2026-09-08T00:00:00Z", "not_after": "2026-09-10T00:00:00Z",
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
	digest := sha256.Sum256(body)
	if value.RequestBinding != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("response is not bound to request: %#v", value)
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

func TestRejectsInvalidRuleTime(t *testing.T) {
	for _, field := range []string{"not_before", "not_after"} {
		t.Run(field, func(t *testing.T) {
			payload := validPayload()
			payload["rule"].(map[string]any)[field] = "not-a-time"
			body, _ := json.Marshal(payload)
			recorder := request(t, http.MethodPost, "/v1/evaluate", body)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_rule_time") {
				t.Fatalf("unexpected response %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestSourceAndTimeRuleDenials(t *testing.T) {
	tests := map[string]func(map[string]any){
		"source": func(payload map[string]any) { payload["request"].(map[string]any)["source_ip"] = "198.51.100.2" },
		"window": func(payload map[string]any) { payload["rule"].(map[string]any)["not_after"] = "2026-09-09T00:00:00Z" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload := validPayload()
			mutate(payload)
			body, _ := json.Marshal(payload)
			recorder := request(t, http.MethodPost, "/v1/evaluate", body)
			var value response
			if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &value) != nil || value.Allow {
				t.Fatalf("unexpected response %d %s", recorder.Code, recorder.Body.String())
			}
		})
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
