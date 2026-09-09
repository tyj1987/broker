// Package server exposes the policy engine over a local Unix domain socket.
// The transport accepts decisions only; it never receives credentials.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tyj1987/broker/core/policy"
)

const maxRequestBytes = 64 * 1024

type wireSubject struct {
	ID                 string   `json:"id"`
	Role               string   `json:"role"`
	SecurityProfile    string   `json:"security_profile"`
	Providers          []string `json:"providers"`
	Operations         []string `json:"operations"`
	Accounts           []string `json:"accounts"`
	Resources          []string `json:"resources"`
	Environments       []string `json:"environments"`
	MaximumTTLMS       int64    `json:"maximum_ttl_ms"`
	RequiresApproval   bool     `json:"requires_approval"`
	RequiresTwoPersons bool     `json:"requires_two_persons"`
}

type wireRequest struct {
	Provider       string `json:"provider"`
	Operation      string `json:"operation"`
	Account        string `json:"account"`
	Resource       string `json:"resource"`
	Environment    string `json:"environment"`
	RequestedTTLMS int64  `json:"requested_ttl_ms"`
	StepUp         bool   `json:"step_up"`
	ApprovalCount  int    `json:"approval_count"`
	SourceIP       string `json:"source_ip"`
	At             string `json:"at"`
}

type wireRule struct {
	Enabled           bool     `json:"enabled"`
	Roles             []string `json:"roles"`
	SecurityProfiles  []string `json:"security_profiles"`
	Providers         []string `json:"providers"`
	Operations        []string `json:"operations"`
	Accounts          []string `json:"accounts"`
	Resources         []string `json:"resources"`
	Environments      []string `json:"environments"`
	MaximumTTLMS      int64    `json:"maximum_ttl_ms"`
	RequireStepUp     bool     `json:"require_step_up"`
	RequiredApprovals int      `json:"required_approvals"`
	SourceCIDRs       []string `json:"source_cidrs"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
}

type evaluation struct {
	Subject wireSubject `json:"subject"`
	Request wireRequest `json:"request"`
	Rule    wireRule    `json:"rule"`
}

type response struct {
	Allow bool   `json:"allow"`
	TTLMS int64  `json:"ttl_ms,omitempty"`
	Code  string `json:"code"`
}

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/evaluate", func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var input evaluation
		if err := decoder.Decode(&input); err != nil {
			writeJSON(writer, http.StatusBadRequest, response{Code: "invalid_json"})
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			writeJSON(writer, http.StatusBadRequest, response{Code: "invalid_json"})
			return
		}

		at, err := time.Parse(time.RFC3339Nano, input.Request.At)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, response{Code: "invalid_time"})
			return
		}
		notBefore, err := optionalTime(input.Rule.NotBefore)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, response{Code: "invalid_rule_time"})
			return
		}
		notAfter, err := optionalTime(input.Rule.NotAfter)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, response{Code: "invalid_rule_time"})
			return
		}
		decision := policy.Evaluate(
			policy.Subject{
				ID: input.Subject.ID, Role: input.Subject.Role, SecurityProfile: input.Subject.SecurityProfile,
				Providers: input.Subject.Providers, Operations: input.Subject.Operations,
				Accounts: input.Subject.Accounts, Resources: input.Subject.Resources,
				Environments: input.Subject.Environments, MaximumTTL: milliseconds(input.Subject.MaximumTTLMS),
				RequiresApproval: input.Subject.RequiresApproval, RequiresTwoPersons: input.Subject.RequiresTwoPersons,
			},
			policy.Request{
				Provider: input.Request.Provider, Operation: input.Request.Operation, Account: input.Request.Account,
				Resource: input.Request.Resource, Environment: input.Request.Environment,
				RequestedTTL: milliseconds(input.Request.RequestedTTLMS), StepUp: input.Request.StepUp,
				ApprovalCount: input.Request.ApprovalCount, SourceIP: input.Request.SourceIP, At: at,
			},
			policy.Rule{
				Enabled: input.Rule.Enabled, Roles: input.Rule.Roles, SecurityProfiles: input.Rule.SecurityProfiles,
				Providers: input.Rule.Providers, Operations: input.Rule.Operations, Accounts: input.Rule.Accounts,
				Resources: input.Rule.Resources, Environments: input.Rule.Environments,
				MaximumTTL: milliseconds(input.Rule.MaximumTTLMS), RequireStepUp: input.Rule.RequireStepUp,
				RequiredApprovals: input.Rule.RequiredApprovals, SourceCIDRs: input.Rule.SourceCIDRs,
				NotBefore: notBefore, NotAfter: notAfter,
			},
		)
		writeJSON(writer, http.StatusOK, response{Allow: decision.Allow, TTLMS: decision.TTL.Milliseconds(), Code: decision.Code})
	})
	return mux
}

func optionalTime(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func Run(socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return errors.New("policy socket path must be absolute")
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path %q", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0660); err != nil {
		return err
	}
	server := &http.Server{
		Handler: Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 * 1024,
	}
	return server.Serve(listener)
}

func milliseconds(value int64) time.Duration {
	if value <= 0 || value > int64((24*time.Hour)/time.Millisecond) {
		return 0
	}
	return time.Duration(value) * time.Millisecond
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
