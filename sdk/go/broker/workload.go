// Workload identity binding.
package broker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WorkloadIdentityProvider identifies the cluster type.
type WorkloadIdentityProvider string

const (
	ProviderK8S     WorkloadIdentityProvider = "k8s"
	ProviderECS     WorkloadIdentityProvider = "ecs"
	ProviderGKE     WorkloadIdentityProvider = "gke"
	ProviderGeneric WorkloadIdentityProvider = "generic"
)

// WorkloadIdentity is a binding for K8s SA / ECS task / GKE SA.
type WorkloadIdentity struct {
	Provider    WorkloadIdentityProvider
	RoleArn     string
	Audience    string
	SessionName string
	// TokenPath: optional override (defaults to standard projected path for K8s)
	TokenPath string
}

// NewWorkloadIdentity constructs a WorkloadIdentity.
func NewWorkloadIdentity(provider WorkloadIdentityProvider, roleArn string) *WorkloadIdentity {
	wi := &WorkloadIdentity{
		Provider: provider,
		RoleArn:  roleArn,
	}
	if provider == ProviderK8S {
		wi.TokenPath = "/var/run/secrets/tokens/broker-oidc"
	}
	return wi
}

// Token returns the projected OIDC token.
func (w *WorkloadIdentity) Token() (string, error) {
	if w.TokenPath != "" {
		if b, err := os.ReadFile(w.TokenPath); err == nil {
			return strings.TrimSpace(string(b)), nil
		}
	}
	// AWS_WEB_IDENTITY_TOKEN_FILE (EKS / IRSA)
	if p := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b)), nil
		}
	}
	// ECS_CONTAINER_METADATA_FILE (relative task role)
	if p := os.Getenv("ECS_CONTAINER_METADATA_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err == nil {
			var data struct {
				CredentialProviders []struct {
					Credentials string `json:"Credentials"`
				} `json:"CredentialProviders"`
			}
			if err := json.Unmarshal(b, &data); err == nil {
				if len(data.CredentialProviders) > 0 {
					return data.CredentialProviders[0].Credentials, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no projected token found for %s workload identity", w.Provider)
}

// WithAudience sets the STS audience.
func (w *WorkloadIdentity) WithAudience(audience string) *WorkloadIdentity {
	w.Audience = audience
	return w
}

// WithTokenPath overrides the projected token path.
func (w *WorkloadIdentity) WithTokenPath(p string) *WorkloadIdentity {
	if p != "" {
		w.TokenPath = filepath.Clean(p)
	}
	return w
}
