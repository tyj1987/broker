// Package policy implements the fail-closed authorization decision used by
// Secret Broker security-core services. It is deliberately independent of
// transports and credential providers.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Subject struct {
	ID                 string
	Role               string
	PrincipalType      string
	SecurityProfile    string
	Tools              []string
	TargetKinds        []string
	RiskLevels         []string
	Providers          []string
	Operations         []string
	Accounts           []string
	Resources          []string
	Environments       []string
	MaximumTTL         time.Duration
	RequiresApproval   bool
	RequiresTwoPersons bool
}

type Request struct {
	Tool          string
	TargetKind    string
	RiskLevel     string
	Provider      string
	Operation     string
	Account       string
	Resource      string
	Environment   string
	RequestedTTL  time.Duration
	StepUp        bool
	ApprovalCount int
	ApprovalPhase bool
	SourceIP      string
	At            time.Time
}

type Rule struct {
	Enabled           bool
	Tools             []string
	TargetKinds       []string
	RiskLevels        []string
	AllowAgentExecute bool
	Roles             []string
	SecurityProfiles  []string
	Providers         []string
	Operations        []string
	Accounts          []string
	Resources         []string
	Environments      []string
	MaximumTTL        time.Duration
	RequireStepUp     bool
	RequiredApprovals int
	SourceCIDRs       []string
	NotBefore         *time.Time
	NotAfter          *time.Time
}

type Decision struct {
	Allow bool
	TTL   time.Duration
	Code  string
}

func Evaluate(subject Subject, request Request, rule Rule) Decision {
	deny := func(code string) Decision { return Decision{Allow: false, Code: code} }
	if subject.ID == "" || subject.Role == "" || subject.SecurityProfile == "" ||
		!contains([]string{"human", "agent", "workload"}, subject.PrincipalType) {
		return deny("invalid_subject")
	}
	if request.Tool == "" || request.TargetKind == "" || !validRisk(request.RiskLevel) ||
		request.Provider == "" || request.Operation == "" || request.Account == "" || request.Environment == "" {
		return deny("invalid_request")
	}
	if request.ApprovalCount < 0 || request.ApprovalCount > 10 {
		return deny("invalid_request")
	}
	if rule.RequiredApprovals < 0 || rule.RequiredApprovals > 10 {
		return deny("invalid_rule")
	}
	if !rule.Enabled {
		return deny("rule_disabled")
	}
	checks := []struct {
		value   string
		subject []string
		rule    []string
		code    string
	}{
		{request.Tool, subject.Tools, rule.Tools, "tool_denied"},
		{request.TargetKind, subject.TargetKinds, rule.TargetKinds, "target_kind_denied"},
		{request.RiskLevel, subject.RiskLevels, rule.RiskLevels, "risk_denied"},
		{subject.Role, []string{subject.Role}, rule.Roles, "role_denied"},
		{subject.SecurityProfile, []string{subject.SecurityProfile}, rule.SecurityProfiles, "profile_denied"},
		{request.Provider, subject.Providers, rule.Providers, "provider_denied"},
		{request.Operation, subject.Operations, rule.Operations, "operation_denied"},
		{request.Account, subject.Accounts, rule.Accounts, "account_denied"},
		{request.Environment, subject.Environments, rule.Environments, "environment_denied"},
	}
	for _, check := range checks {
		if !contains(check.subject, check.value) || !contains(check.rule, check.value) {
			return deny(check.code)
		}
	}
	if subject.PrincipalType != "human" && !rule.AllowAgentExecute {
		return deny("agent_execution_denied")
	}
	if request.RiskLevel == "CRITICAL" {
		if subject.PrincipalType != "human" {
			return deny("critical_agent_denied")
		}
		if !request.StepUp {
			return deny("step_up_required")
		}
	}
	if len(rule.Resources) > 0 {
		if request.Resource == "" || !contains(rule.Resources, request.Resource) || !contains(subject.Resources, request.Resource) {
			return deny("resource_denied")
		}
	} else if request.Resource != "" && !contains(subject.Resources, request.Resource) {
		return deny("resource_denied")
	}
	if (subject.RequiresApproval || rule.RequireStepUp) && !request.StepUp {
		return deny("step_up_required")
	}
	requiredApprovals := rule.RequiredApprovals
	if request.RiskLevel == "HIGH" && requiredApprovals < 1 {
		requiredApprovals = 1
	}
	if request.RiskLevel == "CRITICAL" && requiredApprovals < 2 {
		requiredApprovals = 2
	}
	if subject.RequiresTwoPersons && requiredApprovals < 2 {
		requiredApprovals = 2
	}
	if !request.ApprovalPhase && request.ApprovalCount < requiredApprovals {
		return deny("approval_required")
	}
	if len(rule.SourceCIDRs) > 0 {
		allowed, valid := sourceAllowed(request.SourceIP, rule.SourceCIDRs)
		if !valid {
			return deny("invalid_rule")
		}
		if !allowed {
			return deny("source_ip_denied")
		}
	}
	when := request.At
	if when.IsZero() {
		when = time.Now().UTC()
	}
	if rule.NotBefore != nil && rule.NotAfter != nil && !rule.NotBefore.Before(*rule.NotAfter) {
		return deny("invalid_rule")
	}
	if rule.NotBefore != nil && when.Before(*rule.NotBefore) {
		return deny("outside_time_window")
	}
	if rule.NotAfter != nil && !when.Before(*rule.NotAfter) {
		return deny("outside_time_window")
	}
	ttl := request.RequestedTTL
	if ttl <= 0 {
		return deny("invalid_ttl")
	}
	for _, maximum := range []time.Duration{subject.MaximumTTL, rule.MaximumTTL, 15 * time.Minute} {
		if maximum <= 0 {
			return deny("ttl_policy_missing")
		}
		if ttl > maximum {
			ttl = maximum
		}
	}
	return Decision{Allow: true, TTL: ttl, Code: "allowed"}
}

func validRisk(value string) bool {
	return contains([]string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}, value)
}

func sourceAllowed(source string, cidrs []string) (bool, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(source))
	if err != nil {
		return false, true
	}
	address = address.Unmap()
	allowed := false
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return false, false
		}
		prefix, ok := normalizedPrefix(prefix)
		if !ok {
			return false, false
		}
		if prefix.Contains(address) {
			allowed = true
		}
	}
	return allowed, true
}

func normalizedPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	address := prefix.Addr()
	if !address.Is4In6() {
		return prefix.Masked(), true
	}
	if prefix.Bits() < 96 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address.Unmap(), prefix.Bits()-96).Masked(), true
}

func ValidateDelegation(parent, child Subject) error {
	if parent.ID == "" || child.ID == "" {
		return errors.New("both subjects require an id")
	}
	for _, field := range []struct {
		name   string
		parent []string
		child  []string
	}{
		{"tools", parent.Tools, child.Tools},
		{"target kinds", parent.TargetKinds, child.TargetKinds},
		{"risk levels", parent.RiskLevels, child.RiskLevels},
		{"providers", parent.Providers, child.Providers},
		{"operations", parent.Operations, child.Operations},
		{"accounts", parent.Accounts, child.Accounts},
		{"resources", parent.Resources, child.Resources},
		{"environments", parent.Environments, child.Environments},
	} {
		if !subset(field.child, field.parent) {
			return fmt.Errorf("child %s exceed parent", field.name)
		}
	}
	if parent.PrincipalType != "human" && child.PrincipalType != parent.PrincipalType {
		return errors.New("child changed principal type")
	}
	if child.Role != parent.Role {
		return errors.New("child changed role")
	}
	if child.SecurityProfile != parent.SecurityProfile {
		return errors.New("child changed security profile")
	}
	if child.MaximumTTL <= 0 || parent.MaximumTTL <= 0 || child.MaximumTTL > parent.MaximumTTL {
		return errors.New("child ttl exceeds parent")
	}
	if parent.RequiresApproval && !child.RequiresApproval {
		return errors.New("child removed approval requirement")
	}
	if parent.RequiresTwoPersons && !child.RequiresTwoPersons {
		return errors.New("child removed two-person requirement")
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func subset(child, parent []string) bool {
	if len(child) == 0 {
		return false
	}
	for _, value := range child {
		if !contains(parent, value) {
			return false
		}
	}
	return true
}
