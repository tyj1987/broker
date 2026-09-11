package policy

import (
	"testing"
	"time"
)

func baseline() (Subject, Request, Rule) {
	subject := Subject{
		ID: "workload-1", Role: "automation", PrincipalType: "agent", SecurityProfile: "strict",
		Tools: []string{"github.repository.read@1.0.0"}, TargetKinds: []string{"github-repository"},
		RiskLevels: []string{"LOW"},
		Providers:  []string{"github"}, Operations: []string{"repo.read"},
		Accounts: []string{"personal"}, Resources: []string{"tyj1987/broker"},
		Environments: []string{"production"}, MaximumTTL: 5 * time.Minute,
	}
	request := Request{
		Tool: "github.repository.read@1.0.0", TargetKind: "github-repository", RiskLevel: "LOW",
		Provider: "github", Operation: "repo.read", Account: "personal",
		Resource: "tyj1987/broker", Environment: "production", RequestedTTL: time.Minute,
		SourceIP: "203.0.113.42", At: time.Now().UTC(),
	}
	rule := Rule{
		Enabled: true, Tools: []string{"github.repository.read@1.0.0"}, TargetKinds: []string{"github-repository"},
		RiskLevels: []string{"LOW"}, AllowAgentExecute: true,
		Roles: []string{"automation"}, SecurityProfiles: []string{"strict"},
		Providers: []string{"github"}, Operations: []string{"repo.read"},
		Accounts: []string{"personal"}, Resources: []string{"tyj1987/broker"},
		Environments: []string{"production"}, MaximumTTL: 2 * time.Minute,
	}
	return subject, request, rule
}

func TestEvaluateAllowsExactIntersection(t *testing.T) {
	subject, request, rule := baseline()
	decision := Evaluate(subject, request, rule)
	if !decision.Allow || decision.TTL != time.Minute {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestEvaluateFailsClosedForEveryDimension(t *testing.T) {
	mutations := map[string]func(*Request){
		"tool":        func(r *Request) { r.Tool = "github.repository.write@1.0.0" },
		"target kind": func(r *Request) { r.TargetKind = "organization" },
		"risk":        func(r *Request) { r.RiskLevel = "HIGH" },
		"provider":    func(r *Request) { r.Provider = "openai" },
		"operation":   func(r *Request) { r.Operation = "repo.write" },
		"account":     func(r *Request) { r.Account = "other" },
		"resource":    func(r *Request) { r.Resource = "other/repo" },
		"environment": func(r *Request) { r.Environment = "development" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			subject, request, rule := baseline()
			mutate(&request)
			if Evaluate(subject, request, rule).Allow {
				t.Fatal("mismatched authorization dimension was allowed")
			}
		})
	}
}

func TestEvaluateRiskFloor(t *testing.T) {
	subject, request, rule := baseline()
	request.RiskLevel = "HIGH"
	subject.RiskLevels = []string{"HIGH"}
	rule.RiskLevels = []string{"HIGH"}
	if decision := Evaluate(subject, request, rule); decision.Code != "approval_required" {
		t.Fatalf("expected HIGH approval denial, got %#v", decision)
	}
	request.ApprovalCount = 1
	if decision := Evaluate(subject, request, rule); !decision.Allow {
		t.Fatalf("expected approved HIGH request, got %#v", decision)
	}

	request.RiskLevel = "CRITICAL"
	subject.RiskLevels = []string{"CRITICAL"}
	rule.RiskLevels = []string{"CRITICAL"}
	rule.AllowAgentExecute = false
	if decision := Evaluate(subject, request, rule); decision.Code != "agent_execution_denied" {
		t.Fatalf("expected agent denial, got %#v", decision)
	}
	subject.PrincipalType = "human"
	request.StepUp = true
	request.ApprovalCount = 2
	if decision := Evaluate(subject, request, rule); !decision.Allow {
		t.Fatalf("expected stepped-up human CRITICAL request, got %#v", decision)
	}
}

func TestEvaluateRejectsMalformedApprovalBounds(t *testing.T) {
	subject, request, rule := baseline()
	rule.RequiredApprovals = -1
	if decision := Evaluate(subject, request, rule); decision.Code != "invalid_rule" {
		t.Fatalf("expected malformed negative approval rule denial, got %#v", decision)
	}
	rule.RequiredApprovals = 11
	if decision := Evaluate(subject, request, rule); decision.Code != "invalid_rule" {
		t.Fatalf("expected oversized approval rule denial, got %#v", decision)
	}
	rule.RequiredApprovals = 0
	request.ApprovalCount = -1
	if decision := Evaluate(subject, request, rule); decision.Code != "invalid_request" {
		t.Fatalf("expected malformed negative approval count denial, got %#v", decision)
	}
	request.ApprovalCount = 11
	if decision := Evaluate(subject, request, rule); decision.Code != "invalid_request" {
		t.Fatalf("expected oversized approval count denial, got %#v", decision)
	}
}

func TestApprovalPreflightDoesNotExecute(t *testing.T) {
	subject, request, rule := baseline()
	request.RiskLevel = "HIGH"
	request.ApprovalPhase = true
	subject.RiskLevels = []string{"HIGH"}
	rule.RiskLevels = []string{"HIGH"}
	if decision := Evaluate(subject, request, rule); !decision.Allow {
		t.Fatalf("approval preflight should authorize request creation: %#v", decision)
	}
}

func TestEvaluateApprovalAndTTL(t *testing.T) {
	subject, request, rule := baseline()
	subject.RequiresTwoPersons = true
	request.RequestedTTL = 10 * time.Minute
	if decision := Evaluate(subject, request, rule); decision.Code != "approval_required" {
		t.Fatalf("expected approval denial, got %#v", decision)
	}
	request.ApprovalCount = 2
	if decision := Evaluate(subject, request, rule); !decision.Allow || decision.TTL != 2*time.Minute {
		t.Fatalf("expected bounded allow, got %#v", decision)
	}
}

func TestDelegationCannotExpandParent(t *testing.T) {
	parent, _, _ := baseline()
	child := parent
	child.ID = "api-key-child"
	child.MaximumTTL = time.Minute
	if err := ValidateDelegation(parent, child); err != nil {
		t.Fatalf("valid child denied: %v", err)
	}
	child.Providers = []string{"github", "openai"}
	if err := ValidateDelegation(parent, child); err == nil {
		t.Fatal("expanded child delegation was allowed")
	}
}

func TestEvaluateDenyConditions(t *testing.T) {
	tests := map[string]struct {
		change func(*Subject, *Request, *Rule)
		code   string
	}{
		"invalid subject":    {func(s *Subject, _ *Request, _ *Rule) { s.ID = "" }, "invalid_subject"},
		"invalid request":    {func(_ *Subject, r *Request, _ *Rule) { r.Provider = "" }, "invalid_request"},
		"invalid risk":       {func(_ *Subject, r *Request, _ *Rule) { r.RiskLevel = "UNKNOWN" }, "invalid_request"},
		"disabled":           {func(_ *Subject, _ *Request, p *Rule) { p.Enabled = false }, "rule_disabled"},
		"role":               {func(s *Subject, _ *Request, _ *Rule) { s.Role = "reader" }, "role_denied"},
		"profile":            {func(s *Subject, _ *Request, _ *Rule) { s.SecurityProfile = "compatible" }, "profile_denied"},
		"step up":            {func(s *Subject, _ *Request, _ *Rule) { s.RequiresApproval = true }, "step_up_required"},
		"invalid ttl":        {func(_ *Subject, r *Request, _ *Rule) { r.RequestedTTL = 0 }, "invalid_ttl"},
		"missing ttl policy": {func(s *Subject, _ *Request, _ *Rule) { s.MaximumTTL = 0 }, "ttl_policy_missing"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject, request, rule := baseline()
			test.change(&subject, &request, &rule)
			if decision := Evaluate(subject, request, rule); decision.Allow || decision.Code != test.code {
				t.Fatalf("expected %s, got %#v", test.code, decision)
			}
		})
	}
}

func TestEvaluateTimeWindow(t *testing.T) {
	subject, request, rule := baseline()
	future := request.At.Add(time.Minute)
	rule.NotBefore = &future
	if decision := Evaluate(subject, request, rule); decision.Code != "outside_time_window" {
		t.Fatalf("expected not-before denial, got %#v", decision)
	}
	past := request.At
	rule.NotBefore = nil
	rule.NotAfter = &past
	if decision := Evaluate(subject, request, rule); decision.Code != "outside_time_window" {
		t.Fatalf("expected not-after denial, got %#v", decision)
	}
}

func TestEvaluateSourceCIDRs(t *testing.T) {
	tests := []struct {
		name   string
		source string
		cidrs  []string
		allow  bool
		code   string
	}{
		{"ipv4", "203.0.113.42", []string{"203.0.113.0/24"}, true, "allowed"},
		{"ipv4 mapped", "::ffff:203.0.113.42", []string{"203.0.113.0/24"}, true, "allowed"},
		{"ipv6", "2001:db8::42", []string{"2001:db8::/32"}, true, "allowed"},
		{"outside", "198.51.100.1", []string{"203.0.113.0/24"}, false, "source_ip_denied"},
		{"missing", "", []string{"203.0.113.0/24"}, false, "source_ip_denied"},
		{"invalid source", "not-an-ip", []string{"203.0.113.0/24"}, false, "source_ip_denied"},
		{"invalid cidr", "203.0.113.42", []string{"203.0.113.0/24", "invalid"}, false, "invalid_rule"},
		{"invalid mapped cidr", "203.0.113.42", []string{"::ffff:0:0/80"}, false, "invalid_rule"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject, request, rule := baseline()
			request.SourceIP = test.source
			rule.SourceCIDRs = test.cidrs
			decision := Evaluate(subject, request, rule)
			if decision.Allow != test.allow || decision.Code != test.code {
				t.Fatalf("unexpected decision: %#v", decision)
			}
		})
	}
}

func TestEvaluateRejectsInvertedTimeWindow(t *testing.T) {
	subject, request, rule := baseline()
	start := request.At.Add(time.Minute)
	end := request.At
	rule.NotBefore = &start
	rule.NotAfter = &end
	if decision := Evaluate(subject, request, rule); decision.Code != "invalid_rule" {
		t.Fatalf("expected invalid rule, got %#v", decision)
	}
}

func TestDelegationDeniesWeakerChild(t *testing.T) {
	parent, _, _ := baseline()
	parent.RequiresApproval = true
	parent.RequiresTwoPersons = true
	child := parent
	child.ID = "child"
	child.MaximumTTL = time.Minute

	child.RequiresApproval = false
	if err := ValidateDelegation(parent, child); err == nil {
		t.Fatal("child removed approval requirement")
	}
	child.RequiresApproval = true
	child.RequiresTwoPersons = false
	if err := ValidateDelegation(parent, child); err == nil {
		t.Fatal("child removed two-person requirement")
	}
	child.RequiresTwoPersons = true
	child.MaximumTTL = parent.MaximumTTL + time.Second
	if err := ValidateDelegation(parent, child); err == nil {
		t.Fatal("child expanded ttl")
	}
}
