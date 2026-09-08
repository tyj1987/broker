package policy

import (
	"testing"
	"time"
)

func baseline() (Subject, Request, Rule) {
	subject := Subject{
		ID: "workload-1", Role: "automation", SecurityProfile: "strict",
		Providers: []string{"github"}, Operations: []string{"repo.read"},
		Accounts: []string{"personal"}, Resources: []string{"tyj1987/broker"},
		Environments: []string{"production"}, MaximumTTL: 5 * time.Minute,
	}
	request := Request{
		Provider: "github", Operation: "repo.read", Account: "personal",
		Resource: "tyj1987/broker", Environment: "production", RequestedTTL: time.Minute,
		At: time.Now().UTC(),
	}
	rule := Rule{
		Enabled: true, Roles: []string{"automation"}, SecurityProfiles: []string{"strict"},
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
