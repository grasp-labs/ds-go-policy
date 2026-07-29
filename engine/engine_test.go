package engine_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

const (
	tenant = "ba62a53f-afa9-427d-9d91-c7987bc5662e"
	owner  = "d0498be0-aae2-41c1-9f02-a2d8d9548360"
	// real uuid for a workflow
	workflowID = "ba62a53f-afa9-427d-9d91-c7987bc5662e"
)

// crnPattern builds a resource pattern string for the file service.
func crnPattern(resource string) string {
	return fmt.Sprintf("crn:%s:*:file::file:%s", tenant, resource)
}

// mustResource builds a concrete request resource, failing the test on error.
func mustResource(t *testing.T, resource string) crn.CRN {
	t.Helper()
	c, err := crn.Build(tenant, owner, "file", "", "file", resource)
	if err != nil {
		t.Fatalf("Build(%q): %v", resource, err)
	}
	return c
}

// samplePolicy grants read/list over the datalake, allows writes only under
// datalake/raw, and explicitly denies anything under datalake/secret.
func samplePolicy() policy.Policy {
	return policy.Policy{
		ID:      "pol-1",
		Version: "1.0.0",
		Statements: []policy.Statement{
			{
				Sid:       "read-datalake",
				Effect:    policy.Allow,
				Actions:   []string{"file:getFile", "file:listFiles"},
				Resources: []string{crnPattern("datalake/**")},
			},
			{
				Sid:       "write-raw-only",
				Effect:    policy.Allow,
				Actions:   []string{"file:*"},
				Resources: []string{crnPattern("datalake/raw/**")},
			},
			{
				Sid:       "protect-secrets",
				Effect:    policy.Deny,
				Actions:   []string{"*"},
				Resources: []string{crnPattern("datalake/secret/**")},
			},
			{
				Sid:       "read-single-workflow",
				Effect:    policy.Allow,
				Actions:   []string{"config:getWorkflow"},
				Resources: []string{crnPattern("workflows/" + workflowID)},
			},
		},
	}
}

func TestDecide_APIRequestSimulation(t *testing.T) {
	pol := samplePolicy()

	tests := []struct {
		name       string
		action     string
		resource   string
		wantAllow  bool
		wantReason string
	}{
		{
			name:       "read allowed under datalake",
			action:     "file:getFile",
			resource:   "datalake/reports/q1.csv",
			wantAllow:  true,
			wantReason: "read-datalake",
		},
		{
			name:       "list allowed at datalake root",
			action:     "file:listFiles",
			resource:   "datalake",
			wantAllow:  true,
			wantReason: "read-datalake",
		},
		{
			name:       "write allowed only under raw",
			action:     "file:putFile",
			resource:   "datalake/raw/ingest/2026.parquet",
			wantAllow:  true,
			wantReason: "write-raw-only",
		},
		{
			name:      "write outside raw is implicit deny",
			action:    "file:putFile",
			resource:  "datalake/reports/q1.csv",
			wantAllow: false, wantReason: "implicit deny",
		},
		{
			name:       "explicit deny wins over allow on secrets",
			action:     "file:getFile", // matched by read-datalake AND protect-secrets
			resource:   "datalake/secret/keys.txt",
			wantAllow:  false,
			wantReason: "protect-secrets",
		},
		{
			name:      "unknown action is implicit deny",
			action:    "file:deleteBucket",
			resource:  "datalake/reports/q1.csv",
			wantAllow: false, wantReason: "implicit deny",
		},
		{
			name:       "read single workflow",
			action:     "config:getWorkflow",
			resource:   "workflows/" + workflowID,
			wantAllow:  true,
			wantReason: "read-single-workflow",
		},
		{
			name:      "read another workflow is implicit deny",
			action:    "config:getWorkflow",
			resource:  "workflows/other-workflow",
			wantAllow: false, wantReason: "implicit deny",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := engine.Request{
				Action:   test.action,
				Resource: mustResource(t, test.resource),
			}
			got := engine.Decide([]policy.Policy{pol}, req)
			t.Logf("Decide(%s on %s) = {Allowed:%v Reason:%q}", test.action, test.resource, got.Allowed, got.Reason)
			if got.Allowed != test.wantAllow || got.Reason != test.wantReason {
				t.Errorf("Decide(%s on %s) = {Allowed:%v Reason:%q}, want {Allowed:%v Reason:%q}",
					test.action, test.resource, got.Allowed, got.Reason, test.wantAllow, test.wantReason)
			}
		})
	}
}

func TestDecide_DenyWinsRegardlessOfOrder(t *testing.T) {
	// Deny appears BEFORE the allow; deny must still win.
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "deny-first", Effect: policy.Deny, Actions: []string{"*"}, Resources: []string{crnPattern("datalake/**")}},
			{Sid: "allow-second", Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{crnPattern("datalake/**")}},
		},
	}
	req := engine.Request{Action: "file:getFile", Resource: mustResource(t, "datalake/x")}
	if got := engine.Decide([]policy.Policy{pol}, req); got.Allowed {
		t.Errorf("Decide = allowed, want deny (deny-wins); reason=%q", got.Reason)
	}
}

func TestDecide_FailsClosedOnBadEffect(t *testing.T) {
	// A statement with an unrecognized effect must NOT be treated as allow.
	pol := policy.Policy{
		Statements: []policy.Statement{{
			Sid:       "typo-effect",
			Effect:    "Allow", // wrong case: not policy.Allow
			Actions:   []string{"file:getFile"},
			Resources: []string{crnPattern("datalake/**")},
		}},
	}
	req := engine.Request{Action: "file:getFile", Resource: mustResource(t, "datalake/x")}
	if got := engine.Decide([]policy.Policy{pol}, req); got.Allowed {
		t.Errorf("Decide with bad effect = allowed, want deny (fail closed)")
	}
}

func TestDecide_FailsClosedOnBadDenyPattern(t *testing.T) {
	// A malformed DENY pattern must not be silently skipped (that would be
	// fail-open); the whole policy set is rejected and the request denied.
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "allow-all", Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{crnPattern("datalake/**")}},
			{Sid: "broken-deny", Effect: policy.Deny, Actions: []string{"*"}, Resources: []string{"not-a-valid-crn"}},
		},
	}
	req := engine.Request{Action: "file:getFile", Resource: mustResource(t, "datalake/x")}
	if got := engine.Decide([]policy.Policy{pol}, req); got.Allowed {
		t.Errorf("Decide with malformed deny pattern = allowed, want deny (fail closed)")
	}
}

func TestCompile_ReportsError(t *testing.T) {
	pol := policy.Policy{
		ID: "pol-bad",
		Statements: []policy.Statement{
			{Sid: "s", Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{"not-a-valid-crn"}},
		},
	}
	if _, err := engine.Compile([]policy.Policy{pol}); !errors.Is(err, crn.ErrInvalidPartCount) {
		t.Errorf("Compile err = %v, want wrapped ErrInvalidPartCount", err)
	}
}

func TestDecide_CrossTenantResourceNeverMatches(t *testing.T) {
	// A pattern naming another tenant compiles, but tenant isolation holds at
	// evaluation: it can never match this tenant's resources.
	otherTenant := "11111111-1111-1111-1111-111111111111"
	pol := policy.Policy{
		ID: "pol-x",
		Statements: []policy.Statement{
			{Sid: "s", Effect: policy.Allow, Actions: []string{"*"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file::file:**", otherTenant)}},
		},
	}
	req := engine.Request{Action: "file:getFile", Resource: mustResource(t, "datalake/x")}
	if got := engine.Decide([]policy.Policy{pol}, req); got.Allowed {
		t.Errorf("cross-tenant allow matched; want implicit deny, got %q", got.Reason)
	}
}

// platformPolicy is a platform-issued policy: its patterns use the reserved
// platform token as the tenant placeholder, so one document applies to every
// tenant.
func platformPolicy(statements ...policy.Statement) policy.Policy {
	return policy.Policy{
		ID:         "aic-managed",
		Version:    "1.0.0",
		Statements: statements,
	}
}

func TestDecide_PlatformPolicyAppliesToAnyTenant(t *testing.T) {
	// A platform-issued allow grants the action on the requesting tenant's own
	// resources without naming that tenant anywhere in the document.
	pol := platformPolicy(policy.Statement{
		Sid:       "aic-read-datalake",
		Effect:    policy.Allow,
		Actions:   []string{"file:getFile"},
		Resources: []string{fmt.Sprintf("crn:%s:*:file::file:datalake/**", crn.PlatformTenant)},
	})
	req := engine.Request{Action: "file:getFile", Resource: mustResource(t, "datalake/reports/q1.csv")}
	got := engine.Decide([]policy.Policy{pol}, req)
	if !got.Allowed || got.Reason != "aic-read-datalake" {
		t.Errorf("Decide = {Allowed:%v Reason:%q}, want allow via aic-read-datalake", got.Allowed, got.Reason)
	}
}

func TestDecide_PlatformGuardrailDenyWins(t *testing.T) {
	// A platform-issued deny is a guardrail: it overrides a tenant's own allow.
	guardrail := platformPolicy(policy.Statement{
		Sid:       "aic-protect-secrets",
		Effect:    policy.Deny,
		Actions:   []string{"*"},
		Resources: []string{fmt.Sprintf("crn:%s:*:file::file:datalake/secret/**", crn.PlatformTenant)},
	})
	// The tenant policy allows the whole datalake and has no deny of its own.
	tenantAllow := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "read-datalake", Effect: policy.Allow, Actions: []string{"*"},
				Resources: []string{crnPattern("datalake/**")}},
		},
	}
	req := engine.Request{Action: "file:getFile", Resource: mustResource(t, "datalake/secret/keys.txt")}
	got := engine.Decide([]policy.Policy{tenantAllow, guardrail}, req)
	if got.Allowed || got.Reason != "aic-protect-secrets" {
		t.Errorf("Decide = {Allowed:%v Reason:%q}, want deny via aic-protect-secrets", got.Allowed, got.Reason)
	}
}

func TestCompile_AcceptsValidPolicy(t *testing.T) {
	if _, err := engine.Compile([]policy.Policy{samplePolicy()}); err != nil {
		t.Errorf("Compile err = %v, want nil", err)
	}
}

func TestDecide_ConditionGating(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{{
			Sid:        "mfa-required",
			Effect:     policy.Allow,
			Actions:    []string{"file:getFile"},
			Resources:  []string{crnPattern("datalake/**")},
			Conditions: policy.Conditions{"Bool": {"mfa": {"true"}}},
		}},
	}
	res := mustResource(t, "datalake/x")

	if got := engine.Decide([]policy.Policy{pol}, engine.Request{Action: "file:getFile", Resource: res, Context: map[string]string{"mfa": "true"}}); !got.Allowed {
		t.Errorf("with mfa=true: got deny, want allow")
	}
	if got := engine.Decide([]policy.Policy{pol}, engine.Request{Action: "file:getFile", Resource: res, Context: map[string]string{"mfa": "false"}}); got.Allowed {
		t.Errorf("with mfa=false: got allow, want implicit deny")
	}
	// missing key: positive operator must not pass -> implicit deny
	if got := engine.Decide([]policy.Policy{pol}, engine.Request{Action: "file:getFile", Resource: res}); got.Allowed {
		t.Errorf("with mfa absent: got allow, want implicit deny")
	}
}

func TestDecide_ConditionOperators(t *testing.T) {
	res := mustResource(t, "datalake/x")

	tests := []struct {
		name  string
		conds policy.Conditions
		ctx   map[string]string
		want  bool
	}{
		{"StringEquals hit", policy.Conditions{"StringEquals": {"dept": {"eng"}}}, map[string]string{"dept": "eng"}, true},
		{"StringEquals miss", policy.Conditions{"StringEquals": {"dept": {"eng"}}}, map[string]string{"dept": "sales"}, false},
		{"StringEquals multi-value OR", policy.Conditions{"StringEquals": {"dept": {"eng", "sales"}}}, map[string]string{"dept": "sales"}, true},
		{"StringNotEquals hit", policy.Conditions{"StringNotEquals": {"dept": {"eng"}}}, map[string]string{"dept": "sales"}, true},
		{"StringNotEquals absent is true", policy.Conditions{"StringNotEquals": {"dept": {"eng"}}}, map[string]string{}, true},
		{"StringLike wildcard", policy.Conditions{"StringLike": {"path": {"home/*"}}}, map[string]string{"path": "home/alice"}, true},
		{"StringLike no match", policy.Conditions{"StringLike": {"path": {"home/*"}}}, map[string]string{"path": "work/alice"}, false},
		{"NumericLessThan", policy.Conditions{"NumericLessThan": {"n": {"10"}}}, map[string]string{"n": "5"}, true},
		{"NumericGreaterThanEquals", policy.Conditions{"NumericGreaterThanEquals": {"n": {"10"}}}, map[string]string{"n": "10"}, true},
		{"DateLessThan", policy.Conditions{"DateLessThan": {"t": {"2026-01-01T00:00:00Z"}}}, map[string]string{"t": "2025-06-01T00:00:00Z"}, true},
		{"IpAddress in CIDR", policy.Conditions{"IpAddress": {"ip": {"10.0.0.0/8"}}}, map[string]string{"ip": "10.1.2.3"}, true},
		{"IpAddress outside CIDR", policy.Conditions{"IpAddress": {"ip": {"10.0.0.0/8"}}}, map[string]string{"ip": "192.168.1.1"}, false},
		{"Null must-be-absent", policy.Conditions{"Null": {"opt": {"true"}}}, map[string]string{}, true},
		{"Null must-be-present", policy.Conditions{"Null": {"opt": {"false"}}}, map[string]string{"opt": "x"}, true},
		{"IfExists passes when absent", policy.Conditions{"StringEqualsIfExists": {"dept": {"eng"}}}, map[string]string{}, true},
		{"IfExists evaluates when present", policy.Conditions{"StringEqualsIfExists": {"dept": {"eng"}}}, map[string]string{"dept": "sales"}, false},
		{"multiple operators AND", policy.Conditions{"StringEquals": {"dept": {"eng"}}, "Bool": {"mfa": {"true"}}}, map[string]string{"dept": "eng", "mfa": "true"}, true},
		{"multiple operators AND one fails", policy.Conditions{"StringEquals": {"dept": {"eng"}}, "Bool": {"mfa": {"true"}}}, map[string]string{"dept": "eng", "mfa": "false"}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pol := policy.Policy{Statements: []policy.Statement{{
				Sid: "s", Effect: policy.Allow, Actions: []string{"file:getFile"},
				Resources: []string{crnPattern("datalake/**")}, Conditions: test.conds,
			}}}
			got := engine.Decide([]policy.Policy{pol}, engine.Request{Action: "file:getFile", Resource: res, Context: test.ctx})
			if got.Allowed != test.want {
				t.Errorf("Decide allowed = %v, want %v", got.Allowed, test.want)
			}
		})
	}
}

func TestCompile_RejectsUnknownOperator(t *testing.T) {
	pol := policy.Policy{Statements: []policy.Statement{{
		Sid: "s", Effect: policy.Allow, Actions: []string{"*"},
		Resources:  []string{crnPattern("datalake/**")},
		Conditions: policy.Conditions{"StringWobble": {"k": {"v"}}},
	}}}
	if _, err := engine.Compile([]policy.Policy{pol}); !errors.Is(err, engine.ErrUnknownOperator) {
		t.Errorf("Compile err = %v, want ErrUnknownOperator", err)
	}
}
