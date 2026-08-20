package engine_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/grasp-labs/ds-go-policy/conditionoperator"
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
			Conditions: policy.Conditions{conditionoperator.Bool: {"mfa": {"true"}}},
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
		{"StringEquals hit", policy.Conditions{conditionoperator.StringEquals: {"dept": {"eng"}}}, map[string]string{"dept": "eng"}, true},
		{"StringEquals miss", policy.Conditions{conditionoperator.StringEquals: {"dept": {"eng"}}}, map[string]string{"dept": "sales"}, false},
		{"StringEquals multi-value OR", policy.Conditions{conditionoperator.StringEquals: {"dept": {"eng", "sales"}}}, map[string]string{"dept": "sales"}, true},
		{"StringNotEquals hit", policy.Conditions{conditionoperator.StringNotEquals: {"dept": {"eng"}}}, map[string]string{"dept": "sales"}, true},
		{"StringNotEquals absent is true", policy.Conditions{conditionoperator.StringNotEquals: {"dept": {"eng"}}}, map[string]string{}, true},
		{"StringLike wildcard", policy.Conditions{conditionoperator.StringLike: {"path": {"home/*"}}}, map[string]string{"path": "home/alice"}, true},
		{"StringLike no match", policy.Conditions{conditionoperator.StringLike: {"path": {"home/*"}}}, map[string]string{"path": "work/alice"}, false},
		{"NumericLessThan", policy.Conditions{conditionoperator.NumericLessThan: {"n": {"10"}}}, map[string]string{"n": "5"}, true},
		{"NumericGreaterThanEquals", policy.Conditions{conditionoperator.NumericGreaterThanEquals: {"n": {"10"}}}, map[string]string{"n": "10"}, true},
		{"DateLessThan", policy.Conditions{conditionoperator.DateLessThan: {"t": {"2026-01-01T00:00:00Z"}}}, map[string]string{"t": "2025-06-01T00:00:00Z"}, true},
		{"IpAddress in CIDR", policy.Conditions{conditionoperator.IPAddress: {"ip": {"10.0.0.0/8"}}}, map[string]string{"ip": "10.1.2.3"}, true},
		{"IpAddress outside CIDR", policy.Conditions{conditionoperator.IPAddress: {"ip": {"10.0.0.0/8"}}}, map[string]string{"ip": "192.168.1.1"}, false},
		{"Null must-be-absent", policy.Conditions{conditionoperator.Null: {"opt": {"true"}}}, map[string]string{}, true},
		{"Null must-be-present", policy.Conditions{conditionoperator.Null: {"opt": {"false"}}}, map[string]string{"opt": "x"}, true},
		{"IfExists passes when absent", policy.Conditions{conditionoperator.WithIfExists(conditionoperator.StringEquals): {"dept": {"eng"}}}, map[string]string{}, true},
		{"IfExists evaluates when present", policy.Conditions{conditionoperator.WithIfExists(conditionoperator.StringEquals): {"dept": {"eng"}}}, map[string]string{"dept": "sales"}, false},
		{"multiple operators AND", policy.Conditions{conditionoperator.StringEquals: {"dept": {"eng"}}, conditionoperator.Bool: {"mfa": {"true"}}}, map[string]string{"dept": "eng", "mfa": "true"}, true},
		{"multiple operators AND one fails", policy.Conditions{conditionoperator.StringEquals: {"dept": {"eng"}}, conditionoperator.Bool: {"mfa": {"true"}}}, map[string]string{"dept": "eng", "mfa": "false"}, false},
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

// resource.path[N] conditions the Nth path segment on a value set — one
// pattern plus a value list instead of one resource pattern per partition.
func TestDecide_ResourcePathSegmentCondition(t *testing.T) {
	pol := policy.Policy{Statements: []policy.Statement{{
		Sid:       "inbound-by-org",
		Effect:    policy.Allow,
		Actions:   []string{"file:getFile"},
		Resources: []string{crnPattern("files/inbound/**")},
		Conditions: policy.Conditions{
			conditionoperator.StringEquals: {"resource.path[2]": {"123456789", "23456788"}},
		},
	}}}

	decide := func(path string, ctx map[string]string) engine.Decision {
		return engine.Decide([]policy.Policy{pol},
			engine.Request{Action: "file:getFile", Resource: mustResource(t, path), Context: ctx})
	}

	if got := decide("files/inbound/123456789/report.csv", nil); !got.Allowed {
		t.Errorf("org in list: got deny (%q), want allow", got.Reason)
	}
	if got := decide("files/inbound/23456788/report.csv", nil); !got.Allowed {
		t.Errorf("second org in list: got deny (%q), want allow", got.Reason)
	}
	if got := decide("files/inbound/999999999/report.csv", nil); got.Allowed {
		t.Errorf("org not in list: got allow, want implicit deny")
	}
	// Path too short: the segment is absent, so the positive operator fails.
	if got := decide("files/inbound", nil); got.Allowed {
		t.Errorf("missing segment: got allow, want implicit deny")
	}
	// The key resolves from the resource, never the context — no spoofing.
	spoof := map[string]string{"resource.path[2]": "123456789"}
	if got := decide("files/inbound/999999999/report.csv", spoof); got.Allowed {
		t.Errorf("context spoof: got allow, want implicit deny")
	}
}

// The absent-segment semantics compose with IfExists: "if there is a segment
// at N, it must be one of these".
func TestDecide_ResourcePathSegmentIfExists(t *testing.T) {
	pol := policy.Policy{Statements: []policy.Statement{{
		Sid: "inbound", Effect: policy.Allow, Actions: []string{"file:getFile"},
		Resources: []string{crnPattern("files/inbound/**")},
		Conditions: policy.Conditions{
			conditionoperator.WithIfExists(conditionoperator.StringEquals): {"resource.path[2]": {"123456789"}},
		},
	}}}
	decide := func(path string) engine.Decision {
		return engine.Decide([]policy.Policy{pol},
			engine.Request{Action: "file:getFile", Resource: mustResource(t, path)})
	}
	if got := decide("files/inbound"); !got.Allowed {
		t.Errorf("segment absent: got deny (%q), want allow (IfExists)", got.Reason)
	}
	if got := decide("files/inbound/123456789/x"); !got.Allowed {
		t.Errorf("segment in set: got deny (%q), want allow", got.Reason)
	}
	if got := decide("files/inbound/999/x"); got.Allowed {
		t.Errorf("segment not in set: got allow, want implicit deny")
	}
}

// ResourcePathKey is the exported form adapters use to recognize segment keys.
func TestResourcePathKey(t *testing.T) {
	if n, ok := engine.ResourcePathKey("resource.path[2]"); !ok || n != 2 {
		t.Errorf("ResourcePathKey(resource.path[2]) = %d, %v; want 2, true", n, ok)
	}
	if _, ok := engine.ResourcePathKey("status"); ok {
		t.Errorf("ResourcePathKey(status) = ok, want not a segment key")
	}
}

// The "resource." condition-key namespace is reserved: only well-formed
// resource.path[N] keys compile; malformed ones fail closed at load time.
func TestCompile_ResourceKeyValidation(t *testing.T) {
	cases := []struct {
		key   string
		valid bool
	}{
		{"resource.path[0]", true},
		{"resource.path[12]", true},
		{"resource.path[two]", false},
		{"resource.path[-1]", false},
		{"resource.path[]", false},
		{"resource.path[1", false},
		{"resource.path", false},
		{"resource.owner", false},
		{"department", true}, // ordinary context key, not reserved
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			pol := policy.Policy{Statements: []policy.Statement{{
				Sid: "s", Effect: policy.Allow, Actions: []string{"*"},
				Resources:  []string{crnPattern("files/**")},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {tc.key: {"x"}}},
			}}}
			_, err := engine.Compile([]policy.Policy{pol})
			if tc.valid && err != nil {
				t.Errorf("Compile(%q) = %v, want ok", tc.key, err)
			}
			if !tc.valid && !errors.Is(err, engine.ErrInvalidResourceKey) {
				t.Errorf("Compile(%q) = %v, want ErrInvalidResourceKey", tc.key, err)
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

func TestCompile_ConditionKeyMapValidation(t *testing.T) {
	tests := []struct {
		name       string
		conditions policy.Conditions
		wantErr    error
	}{
		{name: "no conditions"},
		{name: "empty top-level conditions", conditions: policy.Conditions{}},
		{
			name:       "condition with a key",
			conditions: policy.Conditions{conditionoperator.StringEquals: {"department": {"engineering"}}},
		},
		{
			name:       "empty key map",
			conditions: policy.Conditions{conditionoperator.StringEquals: {}},
			wantErr:    engine.ErrNoConditionKeys,
		},
		{
			name:       "nil key map",
			conditions: policy.Conditions{conditionoperator.StringEquals: nil},
			wantErr:    engine.ErrNoConditionKeys,
		},
		{
			name: "one valid and one empty operator",
			conditions: policy.Conditions{
				conditionoperator.Bool:         {"mfa": {"true"}},
				conditionoperator.StringEquals: {},
			},
			wantErr: engine.ErrNoConditionKeys,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pol := policy.Policy{Statements: []policy.Statement{{
				Sid: "s", Effect: policy.Allow, Actions: []string{"*"},
				Resources:  []string{crnPattern("datalake/**")},
				Conditions: test.conditions,
			}}}

			_, err := engine.Compile([]policy.Policy{pol})
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("Compile() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Errorf("Compile() = %v, want %v", err, test.wantErr)
			}
			if !errors.Is(err, engine.ErrInvalidConditions) {
				t.Errorf("Compile() = %v, want ErrInvalidConditions", err)
			}
		})
	}
}
