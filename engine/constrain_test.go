package engine_test

import (
	"fmt"
	"testing"

	"github.com/grasp-labs/ds-go-policy/conditionoperator"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

const constrainTenant = "ba62a53f-afa9-427d-9d91-c7987bc5662e"

func res(path string) string {
	return fmt.Sprintf("crn:%s:*:file::file:%s", constrainTenant, path)
}

// A policy that exercises the three condition outcomes at Constrain time:
//   - "team": context-only condition (department) → resolved now
//   - "public": no condition → always applies
//   - "reports": resource-attribute condition (status) → deferred to adapter
//   - "protect": deny gated by a context-only condition (department)
func constrainPolicy() policy.Policy {
	return policy.Policy{
		ID: "p",
		Statements: []policy.Statement{
			{
				Sid: "team", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{res("datalake/**")},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {"department": {"engineering"}}},
			},
			{
				Sid: "public", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources: []string{res("public/**")},
			},
			{
				Sid: "reports", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{res("reports/**")},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {"status": {"active"}}},
			},
			{
				Sid: "protect", Effect: policy.Deny, Actions: []string{"*"},
				Resources:  []string{res("datalake/secret/**")},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {"department": {"engineering"}}},
			},
		},
	}
}

func allowPaths(c engine.Constraints) []string {
	out := make([]string, 0, len(c.Allow))
	for _, rm := range c.Allow {
		out = append(out, rm.Pattern.Resource())
	}
	return out
}

func denyPaths(c engine.Constraints) []string {
	out := make([]string, 0, len(c.Deny))
	for _, rm := range c.Deny {
		out = append(out, rm.Pattern.Resource())
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// findAllow returns the ResourceMatch for a given resource path.
func findAllow(t *testing.T, c engine.Constraints, path string) engine.ResourceMatch {
	t.Helper()
	for _, rm := range c.Allow {
		if rm.Pattern.Resource() == path {
			return rm
		}
	}
	t.Fatalf("allow path %q not found in %v", path, allowPaths(c))
	return engine.ResourceMatch{}
}

// Happy path: department matches → context-only conditions resolved and stripped;
// resource-attribute condition (status) is preserved for the adapter.
func TestConstrain_ResolvesContextOnlyConditions(t *testing.T) {
	c := engine.Constrain([]policy.Policy{constrainPolicy()}, "file:listFiles", constrainTenant,
		map[string]string{"department": "engineering"})

	// team + public + reports all allowed.
	for _, p := range []string{"datalake/**", "public/**", "reports/**"} {
		if !contains(allowPaths(c), p) {
			t.Errorf("allow missing %q; got %v", p, allowPaths(c))
		}
	}

	// team: department satisfied and consumed → no residual conditions.
	if rm := findAllow(t, c, "datalake/**"); len(rm.Conditions) != 0 {
		t.Errorf("datalake/** should carry no residual conditions, got %v", rm.Conditions)
	}
	// public: never had conditions.
	if rm := findAllow(t, c, "public/**"); len(rm.Conditions) != 0 {
		t.Errorf("public/** should carry no residual conditions, got %v", rm.Conditions)
	}
	// reports: status not in context → deferred to the adapter.
	rm := findAllow(t, c, "reports/**")
	if got := rm.Conditions[conditionoperator.StringEquals]["status"]; len(got) != 1 || got[0] != "active" {
		t.Errorf("reports/** should defer status=active, got %v", rm.Conditions)
	}

	// deny applies because its department condition is satisfied.
	if !contains(denyPaths(c), "datalake/secret/**") {
		t.Errorf("deny missing datalake/secret/**; got %v", denyPaths(c))
	}
}

// Unhappy path: department mismatch → the context-only allow AND the context-only
// deny are both dropped; unconditional/resource-attribute statements survive.
func TestConstrain_DropsStatementsWhenContextFails(t *testing.T) {
	c := engine.Constrain([]policy.Policy{constrainPolicy()}, "file:listFiles", constrainTenant,
		map[string]string{"department": "sales"})

	if contains(allowPaths(c), "datalake/**") {
		t.Errorf("datalake/** must be dropped when department != engineering; got %v", allowPaths(c))
	}
	if !contains(allowPaths(c), "public/**") {
		t.Errorf("public/** should still be allowed; got %v", allowPaths(c))
	}
	if !contains(allowPaths(c), "reports/**") {
		t.Errorf("reports/** should still be allowed (deferred condition); got %v", allowPaths(c))
	}
	// deny gated on department=engineering no longer applies to a sales principal.
	if contains(denyPaths(c), "datalake/secret/**") {
		t.Errorf("deny must be dropped when its condition fails; got %v", denyPaths(c))
	}
}

// With no context supplied, every keyed condition is deferred (nothing resolved),
// and context-gated statements survive with their conditions intact.
func TestConstrain_NoContextDefersEverything(t *testing.T) {
	c := engine.Constrain([]policy.Policy{constrainPolicy()}, "file:listFiles", constrainTenant, nil)

	rm := findAllow(t, c, "datalake/**")
	if got := rm.Conditions[conditionoperator.StringEquals]["department"]; len(got) != 1 || got[0] != "engineering" {
		t.Errorf("datalake/** should defer department=engineering, got %v", rm.Conditions)
	}
	// deny is deferred (condition kept), so it still appears.
	if !contains(denyPaths(c), "datalake/secret/**") {
		t.Errorf("deny should be present with deferred condition; got %v", denyPaths(c))
	}
}

// An action matched by no allow statement yields no allow patterns, so the
// adapter grants nothing. (The wildcard "*" deny still applies to every action.)
func TestConstrain_NoMatchingAction(t *testing.T) {
	c := engine.Constrain([]policy.Policy{constrainPolicy()}, "config:listConfigs", constrainTenant, nil)
	if len(c.Allow) != 0 {
		t.Errorf("expected no allow patterns, got %v", allowPaths(c))
	}
	if !contains(denyPaths(c), "datalake/secret/**") {
		t.Errorf("wildcard deny should still apply; got %v", denyPaths(c))
	}
}

// Constrain applies the same tenant matching as Decide: a platform-issued
// pattern (placeholder tenant) is resolved to the requesting tenant, and a
// pattern naming another tenant is dropped.
func TestConstrain_TenantMatching(t *testing.T) {
	otherTenant := "11111111-1111-1111-1111-111111111111"
	platform := policy.Policy{
		ID: "aic-managed",
		Statements: []policy.Statement{{
			Sid: "aic-deny-secrets", Effect: policy.Deny, Actions: []string{"*"},
			Resources: []string{fmt.Sprintf("crn:%s:*:file::file:**/secrets/**", crn.PlatformTenant)},
		}},
	}
	otherPol := policy.Policy{
		ID: "other",
		Statements: []policy.Statement{{
			Sid: "other-allow", Effect: policy.Allow, Actions: []string{"file:listFiles"},
			Resources: []string{fmt.Sprintf("crn:%s:*:file::file:**", otherTenant)},
		}},
	}

	c := engine.Constrain([]policy.Policy{constrainPolicy(), platform, otherPol},
		"file:listFiles", constrainTenant, nil)

	// The placeholder is resolved: the emitted deny names the requesting tenant.
	if !contains(denyPaths(c), "**/secrets/**") {
		t.Fatalf("platform deny missing; got %v", denyPaths(c))
	}
	for _, rm := range c.Deny {
		if rm.Pattern.Tenant() == crn.PlatformTenant {
			t.Errorf("placeholder leaked to constraints: %v", rm.Pattern)
		}
	}

	// The other tenant's allow cannot match this request and is dropped.
	if contains(allowPaths(c), "**") {
		t.Errorf("other tenant's pattern must be dropped; got %v", allowPaths(c))
	}
}

// resource.path[N] keys resolve against the resource, and Constrain has none —
// they always defer to the adapter, even if a context entry shadows the key.
func TestConstrain_DefersResourcePathKeys(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{{
			Sid: "inbound-by-org", Effect: policy.Allow, Actions: []string{"file:listFiles"},
			Resources:  []string{res("files/inbound/**")},
			Conditions: policy.Conditions{conditionoperator.StringEquals: {"resource.path[2]": {"123456789"}}},
		}},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", constrainTenant,
		map[string]string{"resource.path[2]": "999999999"}) // must not resolve (or fail) from context

	rm := findAllow(t, c, "files/inbound/**")
	if got := rm.Conditions[conditionoperator.StringEquals]["resource.path[2]"]; len(got) != 1 || got[0] != "123456789" {
		t.Errorf("resource.path[2] should be deferred intact, got %v", rm.Conditions)
	}
}

// A malformed policy makes Constrain fail closed: no allow patterns.
func TestConstrain_FailsClosedOnBadPolicy(t *testing.T) {
	bad := policy.Policy{
		ID: "bad",
		Statements: []policy.Statement{{
			Sid: "x", Effect: policy.Allow, Actions: []string{"file:listFiles"},
			Resources: []string{"not-a-crn"},
		}},
	}
	c := engine.Constrain([]policy.Policy{bad}, "file:listFiles", constrainTenant, nil)
	if len(c.Allow) != 0 {
		t.Errorf("bad policy must yield no allow patterns, got %v", allowPaths(c))
	}
}

// An operator with no condition keys must not disappear during partial
// evaluation and turn a conditional allow into an unconditional one.
func TestConstrain_FailsClosedOnEmptyConditionKeyMap(t *testing.T) {
	bad := policy.Policy{
		ID: "empty-condition-keys",
		Statements: []policy.Statement{{
			Sid: "x", Effect: policy.Allow, Actions: []string{"file:listFiles"},
			Resources:  []string{res("datalake/**")},
			Conditions: policy.Conditions{conditionoperator.StringEquals: {}},
		}},
	}

	c := engine.Constrain([]policy.Policy{bad}, "file:listFiles", constrainTenant, nil)
	if len(c.Allow) != 0 {
		t.Errorf("empty condition key map must yield no allow patterns, got %v", allowPaths(c))
	}
}
