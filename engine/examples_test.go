package engine_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/adapter/pathfilter"
	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

// loadPolicy reads a policy document from docs/examples so the examples in the
// docs and the engine behavior can never drift.
func loadPolicy(t *testing.T, name string) policy.Policy {
	t.Helper()
	path := filepath.Join("..", "docs", "examples", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var p policy.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if _, err := engine.Compile([]policy.Policy{p}); err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return p
}

// TestExample_FileAccess exercises docs/examples/file-access.json against the
// DS-file API (service "file", resource = file_path).
func TestExample_FileAccess(t *testing.T) {
	pol := loadPolicy(t, "file-access.json")

	file := func(path string) crn.CRN {
		c, err := crn.Build(tenant, "owner-1", "file", "", "file", path)
		if err != nil {
			t.Fatalf("Build file CRN %q: %v", path, err)
		}
		return c
	}

	tests := []struct {
		name       string
		action     string
		path       string
		ctx        map[string]string
		wantAllow  bool
		wantReason string
	}{
		{"read active file", "file:getFile", "reports/q1.csv", map[string]string{"status": "active"}, true, "read-active-files"},
		// status is a multi-value condition: the values OR together, so
		// "archived" passes the same statement as "active".
		{"read archived file", "file:getFile", "reports/q1.csv", map[string]string{"status": "archived"}, true, "read-active-files"},
		{"read deleted file denied", "file:getFile", "reports/q1.csv", map[string]string{"status": "deleted"}, false, "implicit deny"},
		{"write projectx unrestricted", "file:createFile", "projectx/app.json", map[string]string{"tag.classification": "internal"}, true, "write-projectx-unless-restricted"},
		{"write projectx untagged", "file:createFile", "projectx/app.json", nil, true, "write-projectx-unless-restricted"},
		{"write projectx restricted denied", "file:updateFile", "projectx/app.json", map[string]string{"tag.classification": "restricted"}, false, "implicit deny"},
		{"read secret denied by deny-wins", "file:getFile", "projectx/secrets/key.txt", map[string]string{"status": "active"}, false, "protect-projectx-secrets"},
		{"write secret denied by deny-wins", "file:updateFile", "projectx/secrets/key.txt", map[string]string{"tag.classification": "internal"}, false, "protect-projectx-secrets"},
		{"write outside projectx denied", "file:createFile", "other/app.json", map[string]string{"tag.classification": "internal"}, false, "implicit deny"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := engine.Request{Action: test.action, Resource: file(test.path), Tenant: tenant, Context: test.ctx}
			got := engine.Decide([]policy.Policy{pol}, req)
			if got.Allowed != test.wantAllow || got.Reason != test.wantReason {
				t.Errorf("Decide(%s %s) = {Allowed:%v Reason:%q}, want {Allowed:%v Reason:%q}",
					test.action, test.path, got.Allowed, got.Reason, test.wantAllow, test.wantReason)
			}
		})
	}
}

// TestExample_PlatformGuardrail exercises docs/examples/platform-guardrail.json:
// a platform-issued policy whose deny carries the tenant token, so the one
// document guards each principal's own resources, layered on top of the tenant's
// own file-access policy.
func TestExample_PlatformGuardrail(t *testing.T) {
	guardrail := loadPolicy(t, "platform-guardrail.json")
	tenantPol := loadPolicy(t, "file-access.json")
	policies := []policy.Policy{tenantPol, guardrail}

	file := func(tenantID, path string) crn.CRN {
		c, err := crn.Build(tenantID, "owner-1", "file", "", "file", path)
		if err != nil {
			t.Fatalf("Build file CRN %q: %v", path, err)
		}
		return c
	}
	activeCtx := map[string]string{"status": "active"}

	// The tenant's own allow still works outside the guardrail.
	got := engine.Decide(policies, engine.Request{
		Action: "file:getFile", Resource: file(tenant, "team/config.json"), Tenant: tenant, Context: activeCtx})
	if !got.Allowed || got.Reason != "read-active-files" {
		t.Errorf("outside guardrail = {Allowed:%v Reason:%q}, want allow via read-active-files", got.Allowed, got.Reason)
	}

	// The guardrail denies a path the tenant policy would otherwise allow.
	got = engine.Decide(policies, engine.Request{
		Action: "file:getFile", Resource: file(tenant, "team/secrets/token.txt"), Tenant: tenant, Context: activeCtx})
	if got.Allowed || got.Reason != "protect-secrets" {
		t.Errorf("under guardrail = {Allowed:%v Reason:%q}, want deny via protect-secrets", got.Allowed, got.Reason)
	}

	// The same document, bound to a different principal, guards that principal's
	// own resources too — the token resolves to whoever the caller is.
	other := "11111111-1111-1111-1111-111111111111"
	got = engine.Decide([]policy.Policy{guardrail}, engine.Request{
		Action: "file:getFile", Resource: file(other, "x/secrets/y"), Tenant: other})
	if got.Allowed || got.Reason != "protect-secrets" {
		t.Errorf("other principal = {Allowed:%v Reason:%q}, want deny via protect-secrets", got.Allowed, got.Reason)
	}
}

// TestExample_InboundPartitions exercises docs/examples/inbound-partitions.json:
// one pattern over files/inbound/** plus a resource.path[2] value set replaces
// one resource pattern per org number. The same document gates requests
// (Decide) and narrows a storage walk (Constrain -> pathfilter).
func TestExample_InboundPartitions(t *testing.T) {
	pol := loadPolicy(t, "inbound-partitions.json")

	file := func(path string) crn.CRN {
		c, err := crn.Build(tenant, "owner-1", "file", "", "file", path)
		if err != nil {
			t.Fatalf("Build file CRN %q: %v", path, err)
		}
		return c
	}

	tests := []struct {
		name       string
		path       string
		wantAllow  bool
		wantReason string
	}{
		{"own org", "files/inbound/123456789/report.csv", true, "inbound-by-org"},
		{"second org", "files/inbound/23456788/report.csv", true, "inbound-by-org"},
		{"foreign org denied", "files/inbound/999999999/report.csv", false, "implicit deny"},
		{"no partition segment denied", "files/inbound", false, "implicit deny"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := engine.Decide([]policy.Policy{pol},
				engine.Request{Action: "file:getFile", Resource: file(test.path), Tenant: tenant})
			if got.Allowed != test.wantAllow || got.Reason != test.wantReason {
				t.Errorf("Decide(%s) = {Allowed:%v Reason:%q}, want {Allowed:%v Reason:%q}",
					test.path, got.Allowed, got.Reason, test.wantAllow, test.wantReason)
			}
		})
	}

	// List path: the segment condition folds into one glob per org number.
	cons := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)
	allow, deny, err := pathfilter.Prefixes(cons)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	wantAllow := []string{"files/inbound/123456789/**", "files/inbound/23456788/**"}
	if !reflect.DeepEqual(allow, wantAllow) {
		t.Errorf("allow globs = %#v, want %#v", allow, wantAllow)
	}
	if deny != nil {
		t.Errorf("deny globs = %#v, want none", deny)
	}
}

// TestExample_InboundCountry exercises docs/examples/inbound-country.json: a
// service-owned condition key ("inbound:customer:country_code", <service>:<name>
// grammar) the Inbound service resolves from trusted customer data into
// Request.Context — the engine matches it like any other key.
func TestExample_InboundCountry(t *testing.T) {
	pol := loadPolicy(t, "inbound-country.json")

	file := func(path string) crn.CRN {
		c, err := crn.Build(tenant, "owner-1", "file", "", "file", path)
		if err != nil {
			t.Fatalf("Build file CRN %q: %v", path, err)
		}
		return c
	}

	tests := []struct {
		name       string
		ctx        map[string]string
		wantAllow  bool
		wantReason string
	}{
		{"nordic customer", map[string]string{"inbound:customer:country_code": "NO"}, true, "inbound-nordic-only"},
		{"foreign customer denied", map[string]string{"inbound:customer:country_code": "US"}, false, "implicit deny"},
		{"missing country denied", nil, false, "implicit deny"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := engine.Decide([]policy.Policy{pol},
				engine.Request{Action: "file:getFile", Resource: file("files/inbound/report.csv"), Tenant: tenant, Context: test.ctx})
			if got.Allowed != test.wantAllow || got.Reason != test.wantReason {
				t.Errorf("Decide = {Allowed:%v Reason:%q}, want {Allowed:%v Reason:%q}",
					got.Allowed, got.Reason, test.wantAllow, test.wantReason)
			}
		})
	}
}

// TestExample_ConfigBilling exercises docs/examples/config-billing.json against
// the Config API (service "config", type = resource kind, resource = id).
func TestExample_ConfigBilling(t *testing.T) {
	pol := loadPolicy(t, "config-billing.json")

	const id = "11111111-1111-1111-1111-111111111111"
	res := func(kind string) crn.CRN {
		c, err := crn.Build(tenant, "owner-1", "config", "", kind, id)
		if err != nil {
			t.Fatalf("Build config CRN %q: %v", kind, err)
		}
		return c
	}

	tests := []struct {
		name       string
		action     string
		kind       string
		ctx        map[string]string
		wantAllow  bool
		wantReason string
	}{
		{"list plans", "config:listPlan", "plan", nil, true, "billing-read"},
		{"get invoice", "config:getInvoiceById", "invoice", nil, true, "billing-read"},
		{"create plan in staging", "config:createPlan", "plan", map[string]string{"environment": "staging"}, true, "plan-write-staging-only"},
		{"create plan in prod denied", "config:createPlan", "plan", map[string]string{"environment": "prod"}, false, "implicit deny"},
		{"delete plan in staging", "config:deletePlan", "plan", map[string]string{"environment": "staging"}, true, "plan-write-staging-only"},
		{"generate invoice denied", "config:generateInvoice", "invoice", nil, false, "no-invoice-generation"},
		{"unlisted llm action denied", "config:deleteModel", "model", nil, false, "implicit deny"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := engine.Request{Action: test.action, Resource: res(test.kind), Tenant: tenant, Context: test.ctx}
			got := engine.Decide([]policy.Policy{pol}, req)
			if got.Allowed != test.wantAllow || got.Reason != test.wantReason {
				t.Errorf("Decide(%s %s) = {Allowed:%v Reason:%q}, want {Allowed:%v Reason:%q}",
					test.action, test.kind, got.Allowed, got.Reason, test.wantAllow, test.wantReason)
			}
		})
	}
}

// TestExample_SingleResourceAndPublished shows the two ways a row becomes
// readable, and that only one of them is a policy:
//   - dataset-owner-grant.json grants the caller one of its own datasets.
//   - the platform's published rows come from the marker the service declares on
//     its read mapping, so no document names them and none has to be copied per
//     tenant.
//
// Listing therefore returns the caller's granted dataset OR every published row,
// and nothing belonging to another tenant.
func TestExample_SingleResourceAndPublished(t *testing.T) {
	// One narrow grant, naming a single dataset. Nothing in it mentions the
	// platform's published rows: publication is the grant for those, and the
	// service declares the marker on its read mapping.
	policies := []policy.Policy{loadPolicy(t, "dataset-owner-grant.json")}

	const (
		ownID          = "11111111-1111-1111-1111-111111111111"
		otherID        = "22222222-2222-2222-2222-222222222222"
		otherTen       = "99999999-9999-9999-9999-999999999999"
		platformTenant = "88888888-8888-8888-8888-888888888888"
	)
	dataset := func(tenantID, id string) crn.CRN {
		c, err := crn.Build(tenantID, "", "config", "", "dataset", id)
		if err != nil {
			t.Fatalf("Build dataset CRN (%s,%s): %v", tenantID, id, err)
		}
		return c
	}

	// --- Gate (Decide): a single-resource check on config:getDataset. ---
	decideCases := []struct {
		name      string
		resource  crn.CRN
		published bool
		wantAllow bool
	}{
		{"own granted dataset", dataset(tenant, ownID), false, true},
		// The row carries the platform's marker, so holding the action is enough and
		// the narrow grant above does not have to name it.
		{"a published dataset", dataset(platformTenant, "any-published-id"), true, true},
		{"own but ungranted dataset", dataset(tenant, otherID), false, false},
		{"another tenant's dataset", dataset(otherTen, ownID), false, false},
		// Unmarked, so it is an ordinary row of a tenant that is not the caller.
		{"the platform's unpublished dataset", dataset(platformTenant, ownID), false, false},
	}
	for _, tc := range decideCases {
		t.Run("decide/"+tc.name, func(t *testing.T) {
			got := engine.Decide(policies, engine.Request{
				Action: "config:getDataset", Tenant: tenant,
				Resource: tc.resource, ResourcePublished: tc.published})
			if got.Allowed != tc.wantAllow {
				t.Errorf("Decide = {Allowed:%v Reason:%q}, want allow=%v", got.Allowed, got.Reason, tc.wantAllow)
			}
		})
	}

	// --- List (Constrain -> sqlfilter): the WHERE must select the caller's own
	// dataset OR all public (platform-owned) rows. ---
	cons := engine.Constrain(policies, "config:listDataset", tenant, nil)

	where, args, err := sqlfilter.Where(cons, sqlfilter.Mapping{
		Service:   "config",
		Tenant:    "tenant_id",
		Published: sqlfilter.Published{Column: "issuer", Value: "public"},
		Fixed: map[sqlfilter.Segment]string{
			sqlfilter.SegmentScope:  "",
			sqlfilter.SegmentRegion: "",
			sqlfilter.SegmentType:   "dataset",
		},
		Resource: sqlfilter.ResourceColumn{ID: "id"},
	})
	if err != nil {
		t.Fatalf("Where: %v", err)
	}

	// Own row bound to the request tenant and the granted id; published rows
	// through the marker the mapping declares, which no statement names. A write
	// mapping leaves Published unset and selects the caller's row alone.
	wantWhere := "(tenant_id = ? AND id = ?) OR issuer = ?"
	if where != wantWhere {
		t.Errorf("where =\n  %q\nwant\n  %q", where, wantWhere)
	}
	if wantArgs := []any{tenant, ownID, "public"}; !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, want %#v", args, wantArgs)
	}
}
