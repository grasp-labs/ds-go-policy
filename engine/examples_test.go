package engine_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
		c, err := crn.Build(pol.TenantID, "owner-1", "file", "", "file", path)
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
			req := engine.Request{Action: test.action, Resource: file(test.path), Context: test.ctx}
			got := engine.Decide([]policy.Policy{pol}, req)
			if got.Allowed != test.wantAllow || got.Reason != test.wantReason {
				t.Errorf("Decide(%s %s) = {Allowed:%v Reason:%q}, want {Allowed:%v Reason:%q}",
					test.action, test.path, got.Allowed, got.Reason, test.wantAllow, test.wantReason)
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
		c, err := crn.Build(pol.TenantID, "owner-1", "config", "", kind, id)
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
			req := engine.Request{Action: test.action, Resource: res(test.kind), Context: test.ctx}
			got := engine.Decide([]policy.Policy{pol}, req)
			if got.Allowed != test.wantAllow || got.Reason != test.wantReason {
				t.Errorf("Decide(%s %s) = {Allowed:%v Reason:%q}, want {Allowed:%v Reason:%q}",
					test.action, test.kind, got.Allowed, got.Reason, test.wantAllow, test.wantReason)
			}
		})
	}
}
