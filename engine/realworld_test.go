package engine_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

// realAdminPolicySet is the effective policy set ds-iam served to a principal
// whose dataset list came back empty while its tenant held twenty-odd datasets.
// It is kept verbatim so this test tracks a document that really shipped.
//
// Both policies are platform-managed and written with the tenant token, which is
// how one document is authored once and linked to groups across every tenant.
// Neither names a concrete tenant, so if the token does not resolve to the caller
// these grants match nothing at all — which is exactly what went wrong.
const realAdminPolicySet = `{
    "principal_id": "test@admin.com",
    "policies": [
        {
            "id": "3b313457-c5a2-4b38-8b1e-77bfcf265b0d",
            "name": "ConfigFullAccess",
            "version": "1.0.0",
            "statements": [
                {
                    "sid": "ConfigFullAccess",
                    "effect": "allow",
                    "actions": ["config:*"],
                    "resources": ["crn:aic:*:config::*:**"]
                }
            ]
        },
        {
            "id": "5df2553c-fe85-49fc-a12e-c8b4a9def041",
            "name": "AdministratorAccess",
            "version": "1.0.0",
            "statements": [
                {
                    "sid": "AdministratorAccess",
                    "effect": "allow",
                    "actions": ["*"],
                    "resources": ["crn:aic:*:*::*:**"]
                }
            ]
        }
    ]
}`

// datasetMapping mirrors the read mapping ds-config declares for its dataset
// table: id-addressed rows, an owner column answering scope, no region, and one
// type for the whole table. Published marks the rows the platform issued for
// everyone, which a read mapping carries and a write mapping does not.
var datasetMapping = sqlfilter.Mapping{
	Service:   "config",
	Tenant:    "dataset.tenant_id",
	Scope:     "dataset.owner_id",
	Resource:  sqlfilter.ResourceColumn{ID: "dataset.id"},
	Published: sqlfilter.Published{Column: "dataset.issuer", Value: "public"},
	Fixed: map[sqlfilter.Segment]string{
		sqlfilter.SegmentRegion: "",
		sqlfilter.SegmentType:   "dataset",
	},
}

// loadPolicySet reads the policies out of an effective-policy-set document, the
// shape the principal endpoint returns.
func loadPolicySet(t *testing.T, raw string) []policy.Policy {
	t.Helper()
	var set struct {
		Policies []policy.Policy `json:"policies"`
	}
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		t.Fatalf("unmarshal policy set: %v", err)
	}
	if _, err := engine.Compile(set.Policies); err != nil {
		t.Fatalf("compile policy set: %v", err)
	}
	return set.Policies
}

// TestRealWorld_AdminPolicySetToSQL walks the reported document the whole way to
// the clause ds-config ANDs into its list query. Every segment of both patterns
// is either a wildcard or agrees with a table-wide constant, so nothing narrows
// beyond the tenant — one predicate per policy, widened by the published marker.
func TestRealWorld_AdminPolicySetToSQL(t *testing.T) {
	policies := loadPolicySet(t, realAdminPolicySet)

	constraints := engine.Constrain(policies, "config:listDataset", tenant, nil)
	if len(constraints.Allow) != 2 {
		t.Fatalf("allow patterns = %d, want 2 (one per policy)", len(constraints.Allow))
	}
	// The token is resolved here, not in the adapter: by the time SQL is generated
	// every pattern names one concrete tenant, so no later stage can widen it.
	for _, match := range constraints.Allow {
		if got := match.Pattern.Tenant(); got != tenant {
			t.Errorf("pattern tenant = %q, want the caller %q", got, tenant)
		}
	}

	where, args, err := sqlfilter.Where(constraints, datasetMapping)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}

	const wantWhere = "((dataset.tenant_id = ?) OR (dataset.tenant_id = ?)) OR dataset.issuer = ?"
	if where != wantWhere {
		t.Errorf("where =\n\t%s\nwant\n\t%s", where, wantWhere)
	}
	wantArgs := []any{tenant, tenant, "public"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %v, want %v", args, wantArgs)
	}
	if sqlfilter.IsClosed(where) {
		t.Error("clause is fail-closed: the reported empty list would still be empty")
	}
}

// TestRealWorld_AdminPolicySetIsSharedNotCrossTenant is the security half of the
// document above. The same policies, held by any principal, must answer only for
// the tenant asking: the token makes one document shareable, never a grant across
// tenants. The clause proves it, since the tenant predicate is the only thing the
// caller can be bound by here.
func TestRealWorld_AdminPolicySetIsSharedNotCrossTenant(t *testing.T) {
	policies := loadPolicySet(t, realAdminPolicySet)
	const other = "11111111-1111-1111-1111-111111111111"

	for _, caller := range []string{tenant, other} {
		constraints := engine.Constrain(policies, "config:listDataset", caller, nil)
		_, args, err := sqlfilter.Where(constraints, datasetMapping)
		if err != nil {
			t.Fatalf("Where for %s: %v", caller, err)
		}
		// Every tenant predicate binds the caller and no one else, so the same
		// document selects a different tenant's rows for a different caller.
		for i, arg := range args {
			if arg == "public" {
				continue
			}
			if arg != caller {
				t.Errorf("caller %s: args[%d] = %v, want the caller's own tenant", caller, i, arg)
			}
		}
	}

	// Decide has to agree with the clause: a resource belonging to another tenant
	// is unreachable however broadly the document is written.
	foreign, err := crn.Build(other, "owner-1", "config", "", "dataset", "d1")
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Decide(policies, engine.Request{
		Action: "config:getDataset", Resource: foreign, Tenant: tenant})
	if got.Allowed {
		t.Errorf("another tenant's dataset = allowed (%s), want denied", got.Reason)
	}
	// The same resource, asked for by the tenant that owns it, is allowed — the
	// document is shareable, so it must not be inert either.
	got = engine.Decide(policies, engine.Request{
		Action: "config:getDataset", Resource: foreign, Tenant: other})
	if !got.Allowed {
		t.Errorf("own dataset = denied (%s), want allowed", got.Reason)
	}
}

// TestRealWorld_AdminPolicySetActionBreadth pins what the two action lists cover.
// "config:*" and the bare "*" both reach every config action, and the wildcard
// service in AdministratorAccess must not stop the pattern applying to the
// dataset table.
func TestRealWorld_AdminPolicySetActionBreadth(t *testing.T) {
	policies := loadPolicySet(t, realAdminPolicySet)

	for _, action := range []string{
		"config:listDataset",
		"config:getDataset",
		"config:createDataset",
		"config:updateDataset",
		"config:deleteDataset",
		"config:listLinkedService",
	} {
		t.Run(action, func(t *testing.T) {
			constraints := engine.Constrain(policies, action, tenant, nil)
			where, _, err := sqlfilter.Where(constraints, datasetMapping)
			if err != nil {
				t.Fatalf("Where: %v", err)
			}
			if sqlfilter.IsClosed(where) {
				t.Fatalf("clause is fail-closed, want a grant for %q", action)
			}
		})
	}

	// A service outside config is still refused: "*" in AdministratorAccess widens
	// actions, and its wildcard service segment widens tables, but neither turns
	// this into a grant over another service's action namespace.
	if c := engine.Constrain(policies, "file:getFile", tenant, nil); len(c.Allow) != 1 {
		t.Errorf("file:getFile allow patterns = %d, want 1 (AdministratorAccess only)", len(c.Allow))
	}
}
