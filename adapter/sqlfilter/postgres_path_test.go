package sqlfilter_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/conditionoperator"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

func TestPostgresPathConditionsSQL(t *testing.T) {
	for _, tt := range []struct {
		name           string
		statementsJSON string
		wantSQL        string
		wantArgs       []any
	}{
		{
			name: "empty first and later segments",
			statementsJSON: `[{
				"effect": "allow",
				"actions": ["file:*"],
				"resources": ["crn:aic:*:file:*:file:**"],
				"conditions": {"StringEquals": {
					"resource.path[0]": [""],
					"resource.path[1]": [""]
				}}
			}]`,
			wantSQL: `tenant_id = ? AND type = ?
				AND split_part(file.file_path, '/', 1) = ?
				AND (string_to_array(file.file_path, '/'))[2] = ?`,
			wantArgs: []any{tenant, "file", "", ""},
		},
		{
			name: "nonconsecutive indexes with multiple values",
			statementsJSON: `[{
				"effect": "allow",
				"actions": ["file:*"],
				"resources": ["crn:aic:*:file:*:file:**"],
				"conditions": {"StringEquals": {
					"resource.path[2]": ["org-a"],
					"resource.path[5]": ["file.xml", "other.xml"]
				}}
			}]`,
			wantSQL: `tenant_id = ? AND type = ?
				AND (string_to_array(file.file_path, '/'))[3] = ?
				AND (string_to_array(file.file_path, '/'))[6] IN (?, ?)`,
			wantArgs: []any{tenant, "file", "org-a", "file.xml", "other.xml"},
		},
		{
			name: "high index only in deny",
			statementsJSON: `[
				{
					"effect": "allow",
					"actions": ["file:*"],
					"resources": ["crn:aic:*:file:*:file:**"]
				},
				{
					"effect": "deny",
					"actions": ["file:*"],
					"resources": ["crn:aic:*:file:*:file:**"],
					"conditions": {"StringEquals": {"resource.path[12]": [""]}}
				}
			]`,
			wantSQL: `(tenant_id = ? AND type = ?)
				AND ((tenant_id = ? AND type = ?
				AND (string_to_array(file.file_path, '/'))[13] = ?) IS NOT TRUE)`,
			wantArgs: []any{tenant, "file", tenant, "file", ""},
		},
		{
			name: "largest supported index",
			statementsJSON: `[{
				"effect": "allow",
				"actions": ["file:*"],
				"resources": ["crn:aic:*:file:*:file:**"],
				"conditions": {"StringEquals": {"resource.path[2147483646]": ["value"]}}
			}]`,
			wantSQL: `tenant_id = ? AND type = ?
				AND (string_to_array(file.file_path, '/'))[2147483647] = ?`,
			wantArgs: []any{tenant, "file", "value"},
		},
		{
			name: "SQL metacharacters stay in bound arguments",
			statementsJSON: `[{
				"effect": "allow",
				"actions": ["file:*"],
				"resources": ["crn:aic:*:file:*:file:**"],
				"conditions": {"StringEquals": {"resource.path[1]": ["report_%\\'.xml"]}}
			}]`,
			wantSQL: `tenant_id = ? AND type = ?
				AND (string_to_array(file.file_path, '/'))[2] = ?`,
			wantArgs: []any{tenant, "file", `report_%\'.xml`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var statements []policy.Statement
			if err := json.Unmarshal([]byte(tt.statementsJSON), &statements); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			compiled, err := engine.Compile([]policy.Policy{{Statements: statements}})
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			c := compiled.Constrain("file:getFile", tenant, nil)
			m := sqlfilter.WithPostgresPathConditions(mapping(), c, "file.file_path")
			sql, args, err := sqlfilter.Where(c, m)
			if err != nil {
				t.Fatalf("Where: %v", err)
			}
			if want := strings.Join(strings.Fields(tt.wantSQL), " "); sql != want {
				t.Errorf("sql =\n  %q\nwant\n  %q", sql, want)
			}
			if !reflect.DeepEqual(args, tt.wantArgs) {
				t.Errorf("args = %#v, want %#v", args, tt.wantArgs)
			}
		})
	}
}

func TestPostgresPathConditionsPreserveMapping(t *testing.T) {
	const (
		first  = "resource.path[0]"
		custom = "resource.path[1]"
		third  = "resource.path[2]"
	)
	m := mapping()
	m.Resource = sqlfilter.ResourceColumn{ID: "id"}
	m.Conditions = map[string]string{custom: "partition", "status": "status"}
	m.AllowedConditionOperators = map[string][]string{
		custom:   {conditionoperator.StringLike},
		"status": {conditionoperator.StringEquals},
	}
	c := engine.Constraints{
		Allow: []engine.ResourceMatch{{
			Conditions: policy.Conditions{conditionoperator.StringEquals: {
				first: {""}, custom: {"inbound"},
			}},
		}},
		Deny: []engine.ResourceMatch{{
			Conditions: policy.Conditions{conditionoperator.StringEquals: {
				first: {"private"}, third: {"secret"},
			}},
		}},
	}
	got := sqlfilter.WithPostgresPathConditions(m, c, "key")
	wantConditions := map[string]string{
		first:    "split_part(key, '/', 1)",
		third:    "(string_to_array(key, '/'))[3]",
		custom:   "partition",
		"status": "status",
	}
	if !reflect.DeepEqual(got.Conditions, wantConditions) {
		t.Fatalf("conditions = %#v, want %#v", got.Conditions, wantConditions)
	}
	wantOperators := map[string][]string{
		first: {conditionoperator.StringEquals}, third: {conditionoperator.StringEquals},
		custom: {conditionoperator.StringLike}, "status": {conditionoperator.StringEquals},
	}
	if !reflect.DeepEqual(got.AllowedConditionOperators, wantOperators) {
		t.Fatalf("operators = %#v, want %#v", got.AllowedConditionOperators, wantOperators)
	}
	got.Conditions["status"] = "changed"
	got.AllowedConditionOperators["status"][0] = conditionoperator.StringLike
	if len(m.Conditions) != 2 || m.Conditions["status"] != "status" ||
		len(m.AllowedConditionOperators) != 2 || m.AllowedConditionOperators["status"][0] != conditionoperator.StringEquals {
		t.Fatal("helper modified the original mapping's maps or operator slices")
	}
}

func TestPostgresPathConditionsPreserveEmptyOperatorList(t *testing.T) {
	const key = "resource.path[0]"
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "**"),
		Conditions: policy.Conditions{conditionoperator.StringEquals: {key: {"private"}}},
	}}}
	m := mapping()
	m.AllowedConditionOperators = map[string][]string{key: {}}
	got := sqlfilter.WithPostgresPathConditions(m, c, "path")
	if operators, exists := got.AllowedConditionOperators[key]; !exists || len(operators) != 0 {
		t.Fatalf("operators = %#v, exists = %t, want an explicit empty list", operators, exists)
	}
	if _, _, err := sqlfilter.Where(c, got); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
		t.Fatalf("Where error = %v, want ErrUnsupportedCondition", err)
	}
}

func TestPostgresPathConditionsRejectOversizedIndex(t *testing.T) {
	const action = "file:getFile"
	allow := policy.Statement{
		Effect: policy.Allow, Actions: []string{action}, Resources: []string{"crn:" + tenant + ":*:file:*:file:**"},
	}
	for _, index := range []int{math.MaxInt32, math.MaxInt} {
		for _, effect := range []policy.Effect{policy.Allow, policy.Deny} {
			unsupported := allow
			unsupported.Effect = effect
			unsupported.Conditions = policy.Conditions{conditionoperator.StringEquals: {fmt.Sprintf("resource.path[%d]", index): {"org-a"}}}
			for order, statements := range [][]policy.Statement{{allow, unsupported}, {unsupported, allow}} {
				t.Run(fmt.Sprintf("%d/%s/order-%d", index, effect, order), func(t *testing.T) {
					compiled, err := engine.Compile([]policy.Policy{{Statements: statements}})
					if err != nil {
						t.Fatal(err)
					}
					c := compiled.Constrain(action, tenant, nil)
					m := sqlfilter.WithPostgresPathConditions(mapping(), c, "path")
					if _, _, err := sqlfilter.Where(c, m); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
						t.Fatalf("Where error = %v, want ErrUnsupportedCondition", err)
					}
				})
			}
		}
	}
}

func TestPostgresPathConditionsLeaveUnsupportedConditionsUnusable(t *testing.T) {
	for _, test := range []struct {
		name, key, operator, column string
	}{
		{"negative index", "resource.path[-1]", conditionoperator.StringEquals, "path"},
		{"unmapped attribute", "department", conditionoperator.StringEquals, "path"},
		{"unsupported operator", "resource.path[0]", conditionoperator.StringLike, "path"},
		{"IfExists is not automatically enabled", "resource.path[0]", conditionoperator.StringEquals + conditionoperator.IfExistsSuffix, "path"},
		{"blank column", "resource.path[0]", conditionoperator.StringEquals, " "},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := engine.Constraints{Allow: []engine.ResourceMatch{{
				Pattern:    pattern(t, "**"),
				Conditions: policy.Conditions{test.operator: {test.key: {"value"}}},
			}}}
			m := sqlfilter.WithPostgresPathConditions(mapping(), c, test.column)
			if _, _, err := sqlfilter.Where(c, m); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
				t.Fatalf("Where error = %v, want ErrUnsupportedCondition", err)
			}
		})
	}
}
