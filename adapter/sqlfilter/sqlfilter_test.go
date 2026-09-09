package sqlfilter_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/conditionoperator"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

const tenant = "ba62a53f-afa9-427d-9d91-c7987bc5662e"

func pattern(t *testing.T, resource string) crn.Pattern {
	t.Helper()
	p, err := crn.ParsePattern(fmt.Sprintf("crn:%s:*:file:*:file:%s", tenant, resource))
	if err != nil {
		t.Fatalf("ParsePattern(%q): %v", resource, err)
	}
	return p
}

func mapping() sqlfilter.Mapping {
	return sqlfilter.Mapping{
		Service:  "file",
		Tenant:   "tenant_id",
		Scope:    "owner_id",
		Region:   "region",
		Type:     "type",
		Resource: sqlfilter.ResourceColumn{ID: "id", Path: "path"},
	}
}

func TestWhere_AllowMinusDeny(t *testing.T) {
	c := engine.Constraints{
		Allow: []engine.ResourceMatch{{Pattern: pattern(t, "datalake/**")}},
		Deny:  []engine.ResourceMatch{{Pattern: pattern(t, "datalake/secret/**")}},
	}
	sql, args, err := sqlfilter.Where(c, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}

	// scope (*) and region (*) are wildcards -> no predicate; type "file" -> equality.
	wantSQL := "(tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')) " +
		"AND ((tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')) IS NOT TRUE)"
	wantArgs := []any{
		tenant, "file", "datalake", "datalake/%",
		tenant, "file", "datalake/secret", "datalake/secret/%",
	}
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, want %#v", args, wantArgs)
	}
}

func TestWhere_DenyConditionMatchesOnlyTrue(t *testing.T) {
	wholeCollection, err := crn.ParsePattern(fmt.Sprintf("crn:%s:*:file:*:file:**", tenant))
	if err != nil {
		t.Fatalf("ParsePattern: %v", err)
	}

	c := engine.Constraints{
		Allow: []engine.ResourceMatch{{Pattern: wholeCollection}},
		Deny: []engine.ResourceMatch{{
			Pattern: wholeCollection,
			Conditions: policy.Conditions{
				conditionoperator.StringEquals: {"department": {"blocked"}},
			},
		}},
	}
	m := mapping()
	m.Conditions = map[string]string{
		"department": "department",
	}
	m.AllowedConditionOperators = map[string][]string{
		"department": {conditionoperator.StringEquals},
	}

	sql, args, err := sqlfilter.Where(c, m)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}

	// IS NOT TRUE is deliberate: when department is SQL NULL, the deny
	// condition is UNKNOWN rather than TRUE, matching IAM's absent-key behavior.
	wantSQL := "(tenant_id = ? AND type = ?) AND " +
		"((tenant_id = ? AND type = ? AND department = ?) IS NOT TRUE)"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	wantArgs := []any{tenant, "file", tenant, "file", "blocked"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, want %#v", args, wantArgs)
	}
}

func TestWhere_NoAllowIsClosed(t *testing.T) {
	sql, args, err := sqlfilter.Where(engine.Constraints{
		Deny: []engine.ResourceMatch{{Pattern: pattern(t, "folder/*/file")}},
	}, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	if sql != "1=0" || len(args) != 0 {
		t.Errorf("got (%q, %v), want (\"1=0\", [])", sql, args)
	}
	if !sqlfilter.IsClosed(sql) {
		t.Errorf("IsClosed(%q) = false, want true", sql)
	}
	if sqlfilter.IsClosed("1=1") {
		t.Error("IsClosed(\"1=1\") = true, want false")
	}
}

func TestWhere_ExactIDResource(t *testing.T) {
	c := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "i-0abc123")}}}
	sql, args, err := sqlfilter.Where(c, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	// no slash, ID column present -> id equality
	wantSQL := "tenant_id = ? AND type = ? AND id = ?"
	if sql != wantSQL {
		t.Errorf("sql = %q, want %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{tenant, "file", "i-0abc123"}) {
		t.Errorf("args = %#v", args)
	}
}

// End-to-end: Constrain resolves the context-only condition, so Where succeeds.
func TestWhere_ContextOnlyConditionResolved(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "team", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file:*:file:datalake/**", tenant)},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {"department": {"engineering"}}}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant,
		map[string]string{"department": "engineering"})

	sql, args, err := sqlfilter.Where(c, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')"
	if sql != wantSQL {
		t.Errorf("sql = %q, want %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{tenant, "file", "datalake", "datalake/%"}) {
		t.Errorf("args = %#v", args)
	}
}

// End-to-end for the "resource attribute" case: a policy that allows any file
// carrying department=engineering. department is not a principal attribute (not
// in context), so Constrain defers it and the SQL adapter turns it into a column
// predicate via Mapping.Conditions.
func TestWhere_ResourceAttributeCondition(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "eng-files", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:**", tenant)},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {"department": {"engineering"}}}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)

	m := mapping()
	m.Region = "" // file is region-agnostic: no region column
	m.Fixed = map[sqlfilter.Segment]string{
		sqlfilter.SegmentRegion: "",
	}
	m.Conditions = map[string]string{
		"department": "department",
	}
	m.AllowedConditionOperators = map[string][]string{
		"department": {conditionoperator.StringEquals},
	}
	sql, args, err := sqlfilter.Where(c, m)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	// scope "*", region "" and resource "**" are unconstrained; type "file" and
	// the department condition remain.
	wantSQL := "tenant_id = ? AND type = ? AND department = ?"
	if sql != wantSQL {
		t.Errorf("sql = %q, want %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{tenant, "file", "engineering"}) {
		t.Errorf("args = %#v", args)
	}
}

// Mirrors the file-access example documented in the README: allow listFiles over
// the whole tree where status is "active" or "archived" (a key's values OR
// together, rendered as IN), minus the projectx/secrets subtree.
func TestWhere_READMEFileAccessExample(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "read-active-files", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:**", tenant)},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {"status": {"active", "archived"}}}},
			{Sid: "protect-projectx-secrets", Effect: policy.Deny, Actions: []string{"*"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file::file:projectx/secrets/**", tenant)}},
		},
	}
	cons := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)

	sql, args, err := sqlfilter.Where(cons, sqlfilter.Mapping{
		Service:    "file",
		Tenant:     "tenant_id",
		Type:       "type",
		Resource:   sqlfilter.ResourceColumn{Path: "path"},
		Fixed:      map[sqlfilter.Segment]string{sqlfilter.SegmentRegion: ""},
		Conditions: map[string]string{"status": "status"},
		AllowedConditionOperators: map[string][]string{
			"status": {conditionoperator.StringEquals},
		},
	})
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "(tenant_id = ? AND type = ? AND status IN (?, ?)) " +
		"AND ((tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')) IS NOT TRUE)"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	wantArgs := []any{tenant, "file", "active", "archived", tenant, "file", "projectx/secrets", "projectx/secrets/%"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v\nwant %#v", args, wantArgs)
	}
}

// An empty flat segment (region-agnostic) with a mapped column must filter on
// the empty value, matching Decide (which matches "" only against ""). Skipping
// it would grant more than Decide.
func TestWhere_EmptyMappedFieldFiltersEmpty(t *testing.T) {
	// region "" with a region column present.
	p, err := crn.ParsePattern(fmt.Sprintf("crn:%s:*:file::file:datalake/**", tenant))
	if err != nil {
		t.Fatalf("ParsePattern: %v", err)
	}
	c := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: p}}}
	sql, args, err := sqlfilter.Where(c, mapping()) // mapping() maps Region -> "region"
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "tenant_id = ? AND region = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')"
	if sql != wantSQL {
		t.Errorf("sql = %q, want %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{tenant, "", "file", "datalake", "datalake/%"}) {
		t.Errorf("args = %#v", args)
	}
}

// Whole-resource "*" is one segment. On an id-addressed mapping it needs no
// predicate (ids are single-segment); on a path-only mapping it must exclude
// nested paths so it does not grant more than Decide.
func TestWhere_WholeResourceSingleWildcard(t *testing.T) {
	star, err := crn.ParsePattern(fmt.Sprintf("crn:%s:*:config::plan:*", tenant))
	if err != nil {
		t.Fatalf("ParsePattern: %v", err)
	}
	c := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: star}}}

	// id-addressed (ID column present): no resource predicate. Config is
	// region-agnostic, so no region column is mapped.
	sqlID, argsID, err := sqlfilter.Where(c, sqlfilter.Mapping{
		Service: "config", Tenant: "tenant_id", Type: "type",
		Resource: sqlfilter.ResourceColumn{ID: "id", Path: "path"},
		Fixed:    map[sqlfilter.Segment]string{sqlfilter.SegmentRegion: ""},
	})
	if err != nil {
		t.Fatalf("Where(id): %v", err)
	}
	if wantID := "tenant_id = ? AND type = ?"; sqlID != wantID {
		t.Errorf("id sql = %q, want %q", sqlID, wantID)
	}
	if !reflect.DeepEqual(argsID, []any{tenant, "plan"}) {
		t.Errorf("id args = %#v", argsID)
	}

	// path-only mapping: restrict to single segment (no separator).
	sqlPath, argsPath, err := sqlfilter.Where(c, sqlfilter.Mapping{
		Service: "config", Tenant: "tenant_id", Type: "type",
		Resource: sqlfilter.ResourceColumn{Path: "path"},
		Fixed:    map[sqlfilter.Segment]string{sqlfilter.SegmentRegion: ""},
	})
	if err != nil {
		t.Fatalf("Where(path): %v", err)
	}
	wantPath := "tenant_id = ? AND type = ? AND path NOT LIKE ? ESCAPE '\\'"
	if sqlPath != wantPath {
		t.Errorf("path sql = %q, want %q", sqlPath, wantPath)
	}
	if !reflect.DeepEqual(argsPath, []any{tenant, "plan", "%/%"}) {
		t.Errorf("path args = %#v", argsPath)
	}
}

// A spread of operators, each mapped to a column, translated to portable SQL.
func TestWhere_ConditionOperators(t *testing.T) {
	m := mapping()
	ifExists := conditionoperator.WithIfExists(conditionoperator.StringEquals)
	m.Conditions = map[string]string{
		"department": "dept",
		"env":        "env",
		"size":       "size",
		"archived":   "archived",
		"owner":      "owner",
	}
	m.AllowedConditionOperators = map[string][]string{
		"department": {conditionoperator.StringEquals, conditionoperator.StringNotEquals, ifExists},
		"env":        {conditionoperator.StringLike},
		"size":       {conditionoperator.NumericGreaterThan},
		"archived":   {conditionoperator.Bool},
		"owner":      {conditionoperator.Null},
	}
	base := func(conds policy.Conditions) engine.Constraints {
		return engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "**"), Conditions: conds}}}
	}
	// pattern() -> tenant + type=file prefix on every case.
	const prefix = "tenant_id = ? AND type = ? AND "

	cases := []struct {
		name    string
		conds   policy.Conditions
		wantSQL string
		want    []any
	}{
		{"in-list", policy.Conditions{conditionoperator.StringEquals: {"department": {"eng", "ops"}}},
			prefix + "dept IN (?, ?)", []any{tenant, "file", "eng", "ops"}},
		{"not-equals", policy.Conditions{conditionoperator.StringNotEquals: {"department": {"eng"}}},
			prefix + "(dept IS NULL OR dept <> ?)", []any{tenant, "file", "eng"}},
		{"like", policy.Conditions{conditionoperator.StringLike: {"env": {"prod*"}}},
			prefix + "env LIKE ? ESCAPE '\\'", []any{tenant, "file", "prod%"}},
		{"numeric-gt", policy.Conditions{conditionoperator.NumericGreaterThan: {"size": {"100"}}},
			prefix + "size > ?", []any{tenant, "file", float64(100)}},
		{"bool", policy.Conditions{conditionoperator.Bool: {"archived": {"false"}}},
			prefix + "archived = ?", []any{tenant, "file", false}},
		{"null-true", policy.Conditions{conditionoperator.Null: {"owner": {"true"}}},
			prefix + "owner IS NULL", []any{tenant, "file"}},
		{"if-exists", policy.Conditions{ifExists: {"department": {"eng"}}},
			prefix + "(dept IS NULL OR dept = ?)", []any{tenant, "file", "eng"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args, err := sqlfilter.Where(base(tc.conds), m)
			if err != nil {
				t.Fatalf("Where: %v", err)
			}
			if sql != tc.wantSQL {
				t.Errorf("sql = %q, want %q", sql, tc.wantSQL)
			}
			if !reflect.DeepEqual(args, tc.want) {
				t.Errorf("args = %#v, want %#v", args, tc.want)
			}
		})
	}
}

func TestWhere_RequiresAllowedConditionOperator(t *testing.T) {
	constraints := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern: pattern(t, "**"),
		Conditions: policy.Conditions{
			conditionoperator.StringEquals: {"department": {"engineering"}},
		},
	}}}
	tests := []struct {
		name    string
		allowed []string
		wantErr bool
	}{
		{name: "listed", allowed: []string{conditionoperator.StringEquals}},
		{name: "unlisted", allowed: []string{conditionoperator.StringLike}, wantErr: true},
		{name: "missing", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := mapping()
			m.Conditions = map[string]string{
				"department": "dept",
			}
			m.AllowedConditionOperators = map[string][]string{
				"department": test.allowed,
			}
			_, _, err := sqlfilter.Where(constraints, m)
			if test.wantErr {
				if !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
					t.Fatalf("Where error = %v, want ErrUnsupportedCondition", err)
				}
			} else if err != nil {
				t.Fatalf("Where error = %v, want nil", err)
			}
		})
	}
}

// Unhappy: a resource-attribute condition with no column mapping is rejected.
func TestWhere_ConditionUnmappedKey(t *testing.T) {
	match := engine.ResourceMatch{
		Pattern:    pattern(t, "**"),
		Conditions: policy.Conditions{conditionoperator.StringEquals: {"department": {"eng"}}},
	}
	for _, effect := range []policy.Effect{policy.Allow, policy.Deny} {
		t.Run(string(effect), func(t *testing.T) {
			c := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "**")}}}
			if effect == policy.Allow {
				c.Allow = []engine.ResourceMatch{match}
			} else {
				c.Deny = []engine.ResourceMatch{match}
			}
			if _, _, err := sqlfilter.Where(c, mapping()); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
				t.Errorf("err = %v, want ErrUnsupportedCondition", err)
			}
		})
	}
}

// Unhappy: an operator with no portable SQL form is rejected even when mapped.
func TestWhere_ConditionUnsupportedOperator(t *testing.T) {
	m := mapping()
	m.Conditions = map[string]string{
		"sourceIp": "ip",
	}
	m.AllowedConditionOperators = map[string][]string{
		"sourceIp": {conditionoperator.IPAddress},
	}
	match := engine.ResourceMatch{
		Pattern:    pattern(t, "**"),
		Conditions: policy.Conditions{conditionoperator.IPAddress: {"sourceIp": {"10.0.0.0/8"}}},
	}
	for _, effect := range []policy.Effect{policy.Allow, policy.Deny} {
		t.Run(string(effect), func(t *testing.T) {
			c := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "**")}}}
			if effect == policy.Allow {
				c.Allow = []engine.ResourceMatch{match}
			} else {
				c.Deny = []engine.ResourceMatch{match}
			}
			if _, _, err := sqlfilter.Where(c, m); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
				t.Errorf("err = %v, want ErrUnsupportedCondition", err)
			}
		})
	}
}

func TestWhere_Errors(t *testing.T) {
	base := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "datalake/**")}}}

	if _, _, err := sqlfilter.Where(base, sqlfilter.Mapping{}); !errors.Is(err, sqlfilter.ErrServiceRequired) {
		t.Errorf("missing service: err = %v", err)
	}
	if _, _, err := sqlfilter.Where(base, sqlfilter.Mapping{Service: crn.Wildcard}); !errors.Is(err, sqlfilter.ErrInvalidService) {
		t.Errorf("wildcard service: err = %v", err)
	}
	if _, _, err := sqlfilter.Where(base, sqlfilter.Mapping{Service: "file"}); !errors.Is(err, sqlfilter.ErrTenantColumnRequired) {
		t.Errorf("missing tenant col: err = %v", err)
	}

	withCond := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "datalake/**"),
		Conditions: policy.Conditions{conditionoperator.Bool: {"mfa": {"true"}}},
	}}}
	if _, _, err := sqlfilter.Where(withCond, mapping()); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
		t.Errorf("conditions: err = %v", err)
	}

	// literal type but no type column mapped -> fail closed
	m := mapping()
	m.Type = ""
	if _, _, err := sqlfilter.Where(base, m); !errors.Is(err, sqlfilter.ErrNoColumnForField) {
		t.Errorf("unrepresentable type allow: err = %v, want ErrNoColumnForField", err)
	}

	// mid-path single-segment wildcard cannot be expressed
	mid := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "datalake/*/raw")}}}
	if _, _, err := sqlfilter.Where(mid, mapping()); !errors.Is(err, sqlfilter.ErrUnsupportedPattern) {
		t.Errorf("unrepresentable resource allow: err = %v, want ErrUnsupportedPattern", err)
	}
}

// End-to-end for a path-partition condition: resource.path[N] defers through
// Constrain and maps to a column like any resource attribute, rendering the
// partition's value set as an IN list.
func TestWhere_PathSegmentConditionMappedToColumn(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{{
			Sid: "inbound-by-org", Effect: policy.Allow, Actions: []string{"file:listFiles"},
			Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:files/inbound/**", tenant)},
			Conditions: policy.Conditions{conditionoperator.StringEquals: {"resource.path[2]": {"123456789", "23456788"}}},
		}},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)

	sql, args, err := sqlfilter.Where(c, sqlfilter.Mapping{
		Service:    "file",
		Tenant:     "tenant_id",
		Type:       "type",
		Resource:   sqlfilter.ResourceColumn{Path: "path"},
		Fixed:      map[sqlfilter.Segment]string{sqlfilter.SegmentRegion: ""},
		Conditions: map[string]string{"resource.path[2]": "org_number"},
		AllowedConditionOperators: map[string][]string{
			"resource.path[2]": {conditionoperator.StringEquals},
		},
	})
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\') AND org_number IN (?, ?)"
	if sql != wantSQL {
		t.Errorf("sql = %q, want %q", sql, wantSQL)
	}
	wantArgs := []any{tenant, "file", "files/inbound", "files/inbound/%", "123456789", "23456788"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, want %#v", args, wantArgs)
	}
}

// A platform-issued ("aic") grant is kept unrewritten by engine.Constrain; the
// adapter emits the fixed issuer = 'public' predicate for it — no tenant column,
// no per-table configuration, and never the literal token.
func TestWhere_PlatformTenantEmitsPublicPredicate(t *testing.T) {
	pol := policy.Policy{
		ID: "aic-managed",
		Statements: []policy.Statement{
			{Sid: "aic-read", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file:*:file:datalake/**", crn.PlatformTenant)}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)

	sql, args, err := sqlfilter.Where(c, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "issuer = 'public' AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')"
	if sql != wantSQL {
		t.Errorf("sql = %q, want %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{"file", "datalake", "datalake/%"}) {
		t.Errorf("args = %#v, want [file datalake datalake/%%]", args)
	}
	for _, a := range args {
		if a == crn.PlatformTenant {
			t.Errorf("emitted the literal token %q as a bound value", crn.PlatformTenant)
		}
	}
}

// A caller's own "self" grant and a platform-issued "aic" grant compose
// natively: orGroups ORs the two allow groups, the self group bound to the
// requesting tenant and the aic group to the fixed issuer = 'public' predicate.
func TestWhere_CallerPlusPlatformOrsClause(t *testing.T) {
	policies := []policy.Policy{
		{ID: "own", Statements: []policy.Statement{
			{Sid: "own", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources: []string{"crn:self:*:file:*:file:mine/**"}}}},
		{ID: "aic", Statements: []policy.Statement{
			{Sid: "aic", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file:*:file:shared/**", crn.PlatformTenant)}}}},
	}
	c := engine.Constrain(policies, "file:listFiles", tenant, nil)

	sql, args, err := sqlfilter.Where(c, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "(tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')) OR " +
		"(issuer = 'public' AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\'))"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	wantArgs := []any{
		tenant, "file", "mine", "mine/%",
		"file", "shared", "shared/%",
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, want %#v", args, wantArgs)
	}
}

// A platform-issued deny subtracts platform rows: its predicate is also the
// fixed issuer = 'public' marker and subtracted via IS NOT TRUE (deny-wins).
func TestWhere_PlatformDenySubtractsRow(t *testing.T) {
	policies := []policy.Policy{
		{ID: "aic", Statements: []policy.Statement{
			{Sid: "aic-allow", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file:*:file:shared/**", crn.PlatformTenant)}},
			{Sid: "aic-deny", Effect: policy.Deny, Actions: []string{"*"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file:*:file:shared/secret/**", crn.PlatformTenant)}},
		}},
	}
	c := engine.Constrain(policies, "file:listFiles", tenant, nil)

	sql, args, err := sqlfilter.Where(c, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "(issuer = 'public' AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')) " +
		"AND ((issuer = 'public' AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\')) IS NOT TRUE)"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	wantArgs := []any{
		"file", "shared", "shared/%",
		"file", "shared/secret", "shared/secret/%",
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %#v, want %#v", args, wantArgs)
	}
}

// A caller's own grant may carry an id/path filter and residual conditions
// (e.g. status = active); those attach only to the own group. Public ("aic")
// rows come through their own OR group, unaffected by the caller's filters.
func TestWhere_PublicRowsBypassOwnFilters(t *testing.T) {
	const ownID = "11111111-1111-1111-1111-111111111111"
	policies := []policy.Policy{
		{ID: "own", Statements: []policy.Statement{
			{Sid: "own", Effect: policy.Allow, Actions: []string{"config:listDataset"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:config::dataset:%s", tenant, ownID)},
				Conditions: policy.Conditions{conditionoperator.StringEquals: {"status": {"active"}}}}}},
		{ID: "public", Statements: []policy.Statement{
			{Sid: "public", Effect: policy.Allow, Actions: []string{"config:listDataset"},
				Resources: []string{fmt.Sprintf("crn:%s:*:config::dataset:*", crn.PlatformTenant)}}}},
	}
	// status is a resource attribute (absent from context) -> stays residual.
	c := engine.Constrain(policies, "config:listDataset", tenant, nil)

	m := sqlfilter.Mapping{
		Service: "config",
		Tenant:  "tenant_id",
		Fixed: map[sqlfilter.Segment]string{
			sqlfilter.SegmentScope:  "",
			sqlfilter.SegmentRegion: "",
			sqlfilter.SegmentType:   "dataset",
		},
		Resource:                  sqlfilter.ResourceColumn{ID: "id"},
		Conditions:                map[string]string{"status": "status"},
		AllowedConditionOperators: map[string][]string{"status": {conditionoperator.StringEquals}},
	}
	sql, args, err := sqlfilter.Where(c, m)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	// The id + status filter is confined to the own group; public is untouched.
	wantSQL := "(tenant_id = ? AND id = ? AND status = ?) OR (issuer = 'public')"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{tenant, ownID, "active"}) {
		t.Errorf("args = %#v, want [tenant ownID active]", args)
	}
}

// datasets is a PublicRows table: its platform-published rows are readable by
// every principal holding the action, so no policy has to name them.
func datasets() sqlfilter.Mapping {
	return sqlfilter.Mapping{
		Service:    "config",
		Tenant:     "tenant_id",
		PublicRows: true,
		Scope:      "owner_id",
		Fixed: map[sqlfilter.Segment]string{
			sqlfilter.SegmentRegion: "",
			sqlfilter.SegmentType:   "dataset",
		},
		Resource: sqlfilter.ResourceColumn{ID: "id"},
	}
}

// PublicRows widens a grant that pins one of the caller's own rows: the id
// predicate stays in the caller's group and the platform's rows arrive through
// the OR, which is what a policy naming a single dataset would otherwise
// exclude.
func TestWhere_PublicRowsWidenAnIdPinnedGrant(t *testing.T) {
	const ownID = "11111111-1111-1111-1111-111111111111"
	pol := policy.Policy{
		ID: "dataset-owner-grant",
		Statements: []policy.Statement{
			{Sid: "own-single-dataset", Effect: policy.Allow,
				Actions:   []string{"config:listDataset", "config:getDataset"},
				Resources: []string{fmt.Sprintf("crn:%s:*:config::dataset:%s", tenant, ownID)}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "config:listDataset", tenant, nil)

	sql, args, err := sqlfilter.Where(c, datasets())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "(tenant_id = ? AND id = ?) OR issuer = 'public'"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{tenant, ownID}) {
		t.Errorf("args = %#v, want [tenant ownID]", args)
	}
}

// PublicRows widens an existing grant; it does not create one. Without an
// applicable allow for the action the clause stays closed, so a principal with
// no grant on the table sees no platform rows either.
func TestWhere_PublicRowsStayClosedWithoutAGrant(t *testing.T) {
	pol := policy.Policy{
		ID: "other-action",
		Statements: []policy.Statement{
			{Sid: "create-only", Effect: policy.Allow, Actions: []string{"config:createDataset"},
				Resources: []string{fmt.Sprintf("crn:%s:*:config::dataset:*", tenant)}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "config:listDataset", tenant, nil)

	sql, args, err := sqlfilter.Where(c, datasets())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	if !sqlfilter.IsClosed(sql) {
		t.Errorf("sql = %q, want the closed clause", sql)
	}
	if args != nil {
		t.Errorf("args = %#v, want none", args)
	}
}

// The platform can withdraw one of its published rows from a tenant: an "aic"
// deny emits the same marker predicate and is subtracted from the widened allow.
func TestWhere_PublicRowsSubtractedByPlatformDeny(t *testing.T) {
	const secretID = "22222222-2222-2222-2222-222222222222"
	pol := policy.Policy{
		ID: "tenant-wide",
		Statements: []policy.Statement{
			{Sid: "all-own", Effect: policy.Allow, Actions: []string{"config:listDataset"},
				Resources: []string{fmt.Sprintf("crn:%s:*:config::dataset:*", tenant)}},
			{Sid: "not-that-public-one", Effect: policy.Deny, Actions: []string{"config:listDataset"},
				Resources: []string{fmt.Sprintf("crn:%s:*:config::dataset:%s", crn.PlatformTenant, secretID)}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "config:listDataset", tenant, nil)

	sql, args, err := sqlfilter.Where(c, datasets())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "((tenant_id = ?) OR issuer = 'public') " +
		"AND ((issuer = 'public' AND id = ?) IS NOT TRUE)"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	if !reflect.DeepEqual(args, []any{tenant, secretID}) {
		t.Errorf("args = %#v, want [tenant secretID]", args)
	}
}

// A per-type table (here: IAM groups) has no type column — the type is the
// table — and no scope or region dimension. Fixed declares those constants so
// the narrow pattern "crn:{tenant}::iam::group:{id}" evaluates instead of
// failing with ErrNoColumnForField.
func TestWhere_FixedSegments(t *testing.T) {
	groups := sqlfilter.Mapping{
		Service: "iam",
		Tenant:  "tenant_id",
		Fixed: map[sqlfilter.Segment]string{
			sqlfilter.SegmentScope:  "",
			sqlfilter.SegmentRegion: "",
			sqlfilter.SegmentType:   "group",
		},
		Resource: sqlfilter.ResourceColumn{ID: "id"},
	}
	parse := func(s string) crn.Pattern {
		t.Helper()
		p, err := crn.ParsePattern(s)
		if err != nil {
			t.Fatalf("ParsePattern(%q): %v", s, err)
		}
		return p
	}
	group := parse(fmt.Sprintf("crn:%s::iam::group:g-123", tenant))
	role := parse(fmt.Sprintf("crn:%s::iam::role:*", tenant))

	// Agreement: the fixed segments constrain nothing beyond the constant.
	sql, args, err := sqlfilter.Where(engine.Constraints{
		Allow: []engine.ResourceMatch{{Pattern: group}},
	}, groups)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	if want := "tenant_id = ? AND id = ?"; sql != want {
		t.Errorf("sql = %q, want %q", sql, want)
	}
	if !reflect.DeepEqual(args, []any{tenant, "g-123"}) {
		t.Errorf("args = %#v", args)
	}

	// Mismatch on allow: a grant over roles selects no group row -> closed.
	sql, args, err = sqlfilter.Where(engine.Constraints{
		Allow: []engine.ResourceMatch{{Pattern: role}},
	}, groups)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	if sql != "1=0" || len(args) != 0 {
		t.Errorf("got (%q, %v), want (\"1=0\", [])", sql, args)
	}

	// Mismatch on deny: a deny over roles denies no group row -> allow alone.
	sql, args, err = sqlfilter.Where(engine.Constraints{
		Allow: []engine.ResourceMatch{{Pattern: group}},
		Deny:  []engine.ResourceMatch{{Pattern: role}},
	}, groups)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	if want := "tenant_id = ? AND id = ?"; sql != want {
		t.Errorf("sql = %q, want %q", sql, want)
	}
	if !reflect.DeepEqual(args, []any{tenant, "g-123"}) {
		t.Errorf("args = %#v", args)
	}

	// A pinned segment that is neither a column nor fixed fails for either effect.
	undeclared := groups
	undeclared.Fixed = map[sqlfilter.Segment]string{
		sqlfilter.SegmentRegion: "",
		sqlfilter.SegmentType:   "group",
	}
	scoped := parse(fmt.Sprintf("crn:%s:prod:iam::group:*", tenant))
	if _, _, err := sqlfilter.Where(engine.Constraints{
		Allow: []engine.ResourceMatch{{Pattern: scoped}},
	}, undeclared); !errors.Is(err, sqlfilter.ErrNoColumnForField) {
		t.Errorf("undeclared allow scope: err = %v, want ErrNoColumnForField", err)
	}

	allGroups := parse(fmt.Sprintf("crn:%s:*:iam::group:*", tenant))
	if _, _, err := sqlfilter.Where(engine.Constraints{
		Allow: []engine.ResourceMatch{{Pattern: allGroups}},
		Deny:  []engine.ResourceMatch{{Pattern: scoped}},
	}, undeclared); !errors.Is(err, sqlfilter.ErrNoColumnForField) {
		t.Errorf("undeclared deny scope: err = %v, want ErrNoColumnForField", err)
	}
}

// A projection whose tenant scoping is enforced outside the filter can declare
// TenantAnswered — the escape hatch — so no tenant predicate is emitted, while
// the service applies its own row-visibility clause. (Prefer the default
// issuer = 'public' handling for ordinary platform-published tables.)
func TestWhere_TenantAnswered(t *testing.T) {
	catalog := sqlfilter.Mapping{
		Service:        "iam",
		TenantAnswered: true,
		Fixed: map[sqlfilter.Segment]string{
			sqlfilter.SegmentScope:  "",
			sqlfilter.SegmentRegion: "",
			sqlfilter.SegmentType:   "managed_policy",
		},
		Resource: sqlfilter.ResourceColumn{ID: "id"},
	}
	pol := policy.Policy{
		ID: "aic-managed",
		Statements: []policy.Statement{
			{Sid: "read-managed", Effect: policy.Allow, Actions: []string{"iam:listManagedPolicies"},
				Resources: []string{fmt.Sprintf("crn:%s::iam::managed_policy:*", crn.PlatformTenant)}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "iam:listManagedPolicies", tenant, nil)

	sql, args, err := sqlfilter.Where(c, catalog)
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	// Every segment is answered or fixed: the grant covers the whole table,
	// within the visibility clause the service supplies itself.
	if sql != "1=1" || len(args) != 0 {
		t.Errorf("got (%q, %v), want (\"1=1\", [])", sql, args)
	}

	// Declaring a tenant column and TenantAnswered together is contradictory
	// and must fail rather than silently skip the predicate.
	conflicted := catalog
	conflicted.Tenant = "tenant_id"
	if _, _, err := sqlfilter.Where(c, conflicted); !errors.Is(err, sqlfilter.ErrTenantConflict) {
		t.Errorf("tenant conflict: err = %v, want ErrTenantConflict", err)
	}
}

func TestWhere_LikeEscaping(t *testing.T) {
	// A prefix containing LIKE metacharacters must be escaped.
	c := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "a_b%c/**")}}}
	_, args, err := sqlfilter.Where(c, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	// exact arg is the raw prefix; LIKE arg is escaped
	if args[len(args)-1] != `a\_b\%c/%` {
		t.Errorf("like arg = %q, want %q", args[len(args)-1], `a\_b\%c/%`)
	}
}
