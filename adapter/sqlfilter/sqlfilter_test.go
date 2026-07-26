package sqlfilter_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
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
		"AND NOT (tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\'))"
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

func TestWhere_NoAllowIsClosed(t *testing.T) {
	sql, args, err := sqlfilter.Where(engine.Constraints{}, mapping())
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	if sql != "1=0" || len(args) != 0 {
		t.Errorf("got (%q, %v), want (\"1=0\", [])", sql, args)
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
		TenantID: tenant,
		Statements: []policy.Statement{
			{Sid: "team", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file:*:file:datalake/**", tenant)},
				Conditions: policy.Conditions{"StringEquals": {"department": {"engineering"}}}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles",
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
		TenantID: tenant,
		Statements: []policy.Statement{
			{Sid: "eng-files", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:**", tenant)},
				Conditions: policy.Conditions{"StringEquals": {"department": {"engineering"}}}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", nil)

	m := mapping()
	m.Region = "" // file is region-agnostic: no region column
	m.Conditions = map[string]string{"department": "department"}
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
// the whole tree where status="active", minus the projectx/secrets subtree.
func TestWhere_READMEFileAccessExample(t *testing.T) {
	pol := policy.Policy{
		TenantID: tenant,
		Statements: []policy.Statement{
			{Sid: "read-active-files", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:**", tenant)},
				Conditions: policy.Conditions{"StringEquals": {"status": {"active"}}}},
			{Sid: "protect-projectx-secrets", Effect: policy.Deny, Actions: []string{"*"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file::file:projectx/secrets/**", tenant)}},
		},
	}
	cons := engine.Constrain([]policy.Policy{pol}, "file:listFiles", nil)

	sql, args, err := sqlfilter.Where(cons, sqlfilter.Mapping{
		Tenant:     "tenant_id",
		Type:       "type",
		Resource:   sqlfilter.ResourceColumn{Path: "path"},
		Conditions: map[string]string{"status": "status"},
	})
	if err != nil {
		t.Fatalf("Where: %v", err)
	}
	wantSQL := "(tenant_id = ? AND type = ? AND status = ?) " +
		"AND NOT (tenant_id = ? AND type = ? AND (path = ? OR path LIKE ? ESCAPE '\\'))"
	if sql != wantSQL {
		t.Errorf("sql =\n  %q\nwant\n  %q", sql, wantSQL)
	}
	wantArgs := []any{tenant, "file", "active", tenant, "file", "projectx/secrets", "projectx/secrets/%"}
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
		Tenant: "tenant_id", Type: "type", Resource: sqlfilter.ResourceColumn{ID: "id", Path: "path"},
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
		Tenant: "tenant_id", Type: "type", Resource: sqlfilter.ResourceColumn{Path: "path"},
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
	m.Conditions = map[string]string{
		"department": "dept", "env": "env", "size": "size", "archived": "archived", "owner": "owner",
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
		{"in-list", policy.Conditions{"StringEquals": {"department": {"eng", "ops"}}},
			prefix + "dept IN (?, ?)", []any{tenant, "file", "eng", "ops"}},
		{"not-equals", policy.Conditions{"StringNotEquals": {"department": {"eng"}}},
			prefix + "(dept IS NULL OR dept <> ?)", []any{tenant, "file", "eng"}},
		{"like", policy.Conditions{"StringLike": {"env": {"prod*"}}},
			prefix + "env LIKE ? ESCAPE '\\'", []any{tenant, "file", "prod%"}},
		{"numeric-gt", policy.Conditions{"NumericGreaterThan": {"size": {"100"}}},
			prefix + "size > ?", []any{tenant, "file", float64(100)}},
		{"bool", policy.Conditions{"Bool": {"archived": {"false"}}},
			prefix + "archived = ?", []any{tenant, "file", false}},
		{"null-true", policy.Conditions{"Null": {"owner": {"true"}}},
			prefix + "owner IS NULL", []any{tenant, "file"}},
		{"if-exists", policy.Conditions{"StringEqualsIfExists": {"department": {"eng"}}},
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

// Unhappy: a resource-attribute condition with no column mapping is rejected.
func TestWhere_ConditionUnmappedKey(t *testing.T) {
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "**"),
		Conditions: policy.Conditions{"StringEquals": {"department": {"eng"}}},
	}}}
	if _, _, err := sqlfilter.Where(c, mapping()); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
		t.Errorf("err = %v, want ErrUnsupportedCondition", err)
	}
}

// Unhappy: an operator with no portable SQL form is rejected even when mapped.
func TestWhere_ConditionUnsupportedOperator(t *testing.T) {
	m := mapping()
	m.Conditions = map[string]string{"sourceIp": "ip"}
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "**"),
		Conditions: policy.Conditions{"IpAddress": {"sourceIp": {"10.0.0.0/8"}}},
	}}}
	if _, _, err := sqlfilter.Where(c, m); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
		t.Errorf("err = %v, want ErrUnsupportedCondition", err)
	}
}

func TestWhere_Errors(t *testing.T) {
	base := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "datalake/**")}}}

	if _, _, err := sqlfilter.Where(base, sqlfilter.Mapping{}); !errors.Is(err, sqlfilter.ErrTenantColumnRequired) {
		t.Errorf("missing tenant col: err = %v", err)
	}

	withCond := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "datalake/**"),
		Conditions: policy.Conditions{"Bool": {"mfa": {"true"}}},
	}}}
	if _, _, err := sqlfilter.Where(withCond, mapping()); !errors.Is(err, sqlfilter.ErrUnsupportedCondition) {
		t.Errorf("conditions: err = %v", err)
	}

	// literal type but no type column mapped -> fail closed
	m := mapping()
	m.Type = ""
	if _, _, err := sqlfilter.Where(base, m); !errors.Is(err, sqlfilter.ErrNoColumnForField) {
		t.Errorf("missing type col: err = %v", err)
	}

	// mid-path single-segment wildcard cannot be expressed
	mid := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern(t, "datalake/*/raw")}}}
	if _, _, err := sqlfilter.Where(mid, mapping()); !errors.Is(err, sqlfilter.ErrUnsupportedPattern) {
		t.Errorf("mid-path wildcard: err = %v", err)
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
