// Package sqlfilter turns engine.Constraints into a SQL WHERE clause that a
// service ANDs into its list/query for the current principal. It only narrows:
// it emits the allow patterns OR-ed together, minus the deny patterns
// (deny-wins), scoped to the columns the service provides via Mapping.
//
// A CRN segment a table stores per row maps to a column; a segment every row
// of the table shares — the type of a per-type table, an unused scope — is
// declared constant via Mapping.Fixed. A pattern pinning a fixed segment is
// evaluated against the constant instead of translated: it either agrees, and
// constrains nothing beyond it, or names a value no row of the table can hold,
// and selects nothing. A pattern that pins a segment the Mapping neither
// stores nor fixes fails rather than being silently widened.
package sqlfilter

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

var (
	// ErrTenantColumnRequired is returned when Mapping.Tenant is empty. Tenant
	// scoping is mandatory — omitting it would allow cross-tenant rows.
	ErrTenantColumnRequired = errors.New("sqlfilter: tenant column is required")
	// ErrTenantConflict is returned when Mapping sets both Tenant and
	// TenantAnswered. The two contradict — one emits the tenant predicate, the
	// other declares it enforced outside the filter — and guessing which the
	// service meant could drop a predicate it relies on.
	ErrTenantConflict = errors.New("sqlfilter: Tenant column and TenantAnswered are mutually exclusive")
	// ErrNoColumnForField is returned when a pattern constrains a field to a
	// literal but Mapping neither stores it in a column nor declares it fixed.
	// Silently dropping the predicate would over-grant, so this fails instead.
	ErrNoColumnForField = errors.New("sqlfilter: no column mapped for a constrained field")
	// ErrUnsupportedPattern is returned for resource patterns that cannot be
	// expressed exactly in SQL (e.g. a mid-path single-segment wildcard).
	ErrUnsupportedPattern = errors.New("sqlfilter: resource pattern cannot be expressed as SQL")
	// ErrUnsupportedCondition is returned when a residual condition cannot be
	// turned into a predicate: its key has no column in Mapping.Conditions, its
	// operator is not translatable to portable SQL (e.g. IpAddress/Date), or a
	// value has the wrong type. Failing (rather than dropping the predicate)
	// keeps the filter from over-granting.
	ErrUnsupportedCondition = errors.New("sqlfilter: condition cannot be expressed as SQL")
)

// Segment names a flat CRN segment whose value a Mapping can pin to a constant
// via Fixed.
type Segment int

const (
	SegmentScope Segment = iota
	SegmentRegion
	SegmentType
)

// ResourceColumn maps the CRN resource segment onto storage columns. Provide the
// ID column for id-addressed resources, the Path column for path-addressed ones,
// or both — the adapter picks based on the pattern.
type ResourceColumn struct {
	ID   string
	Path string
}

// Mapping maps CRN segments to one table's columns.
//
// Tenant is the column holding the owning tenant and is required, unless
// TenantAnswered declares the segment enforced outside the filter (setting
// both is contradictory and fails with ErrTenantConflict). Set
// TenantAnswered only for collections the platform publishes across tenants
// (managed policies, a global catalog): there the pattern's tenant is the
// grant's scope, not the row's owner, and an owner-column predicate would hide
// every public row from a caller plainly allowed to read it. engine.Constrain
// has already dropped foreign-tenant patterns and resolved the platform
// placeholder to the caller, so skipping the predicate never widens beyond the
// caller's grant — but the service must still AND its own visibility clause
// (e.g. owner = platform) into the query.
//
// Scope, Region and Type are columns for segments that vary per row; leave one
// empty only if you never constrain that segment to a literal. Fixed instead
// carries the segments every row of the table shares — for a table of groups,
// the type "group" and an empty scope and region. A pattern pinning a fixed
// segment either agrees with the constant (nothing to narrow) or selects no
// row of this table. A segment that is neither a column nor fixed cannot be
// evaluated, and a pattern pinning it fails with ErrNoColumnForField rather
// than being silently ignored. If a segment is both a column and fixed, the
// column wins.
//
// Conditions maps a residual condition key (a resource attribute left by
// engine.Constrain, e.g. "department") to the column that stores it. Keys not
// listed here cannot be expressed and cause ErrUnsupportedCondition — principal
// or request attributes should instead be resolved via the Constrain context.
type Mapping struct {
	Tenant         string
	TenantAnswered bool
	Scope          string
	Region         string
	Type           string
	Fixed          map[Segment]string
	Resource       ResourceColumn
	Conditions     map[string]string
}

// Where returns a clause (with ? placeholders and positional args) to AND into a
// query. With no allow patterns — none granted, or none selecting a row of this
// table — it returns "1=0" (the principal sees nothing).
func Where(c engine.Constraints, m Mapping) (string, []any, error) {
	if m.Tenant == "" && !m.TenantAnswered {
		return "", nil, ErrTenantColumnRequired
	}
	if m.Tenant != "" && m.TenantAnswered {
		return "", nil, ErrTenantConflict
	}
	allowSQL, allowArgs, err := orGroups(c.Allow, m)
	if err != nil {
		return "", nil, err
	}
	if allowSQL == "" {
		return "1=0", nil, nil
	}
	denySQL, denyArgs, err := orGroups(c.Deny, m)
	if err != nil {
		return "", nil, err
	}
	if denySQL == "" {
		return allowSQL, allowArgs, nil
	}
	return fmt.Sprintf("(%s) AND NOT (%s)", allowSQL, denySQL), append(allowArgs, denyArgs...), nil
}

// orGroups OR-s one predicate group per pattern. A pattern that selects no row
// in this table contributes nothing, which is exact for either effect: an allow
// over rows that cannot exist grants nothing, and a deny over them denies
// nothing.
func orGroups(matches []engine.ResourceMatch, m Mapping) (string, []any, error) {
	var groups []string
	var args []any
	for _, rm := range matches {
		g, gArgs, ok, err := group(rm, m)
		if err != nil {
			return "", nil, err
		}
		if !ok {
			continue
		}
		groups = append(groups, g)
		args = append(args, gArgs...)
	}
	switch len(groups) {
	case 0:
		return "", nil, nil
	case 1:
		return groups[0], args, nil
	default:
		return "(" + strings.Join(groups, ") OR (") + ")", args, nil
	}
}

// group turns one pattern into the AND of its segment predicates. The bool
// reports whether the pattern can select a row of this table at all.
func group(rm engine.ResourceMatch, m Mapping) (string, []any, bool, error) {
	p := rm.Pattern
	var preds []string
	var args []any
	// Tenant is always constrained (never a wildcard); engine.Constrain has
	// already resolved the platform placeholder to a concrete tenant. With
	// TenantAnswered the service enforces the segment itself (see Mapping).
	if !m.TenantAnswered {
		preds = append(preds, m.Tenant+" = ?")
		args = append(args, p.Tenant())
	}

	for _, f := range []struct {
		segment  Segment
		col, val string
	}{
		{SegmentScope, m.Scope, p.Scope()},
		{SegmentRegion, m.Region, p.Region()},
		{SegmentType, m.Type, p.Type()},
	} {
		if f.val == crn.Wildcard {
			continue // "*" matches any value (Decide: matchField("*", …) is always true)
		}
		if f.col != "" {
			// Empty is a literal here: Decide matches it only against an empty
			// value, so emit equality to "" rather than skipping (skipping would
			// match every value and grant more than Decide).
			preds = append(preds, f.col+" = ?")
			args = append(args, f.val)
			continue
		}
		if fixed, declared := m.Fixed[f.segment]; declared {
			if f.val != fixed {
				return "", nil, false, nil // no row of this table can match
			}
			continue // agrees with the table's constant; nothing to narrow
		}
		// An empty segment is region-agnostic. With no column there is nothing
		// to filter (all rows share the absent dimension), so it is
		// unconstrained. A non-empty literal with neither column nor constant
		// would be dropped silently and over-grant, so that fails instead.
		if f.val == "" {
			continue
		}
		return "", nil, false, ErrNoColumnForField
	}

	rp, rArgs, err := resourcePred(p.Resource(), m.Resource)
	if err != nil {
		return "", nil, false, err
	}
	if rp != "" {
		preds = append(preds, rp)
		args = append(args, rArgs...)
	}

	cp, cArgs, err := conditionPreds(rm.Conditions, m)
	if err != nil {
		return "", nil, false, err
	}
	preds = append(preds, cp...)
	args = append(args, cArgs...)

	if len(preds) == 0 {
		// Every segment agreed with a constant or was a wildcard: the pattern
		// covers the whole table (within the service's own visibility clause).
		return "1=1", nil, true, nil
	}
	return strings.Join(preds, " AND "), args, true, nil
}

func resourcePred(res string, col ResourceColumn) (string, []any, error) {
	// "**" matches any resource path, including nested — no predicate needed.
	if res == crn.DeepWildcard {
		return "", nil, nil
	}

	// "*" matches exactly one segment (Decide: matchPath over a single "*").
	// Id-addressed resources are always one segment, so no predicate is needed;
	// for a purely path-addressed column, restrict to values without a separator
	// so we don't grant nested paths that Decide would reject (fail-open).
	if res == crn.Wildcard {
		switch {
		case col.ID != "":
			return "", nil, nil
		case col.Path != "":
			return fmt.Sprintf("%s NOT LIKE ? ESCAPE '\\'", col.Path), []any{"%/%"}, nil
		}
		return "", nil, ErrUnsupportedPattern
	}

	// Prefix pattern "<literal>/**": everything at or under the prefix.
	if suffix := "/" + crn.DeepWildcard; strings.HasSuffix(res, suffix) {
		prefix := strings.TrimSuffix(res, suffix)
		if strings.Contains(prefix, crn.Wildcard) || col.Path == "" {
			return "", nil, ErrUnsupportedPattern
		}
		like := escapeLike(prefix) + "/%"
		return fmt.Sprintf("(%s = ? OR %s LIKE ? ESCAPE '\\')", col.Path, col.Path), []any{prefix, like}, nil
	}

	// Exact literal (no wildcards): equality against the appropriate column.
	if !strings.Contains(res, crn.Wildcard) {
		switch {
		case strings.Contains(res, "/") && col.Path != "":
			return col.Path + " = ?", []any{res}, nil
		case col.ID != "":
			return col.ID + " = ?", []any{res}, nil
		case col.Path != "":
			return col.Path + " = ?", []any{res}, nil
		}
		return "", nil, ErrUnsupportedPattern
	}

	// Anything else (mid-path "*", etc.) cannot be represented exactly.
	return "", nil, ErrUnsupportedPattern
}

// escapeLike escapes the LIKE metacharacters in a literal prefix. The generated
// clause declares ESCAPE '\' so the escaping is portable.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// conditionPreds translates the residual conditions on a match into predicates.
// Output is deterministic (operators and keys sorted) so the generated SQL is
// stable. A key with no mapped column, or an operator/value that cannot be
// expressed, fails with ErrUnsupportedCondition (fail-safe).
func conditionPreds(conds policy.Conditions, m Mapping) ([]string, []any, error) {
	var preds []string
	var args []any
	for _, op := range sortedKeys(conds) {
		byKey := conds[op]
		for _, key := range sortedKeys(byKey) {
			col := m.Conditions[key]
			if col == "" {
				return nil, nil, fmt.Errorf("%w: no column mapped for key %q", ErrUnsupportedCondition, key)
			}
			pred, a, err := condPred(op, col, byKey[key])
			if err != nil {
				return nil, nil, err
			}
			preds = append(preds, pred)
			args = append(args, a...)
		}
	}
	return preds, args, nil
}

// condPred builds one predicate for a single operator/column/values triple and
// applies the "...IfExists" suffix (absent column value passes).
func condPred(op, col string, vals policy.Values) (string, []any, error) {
	if len(vals) == 0 {
		return "", nil, fmt.Errorf("%w: no values for operator %q", ErrUnsupportedCondition, op)
	}
	base, ifExists := strings.CutSuffix(op, "IfExists")
	pred, args, err := basePred(base, col, vals)
	if err != nil {
		return "", nil, err
	}
	if ifExists {
		pred = fmt.Sprintf("(%s IS NULL OR %s)", col, pred)
	}
	return pred, args, nil
}

// basePred maps a base operator to portable SQL. Operators that have no faithful
// portable form (IpAddress, Date*, *IgnoreCase) are rejected rather than
// approximated.
func basePred(base, col string, vals policy.Values) (string, []any, error) {
	switch base {
	case "StringEquals":
		s, a := inPred(col, strArgs(vals))
		return s, a, nil
	case "StringNotEquals":
		s, a := notInPred(col, strArgs(vals))
		return s, a, nil
	case "StringLike":
		s, a := likePred(col, vals, false)
		return s, a, nil
	case "StringNotLike":
		s, a := likePred(col, vals, true)
		return s, a, nil
	case "Bool":
		return boolPred(col, vals)
	case "Null":
		return nullPred(col, vals)
	case "NumericEquals":
		a, err := numArgs(vals)
		if err != nil {
			return "", nil, err
		}
		s, aa := inPred(col, a)
		return s, aa, nil
	case "NumericNotEquals":
		a, err := numArgs(vals)
		if err != nil {
			return "", nil, err
		}
		s, aa := notInPred(col, a)
		return s, aa, nil
	case "NumericLessThan":
		return numCmp(col, "<", vals)
	case "NumericLessThanEquals":
		return numCmp(col, "<=", vals)
	case "NumericGreaterThan":
		return numCmp(col, ">", vals)
	case "NumericGreaterThanEquals":
		return numCmp(col, ">=", vals)
	default:
		return "", nil, fmt.Errorf("%w: operator %q not translatable to SQL", ErrUnsupportedCondition, base)
	}
}

// inPred renders equality (one value) or an IN list (many). Values OR together.
func inPred(col string, args []any) (string, []any) {
	if len(args) == 1 {
		return col + " = ?", args
	}
	return fmt.Sprintf("%s IN (%s)", col, placeholders(len(args))), args
}

// notInPred is the negation of inPred. A NULL column passes, mirroring the
// conventional "key absent ⇒ NotEquals is true" semantics.
func notInPred(col string, args []any) (string, []any) {
	if len(args) == 1 {
		return fmt.Sprintf("(%s IS NULL OR %s <> ?)", col, col), args
	}
	return fmt.Sprintf("(%s IS NULL OR %s NOT IN (%s))", col, col, placeholders(len(args))), args
}

// numCmp renders an ordered numeric comparison (OR-ed across values).
func numCmp(col, sqlOp string, vals policy.Values) (string, []any, error) {
	args, err := numArgs(vals)
	if err != nil {
		return "", nil, err
	}
	if len(args) == 1 {
		return fmt.Sprintf("%s %s ?", col, sqlOp), args, nil
	}
	parts := make([]string, len(args))
	for i := range args {
		parts[i] = fmt.Sprintf("%s %s ?", col, sqlOp)
	}
	return "(" + strings.Join(parts, " OR ") + ")", args, nil
}

// likePred renders StringLike/StringNotLike. Positive values OR together; the
// negation is "matches none" (AND) and a NULL column passes.
func likePred(col string, vals policy.Values, negate bool) (string, []any) {
	parts := make([]string, len(vals))
	args := make([]any, len(vals))
	for i, v := range vals {
		args[i] = likePattern(v)
		if negate {
			parts[i] = fmt.Sprintf("%s NOT LIKE ? ESCAPE '\\'", col)
		} else {
			parts[i] = fmt.Sprintf("%s LIKE ? ESCAPE '\\'", col)
		}
	}
	if negate {
		body := strings.Join(parts, " AND ")
		if len(parts) > 1 {
			body = "(" + body + ")"
		}
		return fmt.Sprintf("(%s IS NULL OR %s)", col, body), args
	}
	body := strings.Join(parts, " OR ")
	if len(parts) > 1 {
		body = "(" + body + ")"
	}
	return body, args
}

func boolPred(col string, vals policy.Values) (string, []any, error) {
	args := make([]any, len(vals))
	for i, v := range vals {
		b, err := strconv.ParseBool(strings.ToLower(v))
		if err != nil {
			return "", nil, fmt.Errorf("%w: %q is not boolean", ErrUnsupportedCondition, v)
		}
		args[i] = b
	}
	s, a := inPred(col, args)
	return s, a, nil
}

// nullPred implements the Null operator: "true" ⇒ column IS NULL,
// "false" ⇒ column IS NOT NULL.
func nullPred(col string, vals policy.Values) (string, []any, error) {
	if len(vals) != 1 {
		return "", nil, fmt.Errorf("%w: Null takes exactly one value", ErrUnsupportedCondition)
	}
	absent, err := strconv.ParseBool(vals[0])
	if err != nil {
		return "", nil, fmt.Errorf("%w: Null value %q is not boolean", ErrUnsupportedCondition, vals[0])
	}
	if absent {
		return col + " IS NULL", nil, nil
	}
	return col + " IS NOT NULL", nil, nil
}

func strArgs(vals policy.Values) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}

func numArgs(vals policy.Values) ([]any, error) {
	out := make([]any, len(vals))
	for i, v := range vals {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not numeric", ErrUnsupportedCondition, v)
		}
		out[i] = f
	}
	return out, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?, ", n-1) + "?"
}

// likePattern converts a StringLike value into a SQL LIKE pattern: literal
// LIKE metacharacters are escaped, then "*"→"%" and "?"→"_".
func likePattern(s string) string {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
	esc = strings.ReplaceAll(esc, "*", "%")
	esc = strings.ReplaceAll(esc, "?", "_")
	return esc
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
