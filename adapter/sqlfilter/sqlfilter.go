// Package sqlfilter turns engine.Constraints into a SQL WHERE clause that a
// service ANDs into its list/query for the current principal. It only narrows:
// it emits the allow patterns OR-ed together, minus the deny patterns
// (deny-wins), scoped to the columns the service provides via Mapping.
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
	// ErrNoColumnForField is returned when a pattern constrains a field to a
	// literal but Mapping has no column for it. Silently dropping the predicate
	// would over-grant, so this fails instead.
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

// ResourceColumn maps the CRN resource segment onto storage columns. Provide the
// ID column for id-addressed resources, the Path column for path-addressed ones,
// or both — the adapter picks based on the pattern.
type ResourceColumn struct {
	ID   string
	Path string
}

// Mapping maps CRN segments to one table's columns. Tenant is required; leave a
// column empty only if you never constrain that field to a literal.
//
// Conditions maps a residual condition key (a resource attribute left by
// engine.Constrain, e.g. "department") to the column that stores it. Keys not
// listed here cannot be expressed and cause ErrUnsupportedCondition — principal
// or request attributes should instead be resolved via the Constrain context.
type Mapping struct {
	Tenant     string
	Scope      string
	Region     string
	Type       string
	Resource   ResourceColumn
	Conditions map[string]string
}

// Where returns a clause (with ? placeholders and positional args) to AND into a
// query. With no allow patterns it returns "1=0" (the principal sees nothing).
func Where(c engine.Constraints, m Mapping) (string, []any, error) {
	if m.Tenant == "" {
		return "", nil, ErrTenantColumnRequired
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

func orGroups(matches []engine.ResourceMatch, m Mapping) (string, []any, error) {
	var groups []string
	var args []any
	for _, rm := range matches {
		g, gArgs, err := group(rm, m)
		if err != nil {
			return "", nil, err
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

func group(rm engine.ResourceMatch, m Mapping) (string, []any, error) {
	p := rm.Pattern
	// Tenant is always constrained (never a wildcard); engine.Constrain has
	// already resolved the platform placeholder to a concrete tenant.
	preds := []string{m.Tenant + " = ?"}
	args := []any{p.Tenant()}

	for _, f := range []struct{ col, val string }{
		{m.Scope, p.Scope()},
		{m.Region, p.Region()},
		{m.Type, p.Type()},
	} {
		if f.val == crn.Wildcard {
			continue // "*" matches any value (Decide: matchField("*", …) is always true)
		}
		if f.col == "" {
			// An empty segment is region-agnostic. With no column there is
			// nothing to filter (all rows share the absent dimension), so it is
			// unconstrained. A non-empty literal with no column would be dropped
			// silently and over-grant, so that fails instead.
			if f.val == "" {
				continue
			}
			return "", nil, ErrNoColumnForField
		}
		// Empty is a literal here: Decide matches it only against an empty value,
		// so emit equality to "" rather than skipping (skipping would match every
		// value and grant more than Decide).
		preds = append(preds, f.col+" = ?")
		args = append(args, f.val)
	}

	rp, rArgs, err := resourcePred(p.Resource(), m.Resource)
	if err != nil {
		return "", nil, err
	}
	if rp != "" {
		preds = append(preds, rp)
		args = append(args, rArgs...)
	}

	cp, cArgs, err := conditionPreds(rm.Conditions, m)
	if err != nil {
		return "", nil, err
	}
	preds = append(preds, cp...)
	args = append(args, cArgs...)

	return strings.Join(preds, " AND "), args, nil
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
