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
// and selects nothing. An otherwise applicable pattern that pins a segment the
// Mapping neither stores nor fixes fails rather than being silently widened.
package sqlfilter

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/grasp-labs/ds-go-policy/conditionoperator"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

const closedClause = "1=0"

// PlatformIssuerColumn and PlatformIssuerPublic are the fixed column and value
// that mark platform-published rows in every platform-published table. They are
// the single source of truth for the trust invariant behind the "aic" pattern:
// the read filter authorizes such a row to every principal solely because it
// carries this marker, so each service's write path MUST reject any attempt by a
// non-platform tenant to set PlatformIssuerColumn to PlatformIssuerPublic.
// Services should reference these constants in that guard (and its tests) so the
// write check cannot drift from the read filter. See docs/iam-policy-contract.md.
const (
	PlatformIssuerColumn = "issuer"
	PlatformIssuerPublic = "public"
)

// platformOwnedPredicate is the SQL predicate emitted for an "aic" pattern,
// derived from the exported marker so the two cannot diverge.
const platformOwnedPredicate = PlatformIssuerColumn + " = '" + PlatformIssuerPublic + "'"

var (
	// ErrServiceRequired is returned when Mapping.Service is empty.
	ErrServiceRequired = errors.New("sqlfilter: resource service is required")
	// ErrInvalidService is returned when Mapping.Service equals crn.Wildcard.
	ErrInvalidService = errors.New("sqlfilter: resource service must be concrete")
	// ErrTenantColumnRequired is returned when Mapping.Tenant is empty and
	// TenantAnswered is false. Tenant scoping must be handled in one of those two
	// places.
	ErrTenantColumnRequired = errors.New("sqlfilter: tenant column is required")
	// ErrTenantConflict is returned when Mapping sets both Tenant and
	// TenantAnswered. The two contradict — one emits the tenant predicate, the
	// other declares it enforced outside the filter — and guessing which the
	// service meant could drop a predicate it relies on.
	ErrTenantConflict = errors.New("sqlfilter: Tenant column and TenantAnswered are mutually exclusive")
	// ErrNoColumnForField is returned when an applicable pattern constrains a
	// field to a literal but Mapping neither stores it nor declares it fixed.
	// Silently dropping the predicate would over-grant, so this fails instead.
	ErrNoColumnForField = errors.New("sqlfilter: no column mapped for a constrained field")
	// ErrUnsupportedPattern is returned for resource patterns that cannot be
	// expressed exactly in SQL (e.g. a mid-path single-segment wildcard).
	ErrUnsupportedPattern = errors.New("sqlfilter: resource pattern cannot be expressed as SQL")
	// ErrUnsupportedCondition is returned when a residual condition cannot become
	// a predicate because its key is unmapped, its operator is not allowed or
	// supported, or a value has the wrong type.
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
// Service is the concrete resource service represented by the table. Patterns
// for another service are omitted; wildcard-service patterns remain applicable.
//
// Tenant is the owning-tenant column and is required unless TenantAnswered
// declares that scoping is enforced outside the filter; setting both fails. A
// concrete or "self" pattern emits Tenant = ?; a pattern bound to
// crn.PlatformTenant ("aic") names platform-published rows, which every table
// marks with the fixed convention issuer = 'public' — the adapter emits that
// predicate directly, so no per-table configuration is required.
//
// TenantAnswered declares the tenant predicate is enforced outside the filter,
// so no tenant predicate is emitted for either a concrete or a platform pattern.
// It requires independent proof that every retained match applies to the table
// projection, and the caller must still enforce the table's own visibility
// predicate.
//
// PublicRows declares the table's platform-published rows readable by every
// principal that holds the action, so the filter ORs issuer = 'public' onto the
// allow clause instead of requiring a pattern to name them. It widens only what
// an existing grant already opened: with no applicable allow the clause stays
// closed, and denies still subtract. Set it on the mapping a read uses; a
// mapping used for writes must leave it off, or a tenant could edit rows the
// platform published. The trust invariant below applies.
//
// Scope, Region and Type are columns for segments that vary per row. A column
// may be empty when applicable patterns use the wildcard or Fixed declares the
// table-wide value — for example, type "group" and empty scope and region for a
// groups table. A fixed mismatch selects no rows. A literal with neither a
// column nor a Fixed entry is unrepresentable; use a Fixed entry with value ""
// for an unmapped absent dimension. If both are present, the column wins.
//
// Conditions maps a residual condition key left by engine.Constrain (e.g.
// "department") to its trusted SQL column or expression.
// AllowedConditionOperators lists the exact operator names valid for each key;
// an IfExists variant must be listed separately from its base operator.
// Unmapped keys and unlisted operators cause ErrUnsupportedCondition.
type Mapping struct {
	Service                   string
	Tenant                    string
	TenantAnswered            bool
	PublicRows                bool
	Scope                     string
	Region                    string
	Type                      string
	Fixed                     map[Segment]string
	Resource                  ResourceColumn
	Conditions                map[string]string
	AllowedConditionOperators map[string][]string
}

// Where returns a clause (with ? placeholders and positional args) to AND into a
// query. A valid Mapping with no applicable allow patterns returns "1=0"
// without evaluating denies. Otherwise, an applicable pattern or condition
// that cannot be represented returns an error.
func Where(c engine.Constraints, m Mapping) (string, []any, error) {
	if m.Service == "" {
		return "", nil, ErrServiceRequired
	}
	if m.Service == crn.Wildcard {
		return "", nil, ErrInvalidService
	}
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
		return closedClause, nil, nil
	}
	// A grant over any row of a PublicRows table also opens its platform-published
	// rows. The OR sits inside the allow clause, so a pattern that narrows the
	// caller's own rows by id, owner or condition cannot narrow these away, and
	// the deny composition below still subtracts them.
	if m.PublicRows {
		allowSQL = "(" + allowSQL + ") OR " + platformOwnedPredicate
	}
	denySQL, denyArgs, err := orGroups(c.Deny, m)
	if err != nil {
		return "", nil, err
	}
	if denySQL == "" {
		return allowSQL, allowArgs, nil
	}
	// A deny applies only when its complete predicate is TRUE. SQL comparisons
	// against NULL evaluate to UNKNOWN; that represents an absent resource
	// attribute and must not make a positive IAM condition match. IS NOT TRUE
	// preserves those rows while still subtracting every matching deny group.
	return fmt.Sprintf("(%s) AND ((%s) IS NOT TRUE)", allowSQL, denySQL), append(allowArgs, denyArgs...), nil
}

// IsClosed reports whether where is the fail-closed clause returned by Where
// when no allow pattern can select a row.
func IsClosed(where string) bool {
	return where == closedClause
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

	service := p.Service()
	if service != crn.Wildcard && service != m.Service {
		return "", nil, false, nil
	}

	fields := []struct {
		segment  Segment
		col, val string
	}{
		{SegmentScope, m.Scope, p.Scope()},
		{SegmentRegion, m.Region, p.Region()},
		{SegmentType, m.Type, p.Type()},
	}
	// Prove fixed-dimension mismatches before reporting another unmapped field.
	// One mismatch makes the whole pattern disjoint from this table.
	for _, f := range fields {
		if f.val == crn.Wildcard || f.col != "" {
			continue
		}
		if fixed, declared := m.Fixed[f.segment]; declared && f.val != fixed {
			return "", nil, false, nil
		}
	}

	// Tenant is always constrained (never a wildcard); engine.Constrain has
	// already resolved a "self" placeholder to the concrete request tenant. A
	// PlatformTenant ("aic") pattern names platform-published rows, marked by the
	// fixed issuer = 'public' convention. With TenantAnswered the service enforces
	// tenant scoping itself (see Mapping).
	if !m.TenantAnswered {
		if p.Tenant() == crn.PlatformTenant {
			preds = append(preds, platformOwnedPredicate)
		} else {
			preds = append(preds, m.Tenant+" = ?")
			args = append(args, p.Tenant())
		}
	}

	for _, f := range fields {
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
		// Without a column or an explicit fixed value, no literal can be
		// evaluated safely. This includes "": an absent dimension must be
		// declared with Fixed rather than inferred from the pattern.
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
// stable. An unmapped key or a disallowed/inexpressible operator or value fails
// with ErrUnsupportedCondition (fail-safe).
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
			if !slices.Contains(m.AllowedConditionOperators[key], op) {
				return nil, nil, fmt.Errorf(
					"%w: operator %q is not allowed for key %q",
					ErrUnsupportedCondition,
					op,
					key,
				)
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
	base, ifExists := strings.CutSuffix(op, conditionoperator.IfExistsSuffix)
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
	case conditionoperator.StringEquals:
		s, a := inPred(col, strArgs(vals))
		return s, a, nil
	case conditionoperator.StringNotEquals:
		s, a := notInPred(col, strArgs(vals))
		return s, a, nil
	case conditionoperator.StringLike:
		s, a := likePred(col, vals, false)
		return s, a, nil
	case conditionoperator.StringNotLike:
		s, a := likePred(col, vals, true)
		return s, a, nil
	case conditionoperator.Bool:
		return boolPred(col, vals)
	case conditionoperator.Null:
		return nullPred(col, vals)
	case conditionoperator.NumericEquals:
		a, err := numArgs(vals)
		if err != nil {
			return "", nil, err
		}
		s, aa := inPred(col, a)
		return s, aa, nil
	case conditionoperator.NumericNotEquals:
		a, err := numArgs(vals)
		if err != nil {
			return "", nil, err
		}
		s, aa := notInPred(col, a)
		return s, aa, nil
	case conditionoperator.NumericLessThan:
		return numCmp(col, "<", vals)
	case conditionoperator.NumericLessThanEquals:
		return numCmp(col, "<=", vals)
	case conditionoperator.NumericGreaterThan:
		return numCmp(col, ">", vals)
	case conditionoperator.NumericGreaterThanEquals:
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
		return "", nil, fmt.Errorf("%w: %s takes exactly one value", ErrUnsupportedCondition, conditionoperator.Null)
	}
	absent, err := strconv.ParseBool(vals[0])
	if err != nil {
		return "", nil, fmt.Errorf("%w: %s value %q is not boolean", ErrUnsupportedCondition, conditionoperator.Null, vals[0])
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
