package engine

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/grasp-labs/ds-go-policy/policy"
)

// ErrUnknownOperator is returned by Compile when a policy uses a condition
// operator the engine does not implement. Failing at compile time keeps
// evaluation fail-closed (an unknown operator never silently passes).
var ErrUnknownOperator = errors.New("unknown condition operator")

// ErrInvalidResourceKey is returned by Compile when a condition key under the
// reserved "resource." namespace is not one of the defined forms. Rejecting it
// at load time keeps a typo (e.g. "resource.path[two]") from becoming a key
// that silently never resolves.
var ErrInvalidResourceKey = errors.New("invalid resource condition key")

// resourceKeyPrefix reserves a condition-key namespace that the engine resolves
// from the request resource itself — never from the caller-supplied context, so
// it cannot be spoofed. The one defined form is:
//
//	resource.path[N] — the Nth segment (0-based) of the CRN resource path,
//	                   e.g. resource.path[2] of "files/inbound/123456789/x"
//	                   is "123456789". Out of range means the key is absent.
//
// It pins a path partition to a value set without enumerating one resource
// pattern per value. At Constrain time there is no concrete resource, so these
// keys always defer to the adapter (e.g. mapped to a column via the sqlfilter
// Mapping.Conditions).
const resourceKeyPrefix = "resource."

// ResourcePathKey reports whether a condition key is the reserved
// "resource.path[N]" resource-derived form and, if so, returns the 0-based
// segment index N. Adapters use it to recognize segment conditions they can
// express structurally (pathfilter folds them into globs; sqlfilter maps them
// to columns like any other residual key).
func ResourcePathKey(key string) (index int, ok bool) {
	return pathIndex(key)
}

// pathIndex reports whether key is the reserved "resource.path[N]" form and
// returns the 0-based segment index N.
func pathIndex(key string) (int, bool) {
	s, ok := strings.CutPrefix(key, "resource.path[")
	if !ok {
		return 0, false
	}
	s, ok = strings.CutSuffix(s, "]")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// conditionValue resolves one condition key: reserved resource-derived keys are
// answered from the resource path, everything else from the context.
func conditionValue(key string, ctx map[string]string, path []string) (string, bool) {
	if n, ok := pathIndex(key); ok {
		if n < len(path) {
			return path[n], true
		}
		return "", false
	}
	v, ok := ctx[key]
	return v, ok
}

// condFunc evaluates one operator for one key: actual is the request-context
// value, present reports whether the key was supplied, and wants are the
// policy's acceptable values (OR-ed together).
type condFunc func(actual string, present bool, wants []string) bool

// conditionOps mirrors the mainstream IAM condition operators. Each "Not"
// variant is the negation of its positive form, which also yields the
// conventional missing-key behavior (a negated operator is true when the key
// is absent).
// Every operator additionally supports the "...IfExists" suffix (handled in
// evalConditions), which passes when the key is absent.
var conditionOps = map[string]condFunc{
	"StringEquals":              opStringEquals,
	"StringNotEquals":           not(opStringEquals),
	"StringEqualsIgnoreCase":    opStringEqualsIgnoreCase,
	"StringNotEqualsIgnoreCase": not(opStringEqualsIgnoreCase),
	"StringLike":                opStringLike,
	"StringNotLike":             not(opStringLike),

	"Bool": opBool,

	"NumericEquals":            numeric(func(a, b float64) bool { return a == b }),
	"NumericNotEquals":         not(numeric(func(a, b float64) bool { return a == b })),
	"NumericLessThan":          numeric(func(a, b float64) bool { return a < b }),
	"NumericLessThanEquals":    numeric(func(a, b float64) bool { return a <= b }),
	"NumericGreaterThan":       numeric(func(a, b float64) bool { return a > b }),
	"NumericGreaterThanEquals": numeric(func(a, b float64) bool { return a >= b }),

	"DateEquals":            dateCmp(func(a, b time.Time) bool { return a.Equal(b) }),
	"DateNotEquals":         not(dateCmp(func(a, b time.Time) bool { return a.Equal(b) })),
	"DateLessThan":          dateCmp(func(a, b time.Time) bool { return a.Before(b) }),
	"DateLessThanEquals":    dateCmp(func(a, b time.Time) bool { return !a.After(b) }),
	"DateGreaterThan":       dateCmp(func(a, b time.Time) bool { return a.After(b) }),
	"DateGreaterThanEquals": dateCmp(func(a, b time.Time) bool { return !a.Before(b) }),

	"IpAddress":    opIPAddress,
	"NotIpAddress": not(opIPAddress),

	"Null": opNull,
}

const ifExistsSuffix = "IfExists"

// evalConditions applies conventional IAM semantics: all operators must pass, all keys under
// an operator must pass, and a key's values OR together. Empty conditions match.
// path carries the request resource's path segments for the reserved
// resource-derived keys (see resourceKeyPrefix).
func evalConditions(conds policy.Conditions, ctx map[string]string, path []string) bool {
	for op, keyVals := range conds {
		base, ifExists := strings.CutSuffix(op, ifExistsSuffix)
		fn, ok := conditionOps[base]
		if !ok {
			return false // defensive; Compile rejects unknown operators up front
		}
		for key, wants := range keyVals {
			actual, present := conditionValue(key, ctx, path)
			if !present && ifExists {
				continue
			}
			if !fn(actual, present, wants) {
				return false
			}
		}
	}
	return true
}

// resolveConditions partially evaluates a condition block against a known
// context (e.g. principal/request attributes available at list time). It splits
// each condition key into "resolved now" vs "deferred":
//
//   - If the key is present in ctx, it is evaluated immediately. If that check
//     fails, ok is false and the whole statement does not apply to this
//     principal (the caller drops it).
//   - If the key is absent from ctx, the condition is a resource attribute the
//     store must enforce, so it is copied into deferred for the adapter.
//
// When ok is true and deferred is nil, every condition was satisfied by the
// context and the resulting pattern carries no residual conditions (adapters
// can consume it directly). Empty conditions resolve to (nil, true).
func resolveConditions(conds policy.Conditions, ctx map[string]string) (deferred policy.Conditions, ok bool) {
	for op, keyVals := range conds {
		base, _ := strings.CutSuffix(op, ifExistsSuffix)
		fn, known := conditionOps[base]
		if !known {
			return nil, false // defensive; Compile rejects unknown operators up front
		}
		for key, wants := range keyVals {
			actual, present := ctx[key]
			if _, isResource := pathIndex(key); isResource {
				// Resource-derived keys resolve against the resource, and at
				// Constrain time there is none — always defer, and never trust
				// a context entry that shadows the reserved key.
				present = false
			}
			if !present {
				// Deferred under the original operator, IfExists suffix and
				// all: presence is decided against the store, not the context.
				if deferred == nil {
					deferred = policy.Conditions{}
				}
				if deferred[op] == nil {
					deferred[op] = map[string]policy.Values{}
				}
				deferred[op][key] = wants
				continue
			}
			// Present keys evaluate the base operator, same as evalConditions.
			if !fn(actual, present, wants) {
				return nil, false
			}
		}
	}
	return deferred, true
}

// validateConditions rejects unknown operators and malformed reserved keys so
// Compile can fail closed.
func validateConditions(conds policy.Conditions) error {
	for op, keyVals := range conds {
		base, _ := strings.CutSuffix(op, ifExistsSuffix)
		if _, ok := conditionOps[base]; !ok {
			return fmt.Errorf("%w: %q", ErrUnknownOperator, op)
		}
		for key := range keyVals {
			if strings.HasPrefix(key, resourceKeyPrefix) {
				if _, ok := pathIndex(key); !ok {
					return fmt.Errorf("%w: %q", ErrInvalidResourceKey, key)
				}
			}
		}
	}
	return nil
}

func not(op condFunc) condFunc {
	return func(actual string, present bool, wants []string) bool {
		return !op(actual, present, wants)
	}
}

func opStringEquals(actual string, present bool, wants []string) bool {
	if !present {
		return false
	}
	for _, w := range wants {
		if actual == w {
			return true
		}
	}
	return false
}

func opStringEqualsIgnoreCase(actual string, present bool, wants []string) bool {
	if !present {
		return false
	}
	for _, w := range wants {
		if strings.EqualFold(actual, w) {
			return true
		}
	}
	return false
}

func opStringLike(actual string, present bool, wants []string) bool {
	if !present {
		return false
	}
	for _, w := range wants {
		if wildcardMatch(w, actual) {
			return true
		}
	}
	return false
}

func opBool(actual string, present bool, wants []string) bool {
	if !present {
		return false
	}
	a, err := strconv.ParseBool(strings.ToLower(actual))
	if err != nil {
		return false
	}
	for _, w := range wants {
		if b, err := strconv.ParseBool(strings.ToLower(w)); err == nil && a == b {
			return true
		}
	}
	return false
}

func numeric(cmp func(a, b float64) bool) condFunc {
	return func(actual string, present bool, wants []string) bool {
		if !present {
			return false
		}
		a, err := strconv.ParseFloat(actual, 64)
		if err != nil {
			return false
		}
		for _, w := range wants {
			if b, err := strconv.ParseFloat(w, 64); err == nil && cmp(a, b) {
				return true
			}
		}
		return false
	}
}

func dateCmp(cmp func(a, b time.Time) bool) condFunc {
	return func(actual string, present bool, wants []string) bool {
		if !present {
			return false
		}
		a, err := time.Parse(time.RFC3339, actual)
		if err != nil {
			return false
		}
		for _, w := range wants {
			if b, err := time.Parse(time.RFC3339, w); err == nil && cmp(a, b) {
				return true
			}
		}
		return false
	}
}

func opIPAddress(actual string, present bool, wants []string) bool {
	if !present {
		return false
	}
	ip := net.ParseIP(actual)
	if ip == nil {
		return false
	}
	for _, w := range wants {
		if _, cidr, err := net.ParseCIDR(w); err == nil {
			if cidr.Contains(ip) {
				return true
			}
			continue
		}
		if wip := net.ParseIP(w); wip != nil && wip.Equal(ip) {
			return true
		}
	}
	return false
}

// opNull implements the Null operator: value "true" means the key must be
// absent, "false" means it must be present.
func opNull(actual string, present bool, wants []string) bool {
	_ = actual
	for _, w := range wants {
		wantAbsent, err := strconv.ParseBool(w)
		if err != nil {
			continue
		}
		if wantAbsent == !present {
			return true
		}
	}
	return false
}

// wildcardMatch matches StringLike wildcards: "*" (any sequence) and "?"
// (single character). Linear time, rune-aware.
func wildcardMatch(pattern, s string) bool {
	p, t := []rune(pattern), []rune(s)
	px, sx := 0, 0
	starPx, starSx := -1, -1
	for sx < len(t) {
		switch {
		case px < len(p) && (p[px] == '?' || p[px] == t[sx]):
			px, sx = px+1, sx+1
		case px < len(p) && p[px] == '*':
			starPx, starSx = px, sx
			px++
		case starPx != -1:
			px = starPx + 1
			starSx++
			sx = starSx
		default:
			return false
		}
	}
	for px < len(p) && p[px] == '*' {
		px++
	}
	return px == len(p)
}
