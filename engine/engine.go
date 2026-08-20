package engine

import (
	"strings"

	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/policy"
)

// Request context for a concrete operation.
type Request struct {
	Action   string // "{service}:{operationId}"
	Resource crn.CRN
	Context  map[string]string // attributes the service supplies for conditions
}

type Decision struct {
	Allowed bool
	Reason  string // matched sid / "implicit deny"
}

// Compiled is a validated, pre-parsed policy set. Building it once (via Compile)
// and reusing it avoids re-parsing CRN patterns on every request and moves all
// failure handling to load time, so evaluation itself never has to fail open.
type Compiled struct {
	statements []compiledStatement
}

type compiledStatement struct {
	sid        string
	effect     policy.Effect
	actions    []string
	patterns   []crn.Pattern
	conditions policy.Conditions
}

// Compile validates each policy and pre-parses its resource patterns. It fails
// closed: a structural error or an unparseable resource pattern is returned as
// an error rather than silently skipped — silently skipping a deny pattern
// would let a typo disable a protection (fail-open).
func Compile(policies []policy.Policy) (Compiled, error) {
	var c Compiled
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return Compiled{}, &ParseError{
				Kind:  ErrInvalidPolicy,
				Field: "policy",
				Value: p.ID,
				Cause: err,
			}
		}
		for _, s := range p.Statements {
			if err := validateConditions(s.Conditions); err != nil {
				return Compiled{}, &ParseError{
					Kind:  ErrInvalidConditions,
					Field: "conditions",
					Value: s.Sid,
					Cause: err,
				}
			}

			cs := compiledStatement{
				sid:        s.Sid,
				effect:     s.Effect,
				actions:    s.Actions,
				conditions: s.Conditions,
			}
			for _, res := range s.Resources {
				pat, err := crn.ParsePattern(res)
				if err != nil {
					return Compiled{}, &ParseError{
						Kind:  ErrInvalidPattern,
						Field: "resource",
						Value: res,
						Cause: err,
					}
				}
				cs.patterns = append(cs.patterns, pat)
			}
			c.statements = append(c.statements, cs)
		}
	}
	return c, nil
}

// --- Mode 1: full evaluation (PEP for request gating) ---

// Decide is the pure-function entry point: it compiles the policies and
// evaluates the request. On a compile error it fails closed (denies). For hot
// paths, compile once with Compile and call Compiled.Decide to reuse the work
// and to surface policy errors explicitly.
func Decide(policies []policy.Policy, r Request) Decision {
	c, err := Compile(policies)
	if err != nil {
		return Decision{Allowed: false, Reason: "invalid policy"}
	}
	return c.Decide(r)
}

// Decide evaluates a request against the compiled policies. Deny-wins,
// default-deny: any applicable deny short-circuits to a denial, and a request
// is allowed only if some statement explicitly allows it and none denies it.
func (c Compiled) Decide(r Request) Decision {
	allow := Decision{}
	for _, s := range c.statements {
		if !s.applies(r) {
			continue
		}
		switch s.effect {
		case policy.Deny:
			return Decision{Allowed: false, Reason: reason(s.sid, "explicit deny")}
		case policy.Allow:
			if !allow.Allowed { // remember first allow; a later deny may still override
				allow = Decision{Allowed: true, Reason: reason(s.sid, "allow")}
			}
		}
	}
	if allow.Allowed {
		return allow
	}
	return Decision{Allowed: false, Reason: "implicit deny"}
}

func (s compiledStatement) applies(r Request) bool {
	return actionMatches(s.actions, r.Action) &&
		s.matchesResource(r.Resource) &&
		evalConditions(s.conditions, r.Context, strings.Split(r.Resource.Resource, "/"))
}

func (s compiledStatement) matchesResource(c crn.CRN) bool {
	for _, pat := range s.patterns {
		if pat.Matches(c) {
			return true
		}
	}
	return false
}

// actionMatches supports exact ("file:getFile"), service-wildcard ("file:*"),
// and the global wildcard ("*").
func actionMatches(actions []string, action string) bool {
	for _, a := range actions {
		switch {
		case a == "*" || a == action:
			return true
		case strings.HasSuffix(a, ":*") && strings.HasPrefix(action, strings.TrimSuffix(a, "*")):
			return true
		}
	}
	return false
}

func reason(sid, fallback string) string {
	if sid != "" {
		return sid
	}
	return fallback
}

// --- Mode 2: partial evaluation (emit a filter for list/query paths) ---
// No concrete resource: given an action and the requesting tenant, reduce the
// policy set to the allow/deny resource patterns (+ conditions) that survive
// for this principal.
type ResourceMatch struct {
	Pattern    crn.Pattern
	Conditions policy.Conditions
}

type Constraints struct {
	Allow []ResourceMatch
	Deny  []ResourceMatch // must be subtracted by the adapter (deny-wins)
}

// Filter returns constraints keeping only the resource matches for which
// keep reports true. keep is a test the caller supplies, run once per match;
// Allow and Deny are filtered the same way, their order is preserved, and
// neither input slice is reused. For example, drop matches for a different
// service before handing constraints to that table's adapter:
//
//	dbConstraints := cons.Filter(func(m ResourceMatch) bool {
//		return m.Pattern.Service() == "file"
//	})
func (c Constraints) Filter(keep func(ResourceMatch) bool) Constraints {
	return Constraints{
		Allow: filterResourceMatches(c.Allow, keep),
		Deny:  filterResourceMatches(c.Deny, keep),
	}
}

func filterResourceMatches(matches []ResourceMatch, keep func(ResourceMatch) bool) []ResourceMatch {
	var filtered []ResourceMatch
	for _, match := range matches {
		if keep(match) {
			filtered = append(filtered, match)
		}
	}
	return filtered
}

// Constrain is the pure-function entry point. On a compile error it fails closed
// (returns empty constraints, i.e. no allow patterns → the adapter grants
// nothing). Use Compile + Compiled.Constrain to surface errors explicitly.
func Constrain(policies []policy.Policy, action, tenant string, context map[string]string) Constraints {
	c, err := Compile(policies)
	if err != nil {
		return Constraints{}
	}
	return c.Constrain(action, tenant, context)
}

// Constrain collects the allow/deny resource patterns whose action matches, for
// the adapter to turn into a storage filter. Only explicit allow/deny effects
// contribute; any other effect is ignored (fail-closed).
//
// tenant is the tenant the list/query runs in — the same fact Decide reads from
// Request.Resource. Patterns are matched against it exactly as Decide would:
// a pattern naming another tenant is dropped, and the platform placeholder
// (crn.PlatformTenant) is resolved to this tenant, so adapters only ever see
// concrete tenants and never interpret policy.
//
// context supplies the principal/request attributes known at list time.
// Conditions keyed on those attributes are resolved immediately: a statement
// whose context-only condition fails is dropped (it does not apply to this
// principal). Conditions keyed on attributes not in context are resource
// attributes and stay attached to the pattern for the adapter to enforce.
func (c Compiled) Constrain(action, tenant string, context map[string]string) Constraints {
	var out Constraints
	for _, s := range c.statements {
		if !actionMatches(s.actions, action) {
			continue
		}
		residual, ok := resolveConditions(s.conditions, context)
		if !ok {
			continue // a context-only condition failed → statement doesn't apply
		}
		for _, pat := range s.patterns {
			switch pat.Tenant() {
			case tenant: // the pattern's own tenant
			case crn.PlatformTenant: // placeholder → the requesting tenant
				pat = pat.WithTenant(tenant)
			default:
				continue // another tenant: can never match this request
			}
			rm := ResourceMatch{Pattern: pat, Conditions: residual}
			switch s.effect {
			case policy.Deny:
				out.Deny = append(out.Deny, rm)
			case policy.Allow:
				out.Allow = append(out.Allow, rm)
			}
		}
	}
	return out
}
