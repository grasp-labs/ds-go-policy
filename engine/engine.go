package engine

import (
	"slices"
	"strings"

	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/policy"
)

// Request context for a concrete operation.
type Request struct {
	Action   string // concrete "{service}:{operation}"
	Resource crn.CRN
	// Tenant is the requesting (caller's) tenant, taken from the verified claims.
	// It is what the PlatformTenant token resolves to, and it bounds every
	// pattern: a pattern naming any other tenant cannot match. It is distinct
	// from Resource.Tenant, the tenant owning the resource being acted on, and it
	// is required — an empty Tenant matches no resource.
	Tenant string
	// ResourcePublished reports that the resource carries the platform's published
	// marker, which the service reads off the row (see sqlfilter.Published). The
	// platform published it for every tenant, so an allow need not name it: this
	// widens an allow the caller already holds for the action, exactly as the
	// query filter ORs the marker onto an existing allow clause. It never widens a
	// deny and never creates a grant. Leave it false on write actions, so a
	// published row is writable only by the tenant that owns it.
	ResourcePublished bool
	Context           map[string]string // attributes the service supplies for conditions
}

type Decision struct {
	Allowed bool
	Reason  string // matched Sid or a fallback reason
}

// Compiled contains policies validated by Compile with pre-parsed resource
// patterns. Action slices are cloned; condition data must not be mutated after
// compilation.
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

// Compile validates policies and action patterns and pre-parses resource
// patterns. Validation errors are returned rather than silently skipped.
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
			cs, err := compileStatement(s)
			if err != nil {
				return Compiled{}, err
			}
			c.statements = append(c.statements, cs)
		}
	}
	return c, nil
}

func compileStatement(s policy.Statement) (compiledStatement, error) {
	if err := validateConditions(s.Conditions); err != nil {
		return compiledStatement{}, &ParseError{
			Kind:  ErrInvalidConditions,
			Field: "conditions",
			Value: s.Sid,
			Cause: err,
		}
	}

	cs := compiledStatement{
		sid:        s.Sid,
		effect:     s.Effect,
		actions:    slices.Clone(s.Actions),
		conditions: s.Conditions,
	}
	for _, value := range s.Actions {
		if !ValidActionPattern(value) {
			return compiledStatement{}, &ParseError{
				Kind:  ErrInvalidAction,
				Field: "action",
				Value: value,
			}
		}
	}
	for _, value := range s.Resources {
		pattern, err := crn.ParsePattern(value)
		if err != nil {
			return compiledStatement{}, &ParseError{
				Kind:  ErrInvalidPattern,
				Field: "resource",
				Value: value,
				Cause: err,
			}
		}
		cs.patterns = append(cs.patterns, pattern)
	}
	return cs, nil
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
// is allowed only if some statement explicitly allows it and none denies it. A
// malformed or wildcard request action is implicitly denied.
func (c Compiled) Decide(r Request) Decision {
	if !isConcreteAction(r.Action) {
		return Decision{Allowed: false, Reason: "implicit deny"}
	}

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
	if !actionMatches(s.actions, r.Action) {
		return false
	}
	if !evalConditions(s.conditions, r.Context, strings.Split(r.Resource.Resource, "/")) {
		return false
	}
	// A published resource is readable by every principal holding the action, so an
	// allow does not have to name it. The action check above still stands, so this
	// widens a grant and never creates one, and it deliberately does not apply to a
	// deny — the marker is all-or-nothing, and withholding published rows means
	// withholding the action.
	if r.ResourcePublished && s.effect == policy.Allow {
		return true
	}
	return s.matchesResource(r.Resource, r.Tenant)
}

// matchesResource reports whether any of the statement's patterns covers the
// requested resource.
//
// A pattern bound to a concrete tenant other than the requesting one is skipped
// before matching, the same rule Constrain applies when it reduces a policy to
// query constraints. Both paths therefore share one invariant: a policy can only
// ever reach resources of the tenant the request is made for. Without it a
// document naming another tenant would grant that tenant's resources to whoever
// held the document, so the check must not depend on which tenant the resource
// happens to belong to.
func (s compiledStatement) matchesResource(c crn.CRN, requestTenant string) bool {
	for _, pat := range s.patterns {
		if pat.Tenant() != crn.PlatformTenant && pat.Tenant() != requestTenant {
			continue
		}
		if pat.Matches(c, requestTenant) {
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
	Deny  []ResourceMatch // must be subtracted by the adapter or caller (deny-wins)
}

// Filter keeps matches for which keep returns true, applying keep to Allow and
// Deny. keep must reject only matches that cannot select resources in the target
// projection. Order is preserved and neither input slice is reused. For
// example, keep file and wildcard-service patterns:
//
//	fileConstraints := constraints.Filter(func(m ResourceMatch) bool {
//		service := m.Pattern.Service()
//		return service == "file" || service == crn.Wildcard
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

// Constrain compiles policies and derives constraints. Invalid policies or
// non-concrete actions return empty constraints. Use Compile and
// Compiled.Constrain to surface policy compilation errors.
func Constrain(policies []policy.Policy, action, tenant string, context map[string]string) Constraints {
	c, err := Compile(policies)
	if err != nil {
		return Constraints{}
	}
	return c.Constrain(action, tenant, context)
}

// Constrain collects the allow/deny resource patterns whose action matches, for
// the adapter to turn into a storage filter. The action must be concrete;
// malformed or wildcard actions produce no constraints. Action and resource
// service names are independent.
//
// tenant must be the trusted, concrete tenant UUID for the list/query. Patterns
// are matched against it exactly as Decide would: a PlatformTenant token is
// resolved to this tenant, and a concrete pattern naming another tenant is
// dropped. Adapters therefore only ever see a concrete tenant equal to this one,
// and never interpret policy.
//
// context supplies the principal/request attributes known at list time.
// Keys present in context are resolved immediately; a failing condition drops
// the statement. Keys absent from context stay attached as residual conditions
// for the adapter. Reserved resource.path[N] keys always remain residual, even
// if context contains a value with the same key.
func (c Compiled) Constrain(action, tenant string, context map[string]string) Constraints {
	var out Constraints
	if !isConcreteAction(action) {
		return out
	}
	for _, s := range c.statements {
		if !actionMatches(s.actions, action) {
			continue
		}
		residual, ok := resolveConditions(s.conditions, context)
		if !ok {
			continue
		}
		for _, pat := range s.patterns {
			switch pat.Tenant() {
			case tenant: // concrete UUID equal to the request tenant → keep
			case crn.PlatformTenant: // the token → resolve to the request tenant
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
