package crn

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// PlatformTenant is the reserved token accepted in the tenant field. In a
// concrete CRN it names a platform-owned resource; in a Pattern it stands for
// the requesting tenant and matches resources of any tenant, which is what
// lets a single platform-issued policy apply to every tenant. The engine
// evaluates whatever documents it is given — restricting who may author
// patterns under this token is the responsibility of the policy management
// plane that issues and binds policies.
const PlatformTenant = "aic"

// CRN is a resource identity
type CRN struct {
	Tenant  string
	Scope   string
	Service string
	// empty when region-agnostic
	Region   string
	Type     string
	Resource string
}

// Parse parses a CRN from a string.
func Parse(s string) (CRN, error) {
	// SplitN with limit 7 keeps any ":" in the resource (S3-style keys may
	// contain colons); the first five fields are guaranteed colon-free.
	parts := strings.SplitN(s, ":", 7)
	if len(parts) != 7 {
		return CRN{}, &ParseError{
			Kind:   ErrInvalidPartCount,
			Detail: fmt.Sprintf("expected 7 colon-separated parts, got %d", len(parts)),
			Input:  s,
		}
	}
	if parts[0] != "crn" {
		return CRN{}, &ParseError{
			Kind:   ErrInvalidPrefix,
			Field:  "prefix",
			Value:  parts[0],
			Detail: `expected "crn"`,
			Input:  s,
		}
	}
	tenant, err := normalizeTenant(parts[1])
	if err != nil {
		return CRN{}, &ParseError{Kind: ErrInvalidTenant, Field: "tenant", Value: parts[1], Input: s}
	}

	res := parts[6]
	if strings.HasPrefix(res, "/") {
		return CRN{}, &ParseError{Kind: ErrLeadingSlash, Field: "resource", Value: res, Input: s}
	}

	if strings.HasSuffix(res, "/") {
		return CRN{}, &ParseError{Kind: ErrTrailingSlash, Field: "resource", Value: res, Input: s}
	}
	return CRN{
		Tenant:   tenant,
		Scope:    parts[2],
		Service:  parts[3],
		Region:   parts[4],
		Type:     parts[5],
		Resource: res,
	}, nil
}

// normalizeTenant validates the tenant field: a UUID (canonicalized) or the
// reserved PlatformTenant token. Anything else is rejected — the tenant is the
// isolation boundary and must never be a free-form string or a wildcard.
func normalizeTenant(tenant string) (string, error) {
	if tenant == PlatformTenant {
		return tenant, nil
	}
	id, err := uuid.Parse(tenant)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (c CRN) String() string {
	return fmt.Sprintf("crn:%s:%s:%s:%s:%s:%s", c.Tenant, c.Scope, c.Service, c.Region, c.Type, c.Resource)
}

// Build assembles a canonical CRN. The resource is normalized to S3-style form
// (leading and trailing "/" stripped). Because ":" is the CRN delimiter, the
// flat fields must not contain it; the resource may (it is the final field).
func Build(tenant, scope, service, region, typ, resource string) (CRN, error) {
	normalized, err := normalizeTenant(tenant)
	if err != nil {
		return CRN{}, &ParseError{Kind: ErrInvalidTenant, Field: "tenant", Value: tenant}
	}
	for _, f := range []struct{ name, val string }{
		{"scope", scope}, {"service", service}, {"region", region}, {"type", typ},
	} {
		if strings.Contains(f.val, ":") {
			return CRN{}, &ParseError{
				Kind:   ErrInvalidField,
				Field:  f.name,
				Value:  f.val,
				Detail: `":" is the CRN delimiter and is only allowed in the resource`,
			}
		}
	}
	resource = strings.Trim(resource, "/")
	return CRN{
		Tenant:   normalized,
		Scope:    scope,
		Service:  service,
		Region:   region,
		Type:     typ,
		Resource: resource,
	}, nil
}

// Wildcard tokens usable in a Pattern.
const (
	Wildcard     = "*"  // matches a single segment
	DeepWildcard = "**" // matches zero or more path segments (resource only)
)

// Pattern is a CRN that may contain * (single segment) and ** (recursive, path-addressed).
// Tenant is never a wildcard — it is a concrete UUID (tenant isolation) or the
// reserved PlatformTenant token, which stands for the requesting tenant in
// platform-issued policies.
type Pattern struct {
	crn CRN // Scope/Service/Region/Type may be "*"; Resource may contain "*" and "**"
}

// Field accessors expose the (possibly wildcarded) pattern segments so adapters
// can translate a Pattern into a storage filter. Tenant is a concrete UUID or
// the reserved PlatformTenant token.
func (p Pattern) Tenant() string   { return p.crn.Tenant }
func (p Pattern) Scope() string    { return p.crn.Scope }
func (p Pattern) Service() string  { return p.crn.Service }
func (p Pattern) Region() string   { return p.crn.Region }
func (p Pattern) Type() string     { return p.crn.Type }
func (p Pattern) Resource() string { return p.crn.Resource }

// String renders the pattern in canonical CRN form.
func (p Pattern) String() string { return p.crn.String() }

// WithTenant returns a copy of the pattern with its tenant replaced. The engine
// uses it to resolve the PlatformTenant placeholder to the requesting tenant
// when emitting constraints, so adapters only ever see concrete tenants.
func (p Pattern) WithTenant(tenant string) Pattern {
	p.crn.Tenant = tenant
	return p
}

func ParsePattern(s string) (Pattern, error) {
	c, err := Parse(s) // structural + "crn" prefix + tenant validation, reused
	if err != nil {
		return Pattern{}, err
	}
	// "**" is path-only; the flat fields may only be a literal or "*"
	for _, f := range []struct{ name, val string }{
		{"scope", c.Scope}, {"service", c.Service}, {"region", c.Region}, {"type", c.Type},
	} {
		if strings.Contains(f.val, "**") {
			return Pattern{}, &ParseError{
				Kind:   ErrInvalidPattern,
				Field:  f.name,
				Value:  f.val,
				Detail: `"**" is only valid in the resource path`,
				Input:  s,
			}
		}
	}
	return Pattern{crn: c}, nil
}

func (p Pattern) Matches(c CRN) bool {
	return matchTenant(p.crn.Tenant, c.Tenant) &&
		matchField(p.crn.Scope, c.Scope) &&
		matchField(p.crn.Service, c.Service) &&
		matchField(p.crn.Region, c.Region) &&
		matchField(p.crn.Type, c.Type) &&
		matchPath(strings.Split(p.crn.Resource, "/"), strings.Split(c.Resource, "/"))
}

// matchTenant: exact match, except the reserved platform tenant in a pattern,
// which applies to resources of every tenant (platform-issued policies). "*"
// is never valid here — a concrete tenant pattern only matches its own tenant.
func matchTenant(pat, val string) bool {
	return pat == val || pat == PlatformTenant
}

// matchField: "*" matches any single field value (including ""), else exact.
func matchField(pat, val string) bool {
	return pat == "*" || pat == val
}

// matchPath: linear wildcard match over path segments.
//
//	"*"  matches exactly one segment
//	"**" matches zero or more segments
//
// Parameters
// - pat: pat []string — the pattern path segments (may contain the wildcard tokens * and **). E.g. resource "projectx/*/config" → ["projectx", "*", "config"].
// - seg []string — the concrete resource path segments (literal, no wildcards). E.g. "projectx/db/config" → ["projectx", "db", "config"].
//
// Pat is as such the pattern saved to the policy engine, while seg is the actual resource path.
// Returns: true if the segment matches the pattern
func matchPath(pat, seg []string) bool {
	px, sx := 0, 0
	starPx, starSx := -1, -1
	for sx < len(seg) {
		switch {
		case px < len(pat) && (pat[px] == "*" || pat[px] == seg[sx]):
			px, sx = px+1, sx+1
		case px < len(pat) && pat[px] == "**":
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
	for px < len(pat) && pat[px] == "**" {
		px++
	}
	return px == len(pat)
}
