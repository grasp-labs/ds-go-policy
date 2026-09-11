package crn

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	tenant = "ba62a53f-afa9-427d-9d91-c7987bc5662e"
	scope  = "d0498be0-aae2-41c1-9f02-a2d8d9548360"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		want  CRN
	}{
		{
			input: fmt.Sprintf("crn:%s:%s:%s:%s:%s:%s", tenant, scope, "file", "", "file", "datalake"),
			want:  CRN{Tenant: tenant, Scope: scope, Service: "file", Region: "", Type: "file", Resource: "datalake"},
		},
		{
			// resource keeps its colons (S3-style keys) via SplitN
			input: fmt.Sprintf("crn:%s:%s:%s:%s:%s:%s", tenant, scope, "file", "", "file", "logs/2026:07:02/report"),
			want:  CRN{Tenant: tenant, Scope: scope, Service: "file", Region: "", Type: "file", Resource: "logs/2026:07:02/report"},
		},
	}

	for _, test := range tests {
		got, err := Parse(test.input)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", test.input, err)
			continue
		}
		if got != test.want {
			t.Errorf("Parse(%q) = %v, want %v", test.input, got, test.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"too few parts", "crn:" + tenant + ":file", ErrInvalidPartCount},
		{"bad prefix", fmt.Sprintf("arn:%s:%s:file::file:x", tenant, scope), ErrInvalidPrefix},
		{"bad tenant", fmt.Sprintf("crn:%s:%s:file::file:x", "not-a-uuid", scope), ErrInvalidTenant},
		{"leading slash", fmt.Sprintf("crn:%s:%s:file::file:%s", tenant, scope, "/datalake"), ErrLeadingSlash},
		{"trailing slash", fmt.Sprintf("crn:%s:%s:file::file:%s", tenant, scope, "datalake/"), ErrTrailingSlash},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.input)
			if !errors.Is(err, test.want) {
				t.Errorf("Parse(%q) err = %v, want %v", test.input, err, test.want)
			}
		})
	}
}

func TestBuild(t *testing.T) {
	c, err := Build(tenant, scope, "file", "", "file", "/datalake/raw/")
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}
	if c.Resource != "datalake/raw" {
		t.Errorf("Build resource = %q, want %q", c.Resource, "datalake/raw")
	}

	if _, err := Build(tenant, "a:b", "file", "", "file", "x"); !errors.Is(err, ErrInvalidField) {
		t.Errorf("Build with colon in scope err = %v, want %v", err, ErrInvalidField)
	}
	_, err = Build("not-a-uuid", scope, "file", "", "file", "x")
	if !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("Build with bad tenant err = %v, want %v", err, ErrInvalidTenant)
	}
	// The error must carry the offending tenant value, not an empty string.
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Value != "not-a-uuid" {
		t.Errorf("Build error detail = %+v, want Value=%q", pe, "not-a-uuid")
	}
}

func TestRoundTrip(t *testing.T) {
	inputs := []string{
		fmt.Sprintf("crn:%s:%s:file::file:datalake", tenant, scope),
		fmt.Sprintf("crn:%s:%s:file::file:logs/2026:07:02/report", tenant, scope),
	}
	for _, in := range inputs {
		c, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", in, err)
		}
		if got := c.String(); got != in {
			t.Errorf("round-trip = %q, want %q", got, in)
		}
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		resource string // concrete resource; other fields fixed
		scope    string // concrete scope
		want     bool
	}{
		{"exact", "datalake", "datalake", scope, true},
		{"scope wildcard", "datalake", "datalake", "other-scope", true}, // scope is "*" in pattern below
		{"recursive deep", "datalake/**", "datalake/raw/events", scope, true},
		{"recursive zero", "datalake/**", "datalake", scope, true},
		{"single one segment", "datalake/*", "datalake/raw", scope, true},
		{"single too deep", "datalake/*", "datalake/raw/events", scope, false},
		{"literal mismatch", "datalake", "other", scope, false},
		{"colon in key", "logs/2026:07:02/report", "logs/2026:07:02/report", scope, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patScope := scope
			if test.name == "scope wildcard" {
				patScope = "*"
			}
			p, err := ParsePattern(fmt.Sprintf("crn:%s:%s:file::file:%s", tenant, patScope, test.pattern))
			if err != nil {
				t.Fatalf("ParsePattern error: %v", err)
			}
			c := CRN{Tenant: tenant, Scope: test.scope, Service: "file", Region: "", Type: "file", Resource: test.resource}
			if got := p.Matches(c, tenant); got != test.want {
				t.Errorf("Matches(%q -> %q) = %v, want %v", test.pattern, test.resource, got, test.want)
			}
		})
	}
}

func TestParseErrorDetail(t *testing.T) {
	input := fmt.Sprintf("crn:%s:%s:file::file:%s", "not-a-uuid", scope, "x")
	_, err := Parse(input)

	// Classifiable via the sentinel kind.
	if !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("errors.Is(ErrInvalidTenant) = false; err = %v", err)
	}

	// Carries structured detail.
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("errors.As(*ParseError) = false; err = %v", err)
	}
	if pe.Field != "tenant" || pe.Value != "not-a-uuid" || pe.Input != input {
		t.Errorf("ParseError detail = %+v, want field=tenant value=not-a-uuid input=%q", pe, input)
	}
}

// The token stands for the caller, so it matches a resource whose tenant equals
// the requesting tenant and nothing else. A published row is not addressed here:
// it is owned by the platform tenant like any other row, and its readability is a
// marker on the row (see the sqlfilter adapter).
func TestMatchesPlatformTenant(t *testing.T) {
	p, err := ParsePattern(fmt.Sprintf("crn:%s:*:file::file:datalake/**", PlatformTenant))
	if err != nil {
		t.Fatalf("ParsePattern error: %v", err)
	}
	own := CRN{Tenant: tenant, Scope: scope, Service: "file", Type: "file", Resource: "datalake/raw"}
	if !p.Matches(own, tenant) {
		t.Errorf("the token did not match the caller's own resource")
	}
	// Any other tenant's resource must not match, whichever tenant is asking.
	foreign := CRN{Tenant: scope, Scope: scope, Service: "file", Type: "file", Resource: "datalake/raw"}
	if p.Matches(foreign, tenant) {
		t.Errorf("the token matched tenant %q's resource; want the caller's only", foreign.Tenant)
	}

	// A concrete-tenant pattern matches that tenant's resource and no other.
	tp, err := ParsePattern(fmt.Sprintf("crn:%s:*:file::file:**", tenant))
	if err != nil {
		t.Fatalf("ParsePattern error: %v", err)
	}
	if !tp.Matches(own, tenant) {
		t.Errorf("concrete pattern did not match its own tenant's resource")
	}
	if tp.Matches(foreign, tenant) {
		t.Errorf("concrete pattern matched another tenant's resource; want deny")
	}
}

// The token is pattern-only: a concrete CRN names a real resource identity, whose
// tenant is always a real tenant.
func TestPlatformTenantTokenScope(t *testing.T) {
	if _, err := ParsePattern(fmt.Sprintf("crn:%s:*:file::file:**", PlatformTenant)); err != nil {
		t.Errorf("ParsePattern(token) err = %v, want nil", err)
	}
	if _, err := Parse(fmt.Sprintf("crn:%s:%s:file::file:x", PlatformTenant, scope)); !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("Parse(token) err = %v, want ErrInvalidTenant", err)
	}
	if _, err := Build(PlatformTenant, scope, "file", "", "file", "x"); !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("Build(token) err = %v, want ErrInvalidTenant", err)
	}
	// Only the exact reserved token is accepted — no other non-UUID string, in a
	// pattern any more than in a concrete CRN.
	if _, err := ParsePattern(fmt.Sprintf("crn:%s:%s:file::file:x", "platform", scope)); !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("ParsePattern with unreserved token err = %v, want %v", err, ErrInvalidTenant)
	}
}

func TestMatchesTenantIsolation(t *testing.T) {
	p, err := ParsePattern(fmt.Sprintf("crn:%s:*:*::*:**", tenant))
	if err != nil {
		t.Fatalf("ParsePattern error: %v", err)
	}
	other := CRN{Tenant: scope, Scope: scope, Service: "file", Type: "file", Resource: "datalake"}
	if p.Matches(other, tenant) {
		t.Errorf("pattern matched across tenants; want deny")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pat  []string
		seg  []string
		want bool
	}{
		// Give access to a specific subset of a datalake, and the query matches that.
		{strings.Split("datalake/subset", "/"), strings.Split("datalake/subset", "/"), true},
		// Give access to entire datalake, but the query target files directory.
		{strings.Split("datalake/**", "/"), strings.Split("files", "/"), false},
		// Give access to all files and the query is a very particual file.
		{strings.Split("datalake/**", "/"), strings.Split("datalake/files/specific.txt", "/"), true},
	}

	for _, test := range tests {
		res := matchPath(test.pat, test.seg)
		if res != test.want {
			t.Errorf("matchPath(%v, %v) = %v, want %v", test.pat, test.seg, res, test.want)
		}
	}
}
