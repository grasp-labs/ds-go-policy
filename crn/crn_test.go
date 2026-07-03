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
		{"bad uuid", fmt.Sprintf("crn:%s:%s:file::file:x", "not-a-uuid", scope), ErrInvalidUUID},
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
	if _, err := Build("not-a-uuid", scope, "file", "", "file", "x"); !errors.Is(err, ErrInvalidUUID) {
		t.Errorf("Build with bad uuid err = %v, want %v", err, ErrInvalidUUID)
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
			if got := p.Matches(c); got != test.want {
				t.Errorf("Matches(%q -> %q) = %v, want %v", test.pattern, test.resource, got, test.want)
			}
		})
	}
}

func TestParseErrorDetail(t *testing.T) {
	input := fmt.Sprintf("crn:%s:%s:file::file:%s", "not-a-uuid", scope, "x")
	_, err := Parse(input)

	// Classifiable via the sentinel kind.
	if !errors.Is(err, ErrInvalidUUID) {
		t.Fatalf("errors.Is(ErrInvalidUUID) = false; err = %v", err)
	}

	// Carries structured, AWS-style detail.
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("errors.As(*ParseError) = false; err = %v", err)
	}
	if pe.Field != "tenant" || pe.Value != "not-a-uuid" || pe.Input != input {
		t.Errorf("ParseError detail = %+v, want field=tenant value=not-a-uuid input=%q", pe, input)
	}
}

func TestMatchesTenantIsolation(t *testing.T) {
	p, err := ParsePattern(fmt.Sprintf("crn:%s:*:*::*:**", tenant))
	if err != nil {
		t.Fatalf("ParsePattern error: %v", err)
	}
	other := CRN{Tenant: scope, Scope: scope, Service: "file", Type: "file", Resource: "datalake"}
	if p.Matches(other) {
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
