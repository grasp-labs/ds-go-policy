package pathfilter_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/adapter/pathfilter"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

const tenant = "ba62a53f-afa9-427d-9d91-c7987bc5662e"

func pattern(t *testing.T, resource string) crn.Pattern {
	t.Helper()
	p, err := crn.ParsePattern(fmt.Sprintf("crn:%s:*:file::file:%s", tenant, resource))
	if err != nil {
		t.Fatalf("ParsePattern(%q): %v", resource, err)
	}
	return p
}

func TestPrefixes_FromConstrain(t *testing.T) {
	// Drive the adapter from a real policy through engine.Constrain.
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "read", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources: []string{
					fmt.Sprintf("crn:%s:*:file::file:datalake/**", tenant),
					fmt.Sprintf("crn:%s:*:file::file:public/**", tenant),
				}},
			{Sid: "protect", Effect: policy.Deny, Actions: []string{"*"},
				Resources: []string{fmt.Sprintf("crn:%s:*:file::file:datalake/secret/**", tenant)}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)

	allow, deny, err := pathfilter.Prefixes(c)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if !reflect.DeepEqual(allow, []string{"datalake/**", "public/**"}) { // sorted, deduped
		t.Errorf("allow = %#v", allow)
	}
	if !reflect.DeepEqual(deny, []string{"datalake/secret/**"}) {
		t.Errorf("deny = %#v", deny)
	}
}

// End-to-end: a context-only condition (department) is resolved by Constrain,
// leaving a clean pattern the path filter can consume.
func TestPrefixes_ContextOnlyConditionResolved(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "team", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:datalake/**", tenant)},
				Conditions: policy.Conditions{"StringEquals": {"department": {"engineering"}}}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant,
		map[string]string{"department": "engineering"})

	allow, _, err := pathfilter.Prefixes(c)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if !reflect.DeepEqual(allow, []string{"datalake/**"}) {
		t.Errorf("allow = %#v", allow)
	}
}

// End-to-end for a path partition: a resource.path[N] condition defers through
// Constrain and is folded into the globs — one pinned glob per allowed value,
// on the allow and the deny side alike.
func TestPrefixes_PathSegmentCondition(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "inbound-by-org", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:files/inbound/**", tenant)},
				Conditions: policy.Conditions{"StringEquals": {"resource.path[2]": {"123456789", "23456788"}}}},
			{Sid: "blocked-org", Effect: policy.Deny, Actions: []string{"*"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:files/inbound/**", tenant)},
				Conditions: policy.Conditions{"StringEquals": {"resource.path[2]": {"987654321"}}}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)

	allow, deny, err := pathfilter.Prefixes(c)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if want := []string{"files/inbound/123456789/**", "files/inbound/23456788/**"}; !reflect.DeepEqual(allow, want) {
		t.Errorf("allow = %#v, want %#v", allow, want)
	}
	if want := []string{"files/inbound/987654321/**"}; !reflect.DeepEqual(deny, want) {
		t.Errorf("deny = %#v, want %#v", deny, want)
	}
}

// Pinning replaces a single-segment "*" in place.
func TestPrefixes_PathSegmentPinsSingleWildcard(t *testing.T) {
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "files/inbound/*/reports/**"),
		Conditions: policy.Conditions{"StringEquals": {"resource.path[2]": {"123456789"}}},
	}}}
	allow, _, err := pathfilter.Prefixes(c)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if want := []string{"files/inbound/123456789/reports/**"}; !reflect.DeepEqual(allow, want) {
		t.Errorf("allow = %#v, want %#v", allow, want)
	}
}

// A literal segment already pins the value: the glob survives unchanged when
// the literal is in the allowed set, and disappears when it is not.
func TestPrefixes_PathSegmentLiteralIntersection(t *testing.T) {
	match := func(values ...string) engine.Constraints {
		return engine.Constraints{Allow: []engine.ResourceMatch{{
			Pattern:    pattern(t, "files/inbound/acme/**"),
			Conditions: policy.Conditions{"StringEquals": {"resource.path[2]": policy.Values(values)}},
		}}}
	}
	allow, _, err := pathfilter.Prefixes(match("acme", "other"))
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if want := []string{"files/inbound/acme/**"}; !reflect.DeepEqual(allow, want) {
		t.Errorf("literal in set: allow = %#v, want %#v", allow, want)
	}
	allow, _, err = pathfilter.Prefixes(match("other"))
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if allow != nil {
		t.Errorf("literal not in set: allow = %#v, want none", allow)
	}
}

// An index that falls inside a trailing "**" is padded out with "*" segments.
func TestPrefixes_PathSegmentInsideDeepWildcard(t *testing.T) {
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "files/**"),
		Conditions: policy.Conditions{"StringEquals": {"resource.path[2]": {"123456789"}}},
	}}}
	allow, _, err := pathfilter.Prefixes(c)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if want := []string{"files/*/123456789/**"}; !reflect.DeepEqual(allow, want) {
		t.Errorf("allow = %#v, want %#v", allow, want)
	}
}

// A condition on a segment the pattern can never reach cannot hold: the match
// contributes nothing (fail closed, not an error).
func TestPrefixes_PathSegmentOutOfRange(t *testing.T) {
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "files/inbound"),
		Conditions: policy.Conditions{"StringEquals": {"resource.path[3]": {"x"}}},
	}}}
	allow, _, err := pathfilter.Prefixes(c)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if allow != nil {
		t.Errorf("allow = %#v, want none", allow)
	}
}

// Values that can never equal one path segment are dropped; the rest pin.
func TestPrefixes_PathSegmentValueWithSlashDropped(t *testing.T) {
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "files/**"),
		Conditions: policy.Conditions{"StringEquals": {"resource.path[1]": {"a/b", "ok"}}},
	}}}
	allow, _, err := pathfilter.Prefixes(c)
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if want := []string{"files/ok/**"}; !reflect.DeepEqual(allow, want) {
		t.Errorf("allow = %#v, want %#v", allow, want)
	}
}

// Everything the glob syntax cannot express exactly fails closed.
func TestPrefixes_PathSegmentUnsupported(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		conds   policy.Conditions
	}{
		{"non-equals operator", "files/**",
			policy.Conditions{"StringNotEquals": {"resource.path[2]": {"a"}}}},
		{"IfExists suffix", "files/**",
			policy.Conditions{"StringEqualsIfExists": {"resource.path[2]": {"a"}}}},
		{"segments after deep wildcard", "files/**/logs",
			policy.Conditions{"StringEquals": {"resource.path[2]": {"a"}}}},
		{"wildcard in value", "files/**",
			policy.Conditions{"StringEquals": {"resource.path[1]": {"12*"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := engine.Constraints{Allow: []engine.ResourceMatch{{
				Pattern:    pattern(t, tc.pattern),
				Conditions: tc.conds,
			}}}
			if _, _, err := pathfilter.Prefixes(c); !errors.Is(err, pathfilter.ErrUnsupportedCondition) {
				t.Errorf("err = %v, want ErrUnsupportedCondition", err)
			}
		})
	}
}

// End-to-end: a resource-attribute condition (status) is not in context, so it
// is deferred and the path adapter (which cannot express it) rejects it.
func TestPrefixes_DeferredConditionRejected(t *testing.T) {
	pol := policy.Policy{
		Statements: []policy.Statement{
			{Sid: "reports", Effect: policy.Allow, Actions: []string{"file:listFiles"},
				Resources:  []string{fmt.Sprintf("crn:%s:*:file::file:reports/**", tenant)},
				Conditions: policy.Conditions{"StringEquals": {"status": {"active"}}}},
		},
	}
	c := engine.Constrain([]policy.Policy{pol}, "file:listFiles", tenant, nil)
	if _, _, err := pathfilter.Prefixes(c); !errors.Is(err, pathfilter.ErrUnsupportedCondition) {
		t.Errorf("err = %v, want ErrUnsupportedCondition", err)
	}
}

func TestPrefixes_ConditionsRejected(t *testing.T) {
	c := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern:    pattern(t, "datalake/**"),
		Conditions: policy.Conditions{"Bool": {"mfa": {"true"}}},
	}}}
	if _, _, err := pathfilter.Prefixes(c); !errors.Is(err, pathfilter.ErrUnsupportedCondition) {
		t.Errorf("err = %v, want ErrUnsupportedCondition", err)
	}
}
