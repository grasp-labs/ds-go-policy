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
