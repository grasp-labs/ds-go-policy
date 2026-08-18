package engine_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
)

func constraintMatch(t *testing.T, service, resource string) engine.ResourceMatch {
	t.Helper()
	pattern, err := crn.ParsePattern(fmt.Sprintf(
		"crn:%s:*:%s::resource:%s",
		constrainTenant,
		service,
		resource,
	))
	if err != nil {
		t.Fatalf("ParsePattern: %v", err)
	}
	return engine.ResourceMatch{Pattern: pattern}
}

func TestConstraintsFilter(t *testing.T) {
	fileAllow := constraintMatch(t, "file", "allow-file")
	inboundAllow := constraintMatch(t, "inbound", "allow-inbound")
	fileDeny := constraintMatch(t, "file", "deny-file")
	inboundDeny := constraintMatch(t, "inbound", "deny-inbound")
	constraints := engine.Constraints{
		Allow: []engine.ResourceMatch{fileAllow, inboundAllow},
		Deny:  []engine.ResourceMatch{inboundDeny, fileDeny},
	}

	filtered := constraints.Filter(func(match engine.ResourceMatch) bool {
		return match.Pattern.Service() == "inbound"
	})

	want := engine.Constraints{
		Allow: []engine.ResourceMatch{inboundAllow},
		Deny:  []engine.ResourceMatch{inboundDeny},
	}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf("Filter() = %+v, want %+v", filtered, want)
	}

	// The result owns its slices: changing it must not change the input.
	filtered.Allow[0] = engine.ResourceMatch{}
	filtered.Deny[0] = engine.ResourceMatch{}
	if !reflect.DeepEqual(constraints.Allow, []engine.ResourceMatch{fileAllow, inboundAllow}) {
		t.Errorf("Filter mutated or reused the input Allow slice: %+v", constraints.Allow)
	}
	if !reflect.DeepEqual(constraints.Deny, []engine.ResourceMatch{inboundDeny, fileDeny}) {
		t.Errorf("Filter mutated or reused the input Deny slice: %+v", constraints.Deny)
	}
}
