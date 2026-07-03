// Package pathfilter turns engine.Constraints into allow/deny path globs for
// filesystem walkers and object-store prefixing. The globs use the CRN resource
// syntax: "*" matches one path segment, "**" matches zero or more. The caller
// must subtract the deny globs from the allow globs (deny-wins).
package pathfilter

import (
	"errors"
	"sort"

	"github.com/grasp-labs/ds-go/policy/engine"
)

// ErrUnsupportedCondition is returned when a match carries conditions. This
// adapter derives path globs only; conditions must be resolved by the caller.
var ErrUnsupportedCondition = errors.New("pathfilter: conditions are not supported")

// Prefixes returns the deduplicated, sorted allow and deny resource-path globs.
func Prefixes(c engine.Constraints) (allow, deny []string, err error) {
	if allow, err = globs(c.Allow); err != nil {
		return nil, nil, err
	}
	if deny, err = globs(c.Deny); err != nil {
		return nil, nil, err
	}
	return allow, deny, nil
}

func globs(matches []engine.ResourceMatch) ([]string, error) {
	seen := make(map[string]bool, len(matches))
	var out []string
	for _, rm := range matches {
		if len(rm.Conditions) > 0 {
			return nil, ErrUnsupportedCondition
		}
		g := rm.Pattern.Resource()
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out, nil
}
