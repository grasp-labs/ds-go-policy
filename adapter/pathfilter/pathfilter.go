// Package pathfilter turns engine.Constraints into allow/deny path globs for
// filesystem walkers and object-store prefixing. The globs use the CRN resource
// syntax: "*" matches one path segment, "**" matches zero or more. The caller
// must subtract the deny globs from the allow globs (deny-wins).
//
// The only residual conditions this adapter can express are StringEquals over
// the reserved resource.path[N] segment keys: those are folded into the globs
// by pinning segment N to each allowed value (one glob per value). Any other
// residual condition fails closed with ErrUnsupportedCondition.
package pathfilter

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/grasp-labs/ds-go-policy/conditionoperator"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
)

// ErrUnsupportedCondition is returned when a match carries residual conditions
// this adapter cannot fold into a glob. Only StringEquals over resource.path[N]
// keys is supported; everything else must be enforced by the caller.
var ErrUnsupportedCondition = errors.New("pathfilter: unsupported condition")

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
		expanded, err := expand(rm)
		if err != nil {
			return nil, err
		}
		for _, g := range expanded {
			if !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// expand turns one match into zero or more globs, folding any resource.path[N]
// StringEquals conditions into the pattern. A condition that can never hold
// (e.g. an index the pattern cannot reach) yields no globs — narrower than the
// pattern, never wider. Conditions the glob syntax cannot express exactly
// return ErrUnsupportedCondition.
func expand(rm engine.ResourceMatch) ([]string, error) {
	out := []string{rm.Pattern.Resource()}
	for op, keyVals := range rm.Conditions {
		if op != conditionoperator.StringEquals {
			return nil, fmt.Errorf("%w: operator %q", ErrUnsupportedCondition, op)
		}
		for key, values := range keyVals {
			n, ok := engine.ResourcePathKey(key)
			if !ok {
				return nil, fmt.Errorf("%w: key %q", ErrUnsupportedCondition, key)
			}
			var next []string
			for _, g := range out {
				pinned, err := pin(g, n, values)
				if err != nil {
					return nil, err
				}
				next = append(next, pinned...)
			}
			out = next
		}
	}
	return out, nil
}

// pin restricts segment n of a glob to the given values, returning the exact
// equivalent globs (typically one per value). Semantics mirror evaluation: a
// path matches pin(g, n, vs) iff it matches g AND its segment n is in vs.
func pin(glob string, n int, values []string) ([]string, error) {
	for _, v := range values {
		// A pinned value becomes a glob segment, so wildcard tokens in it
		// would silently widen the filter. No exact encoding exists: reject.
		if strings.Contains(v, "*") {
			return nil, fmt.Errorf("%w: value %q contains a wildcard", ErrUnsupportedCondition, v)
		}
	}
	seg := strings.Split(glob, "/")
	deep := slices.Index(seg, crn.DeepWildcard)

	// Fixed-width case: segment n sits before any "**" (or there is none), so
	// glob index n and path index n coincide.
	if deep == -1 || n < deep {
		if n >= len(seg) {
			return nil, nil // the pattern has no segment n: condition never holds
		}
		if seg[n] != crn.Wildcard {
			// Literal segment: the glob already pins it, so it survives
			// unchanged iff the literal is one of the allowed values.
			if slices.Contains(values, seg[n]) {
				return []string{glob}, nil
			}
			return nil, nil
		}
		var out []string
		for _, v := range values {
			if strings.Contains(v, "/") {
				continue // can never equal a single segment
			}
			pinned := slices.Clone(seg)
			pinned[n] = v
			out = append(out, strings.Join(pinned, "/"))
		}
		return out, nil
	}

	// Segment n falls inside a "**". Only a trailing "**" keeps the index
	// unambiguous: pad with single-segment wildcards up to n, pin the value,
	// and keep matching everything below.
	if deep != len(seg)-1 {
		return nil, fmt.Errorf("%w: %q has segments after %q", ErrUnsupportedCondition, glob, crn.DeepWildcard)
	}
	var out []string
	for _, v := range values {
		if strings.Contains(v, "/") {
			continue // can never equal a single segment
		}
		pinned := slices.Clone(seg[:deep])
		for i := deep; i < n; i++ {
			pinned = append(pinned, crn.Wildcard)
		}
		pinned = append(pinned, v, crn.DeepWildcard)
		out = append(out, strings.Join(pinned, "/"))
	}
	return out, nil
}
