package engine

import (
	"strings"
	"unicode"
)

const actionWildcard = "*"

// ValidActionPattern reports whether value has supported policy-action syntax:
// "{service}:{operation}", "{service}:*", or "*". Parts must be non-empty and
// contain no whitespace; wildcards are valid only in the two wildcard forms.
func ValidActionPattern(value string) bool {
	if value == actionWildcard {
		return true
	}
	service, operation, ok := splitAction(value)
	return ok && !strings.Contains(service, actionWildcard) &&
		(operation == actionWildcard || !strings.Contains(operation, actionWildcard))
}

// isConcreteAction reports whether value is a concrete "{service}:{operation}"
// with no wildcard in either part.
func isConcreteAction(value string) bool {
	service, operation, ok := splitAction(value)
	return ok && !strings.Contains(service, actionWildcard) &&
		!strings.Contains(operation, actionWildcard)
}

// splitAction splits "{service}:{operation}" on its single colon. It reports
// ok only when there is exactly one colon, no whitespace, and both parts are
// non-empty.
func splitAction(value string) (service, operation string, ok bool) {
	if strings.Count(value, ":") != 1 || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return "", "", false
	}
	service, operation, _ = strings.Cut(value, ":")
	if service == "" || operation == "" {
		return "", "", false
	}
	return service, operation, true
}
