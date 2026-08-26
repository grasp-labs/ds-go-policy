package engine

import (
	"strings"
	"unicode"
)

const actionWildcard = "*"

type parsedAction struct {
	service   string
	operation string
}

// ValidActionPattern reports whether value has supported policy-action syntax:
// "{service}:{operation}", "{service}:*", or "*". Parts must be non-empty and
// contain no whitespace; wildcards are valid only in the two wildcard forms.
func ValidActionPattern(value string) bool {
	_, ok := parseActionPattern(value)
	return ok
}

func parseConcreteAction(value string) (parsedAction, bool) {
	action, ok := splitAction(value)
	if !ok || strings.Contains(action.service, actionWildcard) ||
		strings.Contains(action.operation, actionWildcard) {
		return parsedAction{}, false
	}
	return action, true
}

func parseActionPattern(value string) (parsedAction, bool) {
	if value == actionWildcard {
		return parsedAction{service: actionWildcard, operation: actionWildcard}, true
	}

	pattern, ok := splitAction(value)
	if !ok || strings.Contains(pattern.service, actionWildcard) ||
		(pattern.operation != actionWildcard && strings.Contains(pattern.operation, actionWildcard)) {
		return parsedAction{}, false
	}
	return pattern, true
}

func splitAction(value string) (parsedAction, bool) {
	if strings.Count(value, ":") != 1 || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return parsedAction{}, false
	}
	service, operation, _ := strings.Cut(value, ":")
	if service == "" || operation == "" {
		return parsedAction{}, false
	}
	return parsedAction{service: service, operation: operation}, true
}
