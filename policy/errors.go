package policy

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidEffect = errors.New("effect must be allow or deny")
	ErrNoActions     = errors.New("statement has no actions")
	ErrNoResources   = errors.New("statement has no resources")
	ErrEmptyAction   = errors.New("empty action")
	ErrEmptyResource = errors.New("empty resource")
)

// ParseError describes why a policy document failed validation. It wraps a
// sentinel Kind (see the Err* vars above) so callers can classify with
// errors.Is, while the message adds the field, the offending value, and which
// statement was at fault.
type ParseError struct {
	Kind      error  // sentinel kind (errors.Is target)
	Field     string // logical field name: "effect", "actions", "resources"
	Value     string // the offending value, when meaningful
	Statement string // statement locator, e.g. `statement 0 ("sid")`
}

func (e *ParseError) Error() string {
	msg := "policy: " + e.Kind.Error()
	if e.Field != "" {
		msg += fmt.Sprintf(": field %q", e.Field)
		if e.Value != "" {
			msg += fmt.Sprintf(" = %q", e.Value)
		}
	}
	if e.Statement != "" {
		msg += " in " + e.Statement
	}
	return msg
}

// Unwrap exposes the sentinel kind so errors.Is(err, ErrInvalidEffect) etc. works.
func (e *ParseError) Unwrap() error { return e.Kind }
