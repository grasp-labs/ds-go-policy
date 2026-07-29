package engine

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidPattern    = errors.New("invalid CRN pattern")
	ErrInvalidConditions = errors.New("invalid conditions")
	ErrInvalidPolicy     = errors.New("invalid policy")
)

// ParseError describes why a policy failed to compile. It wraps a sentinel Kind
// (see the Err* vars above) so callers can classify with errors.Is, while the
// message adds the logical field and the offending value. The failure always
// originates in a lower layer (a crn parse error, an unknown condition
// operator, a policy validation error); that error is kept in Cause so
// errors.Is also reaches it.
type ParseError struct {
	Kind  error  // sentinel kind (errors.Is target)
	Field string // logical field name: "policy", "resource", "conditions"
	Value string // the offending value
	Cause error  // underlying error from policy or crn
}

func (e *ParseError) Error() string {
	msg := "engine: " + e.Kind.Error()
	if e.Field != "" {
		msg += fmt.Sprintf(": field %q", e.Field)
		if e.Value != "" {
			msg += fmt.Sprintf(" = %q", e.Value)
		}
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap exposes both the sentinel Kind and the underlying Cause so errors.Is
// matches the engine's own classification (e.g. ErrInvalidPattern) and the
// wrapped cause (e.g. crn.ErrInvalidPartCount, ErrUnknownOperator).
func (e *ParseError) Unwrap() []error {
	if e.Cause == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Cause}
}
