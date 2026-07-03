package engine

import (
	"errors"
	"fmt"
)

var (
	ErrTenantMismatch    = errors.New("tenant mismatch")
	ErrInvalidPattern    = errors.New("invalid CRN pattern")
	ErrInvalidConditions = errors.New("invalid conditions")
	ErrInvalidPolicy     = errors.New("invalid policy")
)

// ParseError describes why a policy failed to compile. It wraps a sentinel Kind
// (see the Err* vars above) so callers can classify with errors.Is, while the
// message adds detail: the logical field, the offending value, an optional
// explanation, and the original input. When the failure originates in a lower
// layer (a crn parse error, an unknown condition operator), that error is kept
// in Cause so errors.Is also reaches it.
type ParseError struct {
	Kind   error  // sentinel kind (errors.Is target)
	Field  string // logical field name: "tenant", "resource", "conditions", ...
	Value  string // the offending value
	Detail string // optional human explanation
	Input  string // the string being compiled, when available
	Cause  error  // underlying error, when wrapping a lower layer (optional)
}

func (e *ParseError) Error() string {
	msg := "engine: " + e.Kind.Error()
	if e.Field != "" {
		msg += fmt.Sprintf(": field %q", e.Field)
		if e.Value != "" {
			msg += fmt.Sprintf(" = %q", e.Value)
		}
	} else if e.Value != "" {
		msg += fmt.Sprintf(": %q", e.Value)
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	if e.Input != "" {
		msg += fmt.Sprintf(" (input %q)", e.Input)
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
