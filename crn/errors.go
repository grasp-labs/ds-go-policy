package crn

import (
	"errors"
	"fmt"
)

// Sentinel kinds. These classify a failure; match them with errors.Is. Detailed
// context (which field, the offending value, the input) is carried by ParseError,
// which wraps one of these.
var (
	ErrInvalidPartCount = errors.New("invalid part count")
	ErrInvalidPrefix    = errors.New("invalid prefix")
	ErrInvalidPattern   = errors.New("invalid CRN pattern")
	// ErrInvalidTenant: the tenant field must be a UUID or PlatformTenant.
	ErrInvalidTenant = errors.New("invalid tenant")
	ErrLeadingSlash  = errors.New("leading slash in resource")
	ErrTrailingSlash = errors.New("trailing slash in resource")
	ErrInvalidField  = errors.New("field contains delimiter")
)

// ParseError describes why a CRN string, pattern, or field was rejected. It
// wraps a sentinel kind (see the Err* vars) so callers can classify with
// errors.Is, while the message adds structured detail: the logical field, the
// offending value, an optional explanation, and the original input.
type ParseError struct {
	Kind   error  // sentinel kind (errors.Is target)
	Field  string // logical field name: "tenant", "scope", "resource", ...
	Value  string // the offending value
	Detail string // optional human explanation
	Input  string // full string being parsed, when available
}

func (e *ParseError) Error() string {
	msg := "crn: " + e.Kind.Error()
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
	if e.Input != "" {
		msg += fmt.Sprintf(" (input %q)", e.Input)
	}
	return msg
}

// Unwrap exposes the sentinel kind so errors.Is(err, ErrInvalidTenant) etc. works.
func (e *ParseError) Unwrap() error { return e.Kind }
