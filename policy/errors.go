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

type ParseError struct {
	Kind   error
	Field  string
	Value  string
	Detail string
	Input  string
	Cause  error
}

func (e *ParseError) Error() string {
	msg := "policy: " + e.Kind.Error()
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

func (e *ParseError) Unwrap() []error {
	if e.Cause == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Cause}
}
