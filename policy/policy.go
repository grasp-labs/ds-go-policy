package policy

import (
	"fmt"
	"slices"
)

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Valid reports whether the effect is one of the two recognized values. An
// unrecognized effect (including the zero value "") must never be treated as
// allow — that would be fail-open.
func (e Effect) Valid() bool { return e == Allow || e == Deny }

type Statement struct {
	Sid    string `json:"sid,omitempty"`
	Effect Effect `json:"effect"`
	// "file:getFile", "file:*", "*"
	Actions []string `json:"actions"`
	// CRN patterns
	Resources  []string   `json:"resources"`
	Conditions Conditions `json:"conditions,omitempty"`
}

type Policy struct {
	ID string `json:"id"`
	// Name is the human-readable policy name assigned by the IAM service.
	Name string `json:"name,omitempty"`
	// Version is the document's semantic version (e.g. "1.0.0").
	Version    string      `json:"version"`
	Statements []Statement `json:"statements"`
}

// Validate performs structural validation of a policy: every statement must
// have a recognized effect and at least one non-empty action and resource.
// It leaves action syntax, resource patterns, and conditions to engine.Compile,
// keeping the policy model dependency-free.
func (p Policy) Validate() error {
	for i, s := range p.Statements {
		where := fmt.Sprintf("statement %d (%q)", i, s.Sid)
		if !s.Effect.Valid() {
			return &ParseError{Kind: ErrInvalidEffect, Field: "effect", Value: string(s.Effect), Statement: where}
		}
		if len(s.Actions) == 0 {
			return &ParseError{Kind: ErrNoActions, Field: "actions", Statement: where}
		}
		if len(s.Resources) == 0 {
			return &ParseError{Kind: ErrNoResources, Field: "resources", Statement: where}
		}
		if slices.Contains(s.Actions, "") {
			return &ParseError{Kind: ErrEmptyAction, Field: "actions", Statement: where}
		}
		if slices.Contains(s.Resources, "") {
			return &ParseError{Kind: ErrEmptyResource, Field: "resources", Statement: where}
		}
	}
	return nil
}
