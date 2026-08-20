// Package conditionkey defines the grammar for service-owned IAM condition
// keys.
//
// A service-owned condition key has a service namespace followed by an opaque
// name, separated by the first colon:
//
//	<service>:<name>
//
// For example, "file:path_prefix:project" identifies a file-service-owned
// condition key whose name is "path_prefix:project". The name may contain
// additional colons and is opaque to this package: a service may establish its
// own naming convention within that part.
// The package validates only the key's shared structure. It does not decide
// which keys a service supports or map keys to storage fields; callers must
// keep that mapping explicit.
package conditionkey

import (
	"errors"
	"fmt"
	"strings"
)

const separator = ":"

// ErrInvalidFormat is returned when a condition key is not in
// <service>:<name> form or its service prefix is malformed.
var ErrInvalidFormat = errors.New("invalid condition key format")

// Key is a structurally valid service-owned IAM condition key.
type Key struct {
	Service string
	Name    string
}

// ParseError describes why a condition key was rejected.
type ParseError struct {
	Kind  error
	Field string
	Value string
}

func (e *ParseError) Error() string {
	message := "conditionkey: " + e.Kind.Error()
	if e.Field != "" {
		message += fmt.Sprintf(": field %q", e.Field)
		if e.Value != "" {
			message += fmt.Sprintf(" = %q", e.Value)
		}
	} else if e.Value != "" {
		message += fmt.Sprintf(": %q", e.Value)
	}
	return message
}

// Unwrap exposes the error kind for errors.Is.
func (e *ParseError) Unwrap() error { return e.Kind }

// Parse parses a condition key in <service>:<name> form.
// Parts are case-sensitive and are not normalized.
func Parse(value string) (Key, error) {
	service, name, found := strings.Cut(value, separator)
	if !found {
		return Key{}, &ParseError{Kind: ErrInvalidFormat, Value: value}
	}

	key := Key{
		Service: service,
		Name:    name,
	}
	if err := validate(key); err != nil {
		return Key{}, err
	}
	return key, nil
}

// Build constructs a condition key from its two parts. Parts are
// case-sensitive and are not normalized.
func Build(service, name string) (Key, error) {
	key := Key{
		Service: service,
		Name:    name,
	}
	if err := validate(key); err != nil {
		return Key{}, err
	}
	return key, nil
}

// String renders a key in canonical <service>:<name> form.
func (k Key) String() string {
	return strings.Join([]string{k.Service, k.Name}, separator)
}

func validate(key Key) error {
	if key.Service == "" {
		return &ParseError{Kind: ErrInvalidFormat, Field: "service"}
	}
	if !validService(key.Service) {
		return &ParseError{
			Kind:  ErrInvalidFormat,
			Field: "service",
			Value: key.Service,
		}
	}
	if key.Name == "" {
		return &ParseError{Kind: ErrInvalidFormat, Field: "name"}
	}
	return nil
}

// validService deliberately accepts a small ASCII-only alphabet for the
// namespace. The name remains opaque: services own its validation and
// allowlist rather than this package imposing a global substructure on it.
func validService(value string) bool {
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}
