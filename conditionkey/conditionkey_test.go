package conditionkey

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Key
	}{
		{
			name:  "inbound customer country code",
			input: "inbound:customer:country_code",
			want:  Key{Service: "inbound", Name: "customer:country_code"},
		},
		{
			name:  "opaque AWS-style name containing a colon",
			input: "kms:EncryptionContext:AppName",
			want:  Key{Service: "kms", Name: "EncryptionContext:AppName"},
		},
		{
			name:  "case is preserved",
			input: "Inbound:Customer:Country_Code",
			want:  Key{Service: "Inbound", Name: "Customer:Country_Code"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse(test.input)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", test.input, err)
			}
			if got != test.want {
				t.Errorf("Parse(%q) = %+v, want %+v", test.input, got, test.want)
			}
			if got.String() != test.input {
				t.Errorf("Parse(%q).String() = %q, want unchanged input", test.input, got.String())
			}
		})
	}
}

func TestBuild(t *testing.T) {
	want := Key{Service: "inbound", Name: "customer:org_number"}

	got, err := Build(want.Service, want.Name)
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if got != want {
		t.Errorf("Build() = %+v, want %+v", got, want)
	}
	if got.String() != "inbound:customer:org_number" {
		t.Errorf("Build().String() = %q, want %q", got.String(), "inbound:customer:org_number")
	}
}

func TestRoundTrip(t *testing.T) {
	inputs := []string{
		"inbound:customer:country_code",
		"inbound:customer:org_number",
		"InboundV2:Customer-Type_External_ID",
		"tagging:ResourceTag/owner.value",
		"kms:EncryptionContext:AppName",
	}

	for _, input := range inputs {
		parsed, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", input, err)
		}
		built, err := Build(parsed.Service, parsed.Name)
		if err != nil {
			t.Fatalf("Build() after Parse(%q) error: %v", input, err)
		}
		if got := built.String(); got != input {
			t.Errorf("round trip for %q = %q", input, got)
		}
	}
}

func TestParseRejectsInvalidKeys(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty input", input: ""},
		{name: "missing separator", input: "inbound/customer/country_code"},
		{name: "empty service", input: ":customer:country_code"},
		{name: "empty name", input: "inbound:"},
		{name: "service leading whitespace", input: " inbound:customer:country_code"},
		{name: "service embedded whitespace", input: "in bound:customer:country_code"},
		{name: "service slash", input: "in/bound:customer:country_code"},
		{name: "service wildcard", input: "*:customer:country_code"},
		{name: "service unicode", input: "inboünd:customer:country_code"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.input)
			if !errors.Is(err, ErrInvalidFormat) {
				t.Fatalf("Parse(%q) error = %v, want ErrInvalidFormat", test.input, err)
			}
		})
	}
}

func TestParseErrorDetails(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantField string
		wantValue string
	}{
		{
			name:      "missing separator reports complete key",
			input:     "inbound_customer",
			wantValue: "inbound_customer",
		},
		{
			name:      "invalid service reports field",
			input:     "in bound:customer:country_code",
			wantField: "service",
			wantValue: "in bound",
		},
		{
			name:      "empty name reports field",
			input:     "inbound:",
			wantField: "name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.input)
			var parseErr *ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("Parse() error type = %T, want *ParseError", err)
			}
			if parseErr.Kind != ErrInvalidFormat || parseErr.Field != test.wantField || parseErr.Value != test.wantValue {
				t.Errorf("ParseError = %+v, want kind %v, field %q, value %q", parseErr, ErrInvalidFormat, test.wantField, test.wantValue)
			}
		})
	}
}

func TestBuildRejectsInvalidParts(t *testing.T) {
	tests := []struct {
		name    string
		service string
		keyName string
	}{
		{name: "empty service", keyName: "customer:country_code"},
		{name: "empty name", service: "inbound"},
		{name: "colon in service", service: "in:bound", keyName: "customer:country_code"},
		{name: "space in service", service: "in bound", keyName: "customer:country_code"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Build(test.service, test.keyName)
			if !errors.Is(err, ErrInvalidFormat) {
				t.Fatalf("Build(%q, %q) error = %v, want ErrInvalidFormat", test.service, test.keyName, err)
			}
		})
	}
}
