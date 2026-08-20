package conditionoperator

import "testing"

func TestOperatorWireValues(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"StringEquals", StringEquals, "StringEquals"},
		{"StringNotEquals", StringNotEquals, "StringNotEquals"},
		{"StringEqualsIgnoreCase", StringEqualsIgnoreCase, "StringEqualsIgnoreCase"},
		{"StringNotEqualsIgnoreCase", StringNotEqualsIgnoreCase, "StringNotEqualsIgnoreCase"},
		{"StringLike", StringLike, "StringLike"},
		{"StringNotLike", StringNotLike, "StringNotLike"},
		{"Bool", Bool, "Bool"},
		{"NumericEquals", NumericEquals, "NumericEquals"},
		{"NumericNotEquals", NumericNotEquals, "NumericNotEquals"},
		{"NumericLessThan", NumericLessThan, "NumericLessThan"},
		{"NumericLessThanEquals", NumericLessThanEquals, "NumericLessThanEquals"},
		{"NumericGreaterThan", NumericGreaterThan, "NumericGreaterThan"},
		{"NumericGreaterThanEquals", NumericGreaterThanEquals, "NumericGreaterThanEquals"},
		{"DateEquals", DateEquals, "DateEquals"},
		{"DateNotEquals", DateNotEquals, "DateNotEquals"},
		{"DateLessThan", DateLessThan, "DateLessThan"},
		{"DateLessThanEquals", DateLessThanEquals, "DateLessThanEquals"},
		{"DateGreaterThan", DateGreaterThan, "DateGreaterThan"},
		{"DateGreaterThanEquals", DateGreaterThanEquals, "DateGreaterThanEquals"},
		{"IPAddress", IPAddress, "IpAddress"},
		{"NotIPAddress", NotIPAddress, "NotIpAddress"},
		{"Null", Null, "Null"},
		{"IfExistsSuffix", IfExistsSuffix, "IfExists"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Errorf("operator = %q, want %q", test.got, test.want)
			}
		})
	}
}

func TestWithIfExists(t *testing.T) {
	const want = "StringEqualsIfExists"
	if got := WithIfExists(StringEquals); got != want {
		t.Errorf("WithIfExists(StringEquals) = %q, want %q", got, want)
	}
}
