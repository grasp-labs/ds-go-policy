// Package conditionoperator defines the shared names of IAM condition
// operators. Services may support only a subset of these operators for a
// particular condition key.
package conditionoperator

// String operators.
const (
	StringEquals              = "StringEquals"
	StringNotEquals           = "StringNotEquals"
	StringEqualsIgnoreCase    = "StringEqualsIgnoreCase"
	StringNotEqualsIgnoreCase = "StringNotEqualsIgnoreCase"
	StringLike                = "StringLike"
	StringNotLike             = "StringNotLike"
)

// Boolean operator.
const Bool = "Bool"

// Numeric operators.
const (
	NumericEquals            = "NumericEquals"
	NumericNotEquals         = "NumericNotEquals"
	NumericLessThan          = "NumericLessThan"
	NumericLessThanEquals    = "NumericLessThanEquals"
	NumericGreaterThan       = "NumericGreaterThan"
	NumericGreaterThanEquals = "NumericGreaterThanEquals"
)

// Date operators.
const (
	DateEquals            = "DateEquals"
	DateNotEquals         = "DateNotEquals"
	DateLessThan          = "DateLessThan"
	DateLessThanEquals    = "DateLessThanEquals"
	DateGreaterThan       = "DateGreaterThan"
	DateGreaterThanEquals = "DateGreaterThanEquals"
)

// IP address operators.
const (
	IPAddress    = "IpAddress"
	NotIPAddress = "NotIpAddress"
)

// Null tests whether a condition key is absent ("true") or present ("false").
const Null = "Null"

// IfExistsSuffix turns any supported base operator into its conditional
// variant. The engine evaluates that variant as true when the key is absent.
const IfExistsSuffix = "IfExists"

// WithIfExists returns the wire name of an operator's IfExists variant.
func WithIfExists(operator string) string {
	return operator + IfExistsSuffix
}
