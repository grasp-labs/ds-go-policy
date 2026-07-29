package policy

import (
	"bytes"
	"encoding/json"
)

// Conditions mirrors the mainstream IAM condition block:
//
//	operator -> condition key -> acceptable values
//
// Example (JSON):
//
//	"conditions": {
//	  "StringEquals": { "department": "eng" },
//	  "Bool":         { "mfa": "true" },
//	  "IpAddress":    { "sourceIp": ["10.0.0.0/8", "192.168.0.0/16"] }
//	}
//
// Evaluation (performed by the engine) follows conventional IAM semantics: operators AND
// together, keys within an operator AND together, and the values for a single
// key OR together. The data model here only carries the block; it assigns no
// meaning to operator names.
type Conditions map[string]map[string]Values

// Values is a set of condition values. Following convention it unmarshals from
// either a single JSON string or an array of strings.
type Values []string

func (v *Values) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*v = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*v = Values{s}
	return nil
}
