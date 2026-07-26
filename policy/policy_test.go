package policy_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/policy"
)

func TestConditionsUnmarshal(t *testing.T) {
	// Mirrors AWS: a value may be a single string or an array of strings.
	const doc = `{
		"StringEquals": { "dept": "eng" },
		"IpAddress":    { "ip": ["10.0.0.0/8", "192.168.0.0/16"] }
	}`
	var got policy.Conditions
	if err := json.Unmarshal([]byte(doc), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := policy.Conditions{
		"StringEquals": {"dept": {"eng"}},
		"IpAddress":    {"ip": {"10.0.0.0/8", "192.168.0.0/16"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Conditions = %#v, want %#v", got, want)
	}
}

func TestPolicyValidate(t *testing.T) {
	valid := policy.Statement{
		Effect:    policy.Allow,
		Actions:   []string{"file:getFile"},
		Resources: []string{"crn:t:*:file::file:datalake/**"},
	}

	tests := []struct {
		name string
		stmt policy.Statement
		want error
	}{
		{"valid", valid, nil},
		{"empty effect", policy.Statement{Actions: valid.Actions, Resources: valid.Resources}, policy.ErrInvalidEffect},
		{"bad effect", policy.Statement{Effect: "ALLOW", Actions: valid.Actions, Resources: valid.Resources}, policy.ErrInvalidEffect},
		{"no actions", policy.Statement{Effect: policy.Allow, Resources: valid.Resources}, policy.ErrNoActions},
		{"no resources", policy.Statement{Effect: policy.Allow, Actions: valid.Actions}, policy.ErrNoResources},
		{"empty action", policy.Statement{Effect: policy.Allow, Actions: []string{""}, Resources: valid.Resources}, policy.ErrEmptyAction},
		{"empty resource", policy.Statement{Effect: policy.Allow, Actions: valid.Actions, Resources: []string{""}}, policy.ErrEmptyResource},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := policy.Policy{Statements: []policy.Statement{test.stmt}}.Validate()
			if test.want == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Errorf("Validate() = %v, want %v", err, test.want)
			}
		})
	}
}
