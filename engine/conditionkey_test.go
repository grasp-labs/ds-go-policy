package engine_test

import (
	"errors"
	"testing"

	"github.com/grasp-labs/ds-go-policy/conditionkey"
	"github.com/grasp-labs/ds-go-policy/conditionoperator"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

func TestCompileValidatesServiceOwnedConditionKeys(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr error
	}{
		{name: "valid service key", key: "inbound:customer:country_code"},
		{name: "opaque key name", key: "inbound:ResourceTag/customer.country"},
		{name: "opaque key name containing a colon", key: "config:tag:cost_center"},
		{name: "legacy unqualified key", key: "department"},
		{name: "empty service", key: ":customer:country_code", wantErr: conditionkey.ErrInvalidFormat},
		{name: "empty key name", key: "inbound:", wantErr: conditionkey.ErrInvalidFormat},
		{name: "invalid service", key: "in bound:customer:country_code", wantErr: conditionkey.ErrInvalidFormat},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policies := []policy.Policy{{
				Version: "1.0.0",
				Statements: []policy.Statement{{
					Effect:    policy.Allow,
					Actions:   []string{"inbound:listCustomerDetails"},
					Resources: []string{"crn:aic:*:inbound::*:**"},
					Conditions: policy.Conditions{
						conditionoperator.StringEquals: {test.key: {"value"}},
					},
				}},
			}}

			_, err := engine.Compile(policies)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("Compile() error = %v", err)
				}
				return
			}
			if !errors.Is(err, engine.ErrInvalidConditions) {
				t.Errorf("Compile() error = %v, want ErrInvalidConditions", err)
			}
			if !errors.Is(err, test.wantErr) {
				t.Errorf("Compile() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}
