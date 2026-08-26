package sqlfilter_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
)

func TestWhere_ProjectsPatternsAgainstMapping(t *testing.T) {
	parse := func(value string) crn.Pattern {
		t.Helper()
		p, err := crn.ParsePattern(value)
		if err != nil {
			t.Fatalf("ParsePattern(%q): %v", value, err)
		}
		return p
	}

	supported := engine.ResourceMatch{Pattern: pattern(t, "**")}
	unsupported := engine.ResourceMatch{Pattern: pattern(t, "folder/*/file")}
	broad := engine.ResourceMatch{Pattern: parse(fmt.Sprintf("crn:%s:*:file:*:*:**", tenant))}
	wildcardService := engine.ResourceMatch{Pattern: parse(fmt.Sprintf("crn:%s:*:*:*:*:**", tenant))}
	foreignUnsupported := engine.ResourceMatch{Pattern: parse(
		fmt.Sprintf("crn:%s:*:iam:*:*:folder/*/file", tenant),
	)}
	narrow := engine.ResourceMatch{Pattern: parse(
		fmt.Sprintf("crn:%s:*:file::customer:123", tenant),
	)}
	regionless := engine.ResourceMatch{Pattern: parse(fmt.Sprintf("crn:%s:*:file::*:**", tenant))}
	regioned := engine.ResourceMatch{Pattern: parse(fmt.Sprintf("crn:%s:*:file:eu-west-1:*:**", tenant))}
	regionedAndScoped := engine.ResourceMatch{Pattern: parse(
		fmt.Sprintf("crn:%s:production:file:eu-west-1:*:**", tenant),
	)}
	emptyScope := engine.ResourceMatch{Pattern: parse(fmt.Sprintf("crn:%s::file::*:**", tenant))}
	emptyType := engine.ResourceMatch{Pattern: parse(fmt.Sprintf("crn:%s:*:file:::**", tenant))}
	emptyDimensions := engine.ResourceMatch{Pattern: parse(fmt.Sprintf("crn:%s::file:::**", tenant))}

	defaultMapping := mapping()
	flatMapping := sqlfilter.Mapping{Service: "file", Tenant: "tenant_id"}
	fixedRegionMapping := sqlfilter.Mapping{
		Service: "file",
		Tenant:  "tenant_id",
		Fixed:   map[sqlfilter.Segment]string{sqlfilter.SegmentRegion: ""},
	}
	fixedEmptyMapping := sqlfilter.Mapping{
		Service: "file",
		Tenant:  "tenant_id",
		Fixed: map[sqlfilter.Segment]string{
			sqlfilter.SegmentScope:  "",
			sqlfilter.SegmentRegion: "",
			sqlfilter.SegmentType:   "",
		},
	}

	tests := []struct {
		name        string
		constraints engine.Constraints
		mapping     sqlfilter.Mapping
		wantWhere   string
		wantArgs    []any
		wantErr     error
	}{
		{
			name: "unrepresentable allow before supported allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{unsupported, supported},
			},
			mapping: defaultMapping,
			wantErr: sqlfilter.ErrUnsupportedPattern,
		},
		{
			name: "unrepresentable allow after supported allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{supported, unsupported},
			},
			mapping: defaultMapping,
			wantErr: sqlfilter.ErrUnsupportedPattern,
		},
		{
			name: "unrepresentable allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{unsupported},
			},
			mapping: defaultMapping,
			wantErr: sqlfilter.ErrUnsupportedPattern,
		},
		{
			name: "narrow allow before broad allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{narrow, broad},
			},
			mapping: fixedRegionMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "narrow allow after broad allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{broad, narrow},
			},
			mapping: fixedRegionMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "unrepresentable deny is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{supported},
				Deny:  []engine.ResourceMatch{unsupported},
			},
			mapping: defaultMapping,
			wantErr: sqlfilter.ErrUnsupportedPattern,
		},
		{
			name: "unmapped empty region allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{regionless},
			},
			mapping: flatMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "unmapped empty region deny is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{broad},
				Deny:  []engine.ResourceMatch{regionless},
			},
			mapping: flatMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "unmapped empty scope allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{emptyScope},
			},
			mapping: fixedRegionMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "unmapped empty scope deny is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{broad},
				Deny:  []engine.ResourceMatch{emptyScope},
			},
			mapping: fixedRegionMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "unmapped empty type allow is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{emptyType},
			},
			mapping: fixedRegionMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "unmapped empty type deny is rejected",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{broad},
				Deny:  []engine.ResourceMatch{emptyType},
			},
			mapping: fixedRegionMapping,
			wantErr: sqlfilter.ErrNoColumnForField,
		},
		{
			name: "fixed empty literal is represented and mismatch is disjoint",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{regionless},
				Deny:  []engine.ResourceMatch{regioned},
			},
			mapping:   fixedRegionMapping,
			wantWhere: "tenant_id = ?",
			wantArgs:  []any{tenant},
		},
		{
			name: "fixed mismatch proves deny disjoint before unmapped field",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{regionless},
				Deny:  []engine.ResourceMatch{regionedAndScoped},
			},
			mapping:   fixedRegionMapping,
			wantWhere: "tenant_id = ?",
			wantArgs:  []any{tenant},
		},
		{
			name: "explicit fixed empty dimensions are represented",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{emptyDimensions},
			},
			mapping:   fixedEmptyMapping,
			wantWhere: "tenant_id = ?",
			wantArgs:  []any{tenant},
		},
		{
			name: "service wildcard applies to the mapped service",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{wildcardService},
			},
			mapping:   defaultMapping,
			wantWhere: "tenant_id = ?",
			wantArgs:  []any{tenant},
		},
		{
			name: "foreign service allow closes the query",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{foreignUnsupported},
			},
			mapping:   defaultMapping,
			wantWhere: "1=0",
		},
		{
			name: "foreign service allow is omitted beside local allow",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{foreignUnsupported, supported},
			},
			mapping:   defaultMapping,
			wantWhere: "tenant_id = ? AND type = ?",
			wantArgs:  []any{tenant, "file"},
		},
		{
			name: "foreign service deny is omitted before pattern projection",
			constraints: engine.Constraints{
				Allow: []engine.ResourceMatch{supported},
				Deny:  []engine.ResourceMatch{foreignUnsupported},
			},
			mapping:   defaultMapping,
			wantWhere: "tenant_id = ? AND type = ?",
			wantArgs:  []any{tenant, "file"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			where, args, err := sqlfilter.Where(test.constraints, test.mapping)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Where error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Where: %v", err)
			}
			if where != test.wantWhere {
				t.Fatalf("where = %q, want %q", where, test.wantWhere)
			}
			if !reflect.DeepEqual(args, test.wantArgs) {
				t.Fatalf("args = %#v, want %#v", args, test.wantArgs)
			}
		})
	}
}
