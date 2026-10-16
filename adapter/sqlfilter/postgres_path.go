package sqlfilter

import (
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/grasp-labs/ds-go-policy/conditionoperator"
	"github.com/grasp-labs/ds-go-policy/engine"
)

// WithPostgresPathConditions connects policy path conditions to a PostgreSQL
// column, so Where can filter rows without hand-written SQL for each path segment.
//
// For example, a policy statement can include this condition:
//
//	{
//	  "conditions": {
//	    "StringEquals": {"resource.path[1]": ["org-a", "org-b"]}
//	  }
//	}
//
// Indexes start at zero, so this checks the second part of the path:
//
//	inbound/org-a/report.xml   -> matches
//	inbound/org-b/invoice.xml  -> matches
//	inbound/org-c/report.xml   -> does not match
//	inbound                    -> does not match (no second part)
//
// After Constrain, pass the table's existing mapping through the helper:
//
//	mapping = sqlfilter.WithPostgresPathConditions(mapping, cons, "file.file_path")
//	where, args, err := sqlfilter.Where(cons, mapping)
//
// Where adds this SQL condition, with "org-a" and "org-b" as bound arguments:
//
//	(string_to_array(file.file_path, '/'))[2] IN (?, ?)
//
// Other authorization checks still apply. The helper handles both allows and
// denies, preserves existing mappings, and enables StringEquals for new keys.
// pathColumn must be trusted SQL from the service, never user input.
func WithPostgresPathConditions(mapping Mapping, constraints engine.Constraints, pathColumn string) Mapping {
	if strings.TrimSpace(pathColumn) == "" {
		return mapping
	}
	mapping.Conditions = maps.Clone(mapping.Conditions)
	if mapping.Conditions == nil {
		mapping.Conditions = make(map[string]string)
	}
	mapping.AllowedConditionOperators = maps.Clone(mapping.AllowedConditionOperators)
	if mapping.AllowedConditionOperators == nil {
		mapping.AllowedConditionOperators = make(map[string][]string)
	}
	for key, operators := range mapping.AllowedConditionOperators {
		mapping.AllowedConditionOperators[key] = slices.Clone(operators)
	}

	for _, matches := range [][]engine.ResourceMatch{constraints.Allow, constraints.Deny} {
		for _, match := range matches {
			for _, byKey := range match.Conditions {
				for key := range byKey {
					index, ok := engine.ResourcePathKey(key)
					// PostgreSQL's one-based segment index is a signed 32-bit integer.
					if !ok || index >= math.MaxInt32 || mapping.Conditions[key] != "" {
						continue
					}
					if index == 0 {
						mapping.Conditions[key] = fmt.Sprintf("split_part(%s, '/', 1)", pathColumn)
					} else {
						mapping.Conditions[key] = fmt.Sprintf("(string_to_array(%s, '/'))[%d]", pathColumn, index+1)
					}
					if _, exists := mapping.AllowedConditionOperators[key]; !exists {
						mapping.AllowedConditionOperators[key] = []string{conditionoperator.StringEquals}
					}
				}
			}
		}
	}
	return mapping
}
