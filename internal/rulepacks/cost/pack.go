// Package cost provides the rule pack for AWS cost audit.
// New returns every cost rule in evaluation order; callers register them
// into a RuleRegistry via a loop rather than listing each rule explicitly.
//
// Adding a new cost rule:
//  1. Implement the rule in internal/rules/ following the Rule interface.
//  2. Append it to the slice returned by New().
//  3. No other files need to change.
//
// Future packs (e.g. internal/rulepacks/security, internal/rulepacks/k8s)
// follow the same convention: a single New() function returns a []rules.Rule
// slice that the corresponding command registers in one loop.
package cost

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns all AWS cost rules in the order they should be evaluated.
func New() []rules.Rule {
	return []rules.Rule{
		rules.EBSUnattachedRule{},
		rules.EBSGP2LegacyRule{},
		rules.EC2LowCPURule{},
		rules.NATLowTrafficRule{},
		rules.SavingsPlanUnderutilizedRule{},
		rules.RDSLowCPURule{},
	}
}
