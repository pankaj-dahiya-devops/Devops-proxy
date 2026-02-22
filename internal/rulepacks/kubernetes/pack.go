// Package kubernetes provides the Kubernetes governance rule pack.
// It groups cluster-level deterministic checks into a single registration call.
package kubernetes

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the complete set of Kubernetes governance rules ordered by
// severity: HIGH first (cluster, node), then MEDIUM (namespace).
func New() []rules.Rule {
	return []rules.Rule{
		rules.K8SClusterSingleNodeRule{},      // HIGH
		rules.K8SNodeOverallocatedRule{},      // HIGH
		rules.K8SNamespaceWithoutLimitsRule{}, // MEDIUM
	}
}
