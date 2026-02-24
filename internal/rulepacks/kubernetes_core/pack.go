// Package kubernetes_core provides the cloud-agnostic Kubernetes governance
// rule pack. These rules apply to any Kubernetes cluster regardless of the
// underlying cloud provider.
package kubernetes_core

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the complete set of cloud-agnostic Kubernetes governance rules
// ordered by severity: CRITICAL first, then HIGH, then MEDIUM.
func New() []rules.Rule {
	return []rules.Rule{
		rules.K8SPrivilegedContainerRule{},        // CRITICAL
		rules.K8SClusterSingleNodeRule{},           // HIGH
		rules.K8SNodeOverallocatedRule{},           // HIGH
		rules.K8SServicePublicLoadBalancerRule{},   // HIGH
		rules.K8SNamespaceWithoutLimitsRule{},      // MEDIUM
		rules.K8SPodNoResourceRequestsRule{},       // MEDIUM
	}
}
