// Package kubernetes_eks provides EKS-specific Kubernetes governance rules.
// These rules are evaluated only when the cluster provider is detected as "eks"
// and require EKS control-plane data collected via the AWS EKS API.
package kubernetes_eks

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the EKS-specific governance rules ordered by severity.
func New() []rules.Rule {
	return []rules.Rule{
		rules.EKSPublicEndpointRule{},        // HIGH
		rules.EKSOIDCProviderMissingRule{},   // HIGH
		rules.EKSClusterLoggingDisabledRule{}, // MEDIUM
	}
}
