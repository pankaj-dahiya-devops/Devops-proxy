// Package kubernetes_eks provides the EKS-specific governance rule pack.
// These rules require AWS EKS API data and are evaluated only when the cluster
// provider is detected as "eks". They complement the core Kubernetes rules.
package kubernetes_eks

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the EKS-specific governance rules ordered by severity:
// CRITICAL first, then HIGH, then MEDIUM.
func New() []rules.Rule {
	return []rules.Rule{
		rules.EKSPublicEndpointWideOpenRule{},     // CRITICAL
		rules.EKSSecretsEncryptionDisabledRule{},  // HIGH
		rules.EKSNodegroupIMDSv2NotEnforcedRule{}, // HIGH
		rules.EKSClusterLoggingPartialRule{},      // MEDIUM
		rules.EKSNodeVersionSkewRule{},            // MEDIUM
	}
}
