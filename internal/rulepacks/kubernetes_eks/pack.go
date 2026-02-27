// Package kubernetes_eks provides EKS-specific Kubernetes governance rules.
// These rules are evaluated only when the cluster provider is detected as "eks"
// and require EKS control-plane data collected via the AWS EKS API.
package kubernetes_eks

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the Phase 5A EKS-specific governance rules ordered by severity:
//   - EKS_ENCRYPTION_DISABLED          (CRITICAL) — secrets not encrypted at rest
//   - EKS_PUBLIC_ENDPOINT_ENABLED      (HIGH)     — API server endpoint publicly accessible
//   - EKS_CONTROL_PLANE_LOGGING_DISABLED (HIGH)   — api/audit/authenticator logs not all enabled
func New() []rules.Rule {
	return []rules.Rule{
		rules.EKSEncryptionDisabledRule{},              // CRITICAL
		rules.EKSPublicEndpointRule{},                  // HIGH
		rules.EKSControlPlaneLoggingDisabledRule{},     // HIGH
	}
}
