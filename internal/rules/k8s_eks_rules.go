package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// ── EKS_PUBLIC_ENDPOINT_WIDE_OPEN ─────────────────────────────────────────────

// EKSPublicEndpointWideOpenRule fires when the EKS cluster's public API server
// endpoint is accessible from the internet (0.0.0.0/0 in PublicAccessCidrs).
type EKSPublicEndpointWideOpenRule struct{}

func (r EKSPublicEndpointWideOpenRule) ID() string   { return "EKS_PUBLIC_ENDPOINT_WIDE_OPEN" }
func (r EKSPublicEndpointWideOpenRule) Name() string { return "EKS Public Endpoint Wide Open" }

func (r EKSPublicEndpointWideOpenRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if !eks.EndpointPublicAccess {
		return nil
	}
	hasOpenCIDR := false
	for _, cidr := range eks.PublicAccessCidrs {
		if cidr == "0.0.0.0/0" {
			hasOpenCIDR = true
			break
		}
	}
	if !hasOpenCIDR {
		return nil
	}
	return []models.Finding{{
		RuleID:         r.ID(),
		ResourceID:     eks.ClusterName,
		ResourceType:   models.ResourceK8sCluster,
		Region:         eks.Region,
		Severity:       models.SeverityCritical,
		Explanation:    "EKS cluster public endpoint allows 0.0.0.0/0; control plane exposed to internet",
		Recommendation: "Restrict PublicAccessCidrs to known CIDR ranges or disable the public endpoint.",
	}}
}

// ── EKS_SECRETS_ENCRYPTION_DISABLED ───────────────────────────────────────────

// EKSSecretsEncryptionDisabledRule fires when the EKS cluster does not use
// KMS envelope encryption for Kubernetes Secrets at rest.
type EKSSecretsEncryptionDisabledRule struct{}

func (r EKSSecretsEncryptionDisabledRule) ID() string {
	return "EKS_SECRETS_ENCRYPTION_DISABLED"
}
func (r EKSSecretsEncryptionDisabledRule) Name() string {
	return "EKS Secrets Encryption Disabled"
}

func (r EKSSecretsEncryptionDisabledRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if eks.EncryptionKeyARN != "" {
		return nil
	}
	return []models.Finding{{
		RuleID:         r.ID(),
		ResourceID:     eks.ClusterName,
		ResourceType:   models.ResourceK8sCluster,
		Region:         eks.Region,
		Severity:       models.SeverityHigh,
		Explanation:    "EKS cluster does not use KMS envelope encryption for Kubernetes secrets",
		Recommendation: "Enable secrets encryption by associating a KMS key with the EKS cluster.",
	}}
}

// ── EKS_CLUSTER_LOGGING_PARTIAL ───────────────────────────────────────────────

// eksRequiredLogTypes are the four control-plane log types that must ALL be
// enabled for complete auditability. "api" is omitted intentionally: it is
// high-volume and often disabled by design.
var eksRequiredLogTypes = []string{"audit", "authenticator", "controllerManager", "scheduler"}

// EKSClusterLoggingPartialRule fires when some — but not all — of the four
// required EKS control-plane log types are enabled in CloudWatch.
type EKSClusterLoggingPartialRule struct{}

func (r EKSClusterLoggingPartialRule) ID() string   { return "EKS_CLUSTER_LOGGING_PARTIAL" }
func (r EKSClusterLoggingPartialRule) Name() string { return "EKS Cluster Logging Partial" }

func (r EKSClusterLoggingPartialRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData

	enabled := make(map[string]bool, len(eks.EnabledLogTypes))
	for _, lt := range eks.EnabledLogTypes {
		enabled[lt] = true
	}

	count := 0
	for _, rt := range eksRequiredLogTypes {
		if enabled[rt] {
			count++
		}
	}

	// Fire only when partially configured: 1 ≤ count < 4.
	// 0 enabled → separate concern; 4 enabled → compliant.
	if count == 0 || count == len(eksRequiredLogTypes) {
		return nil
	}

	return []models.Finding{{
		RuleID:         r.ID(),
		ResourceID:     eks.ClusterName,
		ResourceType:   models.ResourceK8sCluster,
		Region:         eks.Region,
		Severity:       models.SeverityMedium,
		Explanation:    "EKS control plane logging is partially enabled; missing log types reduce auditability",
		Recommendation: "Enable all four required log types: audit, authenticator, controllerManager, scheduler.",
	}}
}

// ── EKS_NODEGROUP_IMDSV2_NOT_ENFORCED ─────────────────────────────────────────

// EKSNodegroupIMDSv2NotEnforcedRule fires for each EKS managed nodegroup where
// the instance metadata service does not require IMDSv2 (HttpTokens != "required").
// IMDSv1 is vulnerable to SSRF attacks that can expose node instance credentials.
type EKSNodegroupIMDSv2NotEnforcedRule struct{}

func (r EKSNodegroupIMDSv2NotEnforcedRule) ID() string {
	return "EKS_NODEGROUP_IMDSV2_NOT_ENFORCED"
}
func (r EKSNodegroupIMDSv2NotEnforcedRule) Name() string {
	return "EKS Nodegroup IMDSv2 Not Enforced"
}

func (r EKSNodegroupIMDSv2NotEnforcedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData

	var findings []models.Finding
	for _, ng := range eks.NodeGroups {
		if ng.HttpTokens == "required" {
			continue
		}
		findings = append(findings, models.Finding{
			RuleID:         r.ID(),
			ResourceID:     ng.Name,
			ResourceType:   models.ResourceK8sCluster,
			Region:         eks.Region,
			Severity:       models.SeverityHigh,
			Explanation:    "EKS node group does not enforce IMDSv2; metadata service vulnerable to SSRF",
			Recommendation: fmt.Sprintf("Set HttpTokens=required in the launch template for nodegroup %q.", ng.Name),
		})
	}
	return findings
}

// ── EKS_NODE_VERSION_SKEW ─────────────────────────────────────────────────────

// EKSNodeVersionSkewRule fires for each EKS nodegroup whose Kubernetes minor
// version differs from the control plane minor version by more than 1.
// A skew greater than 1 is outside the supported Kubernetes version skew policy
// and may cause API compatibility issues.
type EKSNodeVersionSkewRule struct{}

func (r EKSNodeVersionSkewRule) ID() string   { return "EKS_NODE_VERSION_SKEW" }
func (r EKSNodeVersionSkewRule) Name() string { return "EKS Node Version Skew" }

func (r EKSNodeVersionSkewRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData

	if eks.ControlPlaneVersion == "" {
		return nil
	}
	cpMinor, err := eksParseMinorVersion(eks.ControlPlaneVersion)
	if err != nil {
		return nil
	}

	var findings []models.Finding
	for _, ng := range eks.NodeGroups {
		if ng.Version == "" {
			continue
		}
		ngMinor, err := eksParseMinorVersion(ng.Version)
		if err != nil {
			continue
		}
		skew := cpMinor - ngMinor
		if skew < 0 {
			skew = -skew
		}
		if skew <= 1 {
			continue
		}
		findings = append(findings, models.Finding{
			RuleID:       r.ID(),
			ResourceID:   ng.Name,
			ResourceType: models.ResourceK8sCluster,
			Region:       eks.Region,
			Severity:     models.SeverityMedium,
			Explanation:  "EKS node version differs significantly from control plane version",
			Recommendation: fmt.Sprintf(
				"Update nodegroup %q from Kubernetes %s to match or be within 1 minor version of control plane %s.",
				ng.Name, ng.Version, eks.ControlPlaneVersion,
			),
		})
	}
	return findings
}

// ── helpers ───────────────────────────────────────────────────────────────────

// eksParseMinorVersion extracts the minor version integer from a Kubernetes
// version string such as "1.29", "1.29.3", or "v1.29.3-eks-abc123".
func eksParseMinorVersion(v string) (int, error) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("cannot parse minor version from %q", v)
	}
	// Strip any pre-release suffix from the minor part (e.g. "29-eks-abc123").
	minorStr := strings.SplitN(parts[1], "-", 2)[0]
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, fmt.Errorf("minor version in %q is not an integer: %w", v, err)
	}
	return minor, nil
}
