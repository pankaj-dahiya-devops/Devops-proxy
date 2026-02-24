package rules_test

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
)

// eksRuleCtx builds a minimal RuleContext containing the provided EKSData.
func eksRuleCtx(eks *models.KubernetesEKSData) rules.RuleContext {
	return rules.RuleContext{
		ClusterData: &models.KubernetesClusterData{
			EKSData: eks,
		},
	}
}

// ── EKS_PUBLIC_ENDPOINT_WIDE_OPEN ─────────────────────────────────────────────

func TestEKSPublicEndpointWideOpen_Fires_WhenPublicAndOpenCIDR(t *testing.T) {
	rule := rules.EKSPublicEndpointWideOpenRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		ClusterName:          "prod-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: true,
		PublicAccessCidrs:    []string{"0.0.0.0/0"},
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_PUBLIC_ENDPOINT_WIDE_OPEN" {
		t.Errorf("RuleID = %q; want EKS_PUBLIC_ENDPOINT_WIDE_OPEN", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("Severity = %q; want CRITICAL", findings[0].Severity)
	}
	if findings[0].ResourceID != "prod-cluster" {
		t.Errorf("ResourceID = %q; want prod-cluster", findings[0].ResourceID)
	}
}

func TestEKSPublicEndpointWideOpen_Silent_WhenRestrictedCIDRs(t *testing.T) {
	rule := rules.EKSPublicEndpointWideOpenRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		EndpointPublicAccess: true,
		PublicAccessCidrs:    []string{"10.0.0.0/8", "192.168.1.0/24"},
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings for restricted CIDRs, got %d", len(findings))
	}
}

func TestEKSPublicEndpointWideOpen_Silent_WhenPublicAccessDisabled(t *testing.T) {
	rule := rules.EKSPublicEndpointWideOpenRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		EndpointPublicAccess: false,
		PublicAccessCidrs:    []string{"0.0.0.0/0"},
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when public access disabled, got %d", len(findings))
	}
}

func TestEKSPublicEndpointWideOpen_Silent_WhenEKSDataNil(t *testing.T) {
	rule := rules.EKSPublicEndpointWideOpenRule{}
	ctx := rules.RuleContext{ClusterData: &models.KubernetesClusterData{EKSData: nil}}
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when EKSData nil, got %d", len(findings))
	}
}

func TestEKSPublicEndpointWideOpen_Silent_WhenClusterDataNil(t *testing.T) {
	rule := rules.EKSPublicEndpointWideOpenRule{}
	ctx := rules.RuleContext{ClusterData: nil}
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when ClusterData nil, got %d", len(findings))
	}
}

// ── EKS_SECRETS_ENCRYPTION_DISABLED ───────────────────────────────────────────

func TestEKSSecretsEncryptionDisabled_Fires_WhenNoKMSKey(t *testing.T) {
	rule := rules.EKSSecretsEncryptionDisabledRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		ClusterName:      "prod-cluster",
		Region:           "us-east-1",
		EncryptionKeyARN: "",
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
	if findings[0].RuleID != "EKS_SECRETS_ENCRYPTION_DISABLED" {
		t.Errorf("RuleID = %q; want EKS_SECRETS_ENCRYPTION_DISABLED", findings[0].RuleID)
	}
}

func TestEKSSecretsEncryptionDisabled_Silent_WhenKMSKeySet(t *testing.T) {
	rule := rules.EKSSecretsEncryptionDisabledRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		EncryptionKeyARN: "arn:aws:kms:us-east-1:123456789012:key/abc-123",
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when KMS key is set, got %d", len(findings))
	}
}

func TestEKSSecretsEncryptionDisabled_Silent_WhenEKSDataNil(t *testing.T) {
	rule := rules.EKSSecretsEncryptionDisabledRule{}
	ctx := rules.RuleContext{ClusterData: &models.KubernetesClusterData{}}
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when EKSData nil, got %d", len(findings))
	}
}

func TestEKSSecretsEncryptionDisabled_Silent_WhenClusterDataNil(t *testing.T) {
	rule := rules.EKSSecretsEncryptionDisabledRule{}
	ctx := rules.RuleContext{ClusterData: nil}
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when ClusterData nil, got %d", len(findings))
	}
}

func TestEKSSecretsEncryptionDisabled_IDAndName(t *testing.T) {
	rule := rules.EKSSecretsEncryptionDisabledRule{}
	if rule.ID() != "EKS_SECRETS_ENCRYPTION_DISABLED" {
		t.Errorf("ID() = %q; want EKS_SECRETS_ENCRYPTION_DISABLED", rule.ID())
	}
	if rule.Name() != "EKS Secrets Encryption Disabled" {
		t.Errorf("Name() = %q; want EKS Secrets Encryption Disabled", rule.Name())
	}
}

// ── EKS_CLUSTER_LOGGING_PARTIAL ───────────────────────────────────────────────

func TestEKSClusterLoggingPartial_Fires_WhenTwoOfFourEnabled(t *testing.T) {
	rule := rules.EKSClusterLoggingPartialRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		ClusterName:     "prod-cluster",
		Region:          "us-east-1",
		EnabledLogTypes: []string{"audit", "authenticator"},
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 2-of-4 log types, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
	}
}

func TestEKSClusterLoggingPartial_Silent_WhenAllFourEnabled(t *testing.T) {
	rule := rules.EKSClusterLoggingPartialRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		EnabledLogTypes: []string{"audit", "authenticator", "controllerManager", "scheduler"},
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when all 4 log types enabled, got %d", len(findings))
	}
}

func TestEKSClusterLoggingPartial_Silent_WhenNoneEnabled(t *testing.T) {
	rule := rules.EKSClusterLoggingPartialRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		EnabledLogTypes: []string{},
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when no log types enabled (separate concern), got %d", len(findings))
	}
}

func TestEKSClusterLoggingPartial_Fires_WhenOneOfFourEnabled(t *testing.T) {
	rule := rules.EKSClusterLoggingPartialRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		EnabledLogTypes: []string{"audit"},
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 1-of-4 log types, got %d", len(findings))
	}
}

func TestEKSClusterLoggingPartial_Silent_WhenEKSDataNil(t *testing.T) {
	rule := rules.EKSClusterLoggingPartialRule{}
	ctx := rules.RuleContext{ClusterData: &models.KubernetesClusterData{}}
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when EKSData nil, got %d", len(findings))
	}
}

// ── EKS_NODEGROUP_IMDSV2_NOT_ENFORCED ─────────────────────────────────────────

func TestEKSNodegroupIMDSv2NotEnforced_Fires_WhenOptional(t *testing.T) {
	rule := rules.EKSNodegroupIMDSv2NotEnforcedRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		Region: "us-east-1",
		NodeGroups: []models.KubernetesEKSNodeGroupData{
			{Name: "ng-workers", HttpTokens: "optional"},
		},
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ResourceID != "ng-workers" {
		t.Errorf("ResourceID = %q; want ng-workers", findings[0].ResourceID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
}

func TestEKSNodegroupIMDSv2NotEnforced_Silent_WhenRequired(t *testing.T) {
	rule := rules.EKSNodegroupIMDSv2NotEnforcedRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		NodeGroups: []models.KubernetesEKSNodeGroupData{
			{Name: "ng-1", HttpTokens: "required"},
		},
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings for required HttpTokens, got %d", len(findings))
	}
}

func TestEKSNodegroupIMDSv2NotEnforced_MultipleNodegroups_TwoFire(t *testing.T) {
	rule := rules.EKSNodegroupIMDSv2NotEnforcedRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		NodeGroups: []models.KubernetesEKSNodeGroupData{
			{Name: "ng-ok", HttpTokens: "required"},
			{Name: "ng-bad-1", HttpTokens: "optional"},
			{Name: "ng-bad-2", HttpTokens: "optional"},
		},
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for 2 non-compliant nodegroups, got %d", len(findings))
	}
}

func TestEKSNodegroupIMDSv2NotEnforced_Silent_WhenNoNodegroups(t *testing.T) {
	rule := rules.EKSNodegroupIMDSv2NotEnforcedRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{NodeGroups: nil})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when no nodegroups, got %d", len(findings))
	}
}

func TestEKSNodegroupIMDSv2NotEnforced_Silent_WhenEKSDataNil(t *testing.T) {
	rule := rules.EKSNodegroupIMDSv2NotEnforcedRule{}
	ctx := rules.RuleContext{ClusterData: &models.KubernetesClusterData{}}
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when EKSData nil, got %d", len(findings))
	}
}

// ── EKS_NODE_VERSION_SKEW ─────────────────────────────────────────────────────

func TestEKSNodeVersionSkew_Fires_WhenSkewIsTwo(t *testing.T) {
	rule := rules.EKSNodeVersionSkewRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		ClusterName:         "prod-cluster",
		Region:              "us-east-1",
		ControlPlaneVersion: "1.29",
		NodeGroups: []models.KubernetesEKSNodeGroupData{
			{Name: "ng-old", Version: "1.27"},
		},
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for skew=2, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
	}
	if findings[0].ResourceID != "ng-old" {
		t.Errorf("ResourceID = %q; want ng-old", findings[0].ResourceID)
	}
}

func TestEKSNodeVersionSkew_Silent_WhenSkewIsOne(t *testing.T) {
	rule := rules.EKSNodeVersionSkewRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		ControlPlaneVersion: "1.29",
		NodeGroups: []models.KubernetesEKSNodeGroupData{
			{Name: "ng-1", Version: "1.28"},
		},
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings for skew=1, got %d", len(findings))
	}
}

func TestEKSNodeVersionSkew_Mixed_OnlySkewedFires(t *testing.T) {
	rule := rules.EKSNodeVersionSkewRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		ControlPlaneVersion: "1.29",
		NodeGroups: []models.KubernetesEKSNodeGroupData{
			{Name: "ng-ok", Version: "1.28"},   // skew=1 → silent
			{Name: "ng-bad", Version: "1.26"},  // skew=3 → fires
		},
	})
	findings := rule.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (only ng-bad), got %d", len(findings))
	}
	if findings[0].ResourceID != "ng-bad" {
		t.Errorf("ResourceID = %q; want ng-bad", findings[0].ResourceID)
	}
}

func TestEKSNodeVersionSkew_Silent_WhenControlPlaneVersionEmpty(t *testing.T) {
	rule := rules.EKSNodeVersionSkewRule{}
	ctx := eksRuleCtx(&models.KubernetesEKSData{
		ControlPlaneVersion: "",
		NodeGroups: []models.KubernetesEKSNodeGroupData{
			{Name: "ng-1", Version: "1.27"},
		},
	})
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when control plane version is empty, got %d", len(findings))
	}
}

func TestEKSNodeVersionSkew_Silent_WhenEKSDataNil(t *testing.T) {
	rule := rules.EKSNodeVersionSkewRule{}
	ctx := rules.RuleContext{ClusterData: &models.KubernetesClusterData{}}
	if findings := rule.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected no findings when EKSData nil, got %d", len(findings))
	}
}
