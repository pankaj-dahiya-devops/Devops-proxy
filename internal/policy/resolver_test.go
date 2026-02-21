package policy

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

func boolPtr(b bool) *bool { return &b }

func TestApplyPolicy_DomainDisabled(t *testing.T) {
	cfg := &PolicyConfig{
		Domains: map[string]DomainConfig{
			"cost": {Enabled: false},
		},
	}

	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU"},
	}

	result := ApplyPolicy(findings, "cost", cfg)

	if len(result) != 0 {
		t.Fatalf("expected all findings dropped")
	}
}

func TestApplyPolicy_RuleDisabled(t *testing.T) {
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {Enabled: boolPtr(false)},
		},
	}

	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU"},
		{RuleID: "EBS_UNATTACHED"},
	}

	result := ApplyPolicy(findings, "cost", cfg)

	if len(result) != 1 {
		t.Fatalf("expected one finding remaining")
	}
	if result[0].RuleID != "EBS_UNATTACHED" {
		t.Fatalf("wrong finding kept")
	}
}

func TestApplyPolicy_SeverityOverride(t *testing.T) {
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {Severity: "CRITICAL"},
		},
	}

	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU", Severity: "MEDIUM"},
	}

	result := ApplyPolicy(findings, "cost", cfg)

	if result[0].Severity != "CRITICAL" {
		t.Fatalf("severity override failed")
	}
}

func TestApplyPolicy_NoPolicy(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU"},
	}

	result := ApplyPolicy(findings, "cost", nil)

	if len(result) != 1 {
		t.Fatalf("nil policy should not modify findings")
	}
}