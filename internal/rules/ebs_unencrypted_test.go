package rules

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

func TestEBSUnencryptedRule_ID(t *testing.T) {
	r := EBSUnencryptedRule{}
	if r.ID() != "EBS_UNENCRYPTED" {
		t.Error("unexpected rule ID")
	}
}

func TestEBSUnencryptedRule_NilRegionData(t *testing.T) {
	findings := EBSUnencryptedRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

func TestEBSUnencryptedRule_EncryptedVolume_NoFinding(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.RegionData{
			Region: "us-east-1",
			EBSVolumes: []models.EBSVolume{
				{VolumeID: "vol-enc", VolumeType: "gp3", SizeGB: 100, Encrypted: true},
			},
		},
	}
	findings := EBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for encrypted volume, got %d", len(findings))
	}
}

func TestEBSUnencryptedRule_UnencryptedVolume_HighSeverity(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "test",
		RegionData: &models.RegionData{
			Region: "us-east-1",
			EBSVolumes: []models.EBSVolume{
				{VolumeID: "vol-bare", VolumeType: "gp3", SizeGB: 200, Encrypted: false, State: "in-use"},
			},
		},
	}
	findings := EBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ResourceID != "vol-bare" {
		t.Errorf("resource_id: got %q; want vol-bare", f.ResourceID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity: got %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceEBS {
		t.Errorf("resource_type: got %q; want EBS_VOLUME", f.ResourceType)
	}
	if f.Region != "us-east-1" {
		t.Errorf("region: got %q; want us-east-1", f.Region)
	}
}

func TestEBSUnencryptedRule_NoVolumes(t *testing.T) {
	ctx := RuleContext{
		AccountID:  "123",
		RegionData: &models.RegionData{Region: "us-east-1"},
	}
	findings := EBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings with no volumes, got %d", len(findings))
	}
}

func TestEBSUnencryptedRule_MixedVolumes(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.RegionData{
			Region: "eu-west-1",
			EBSVolumes: []models.EBSVolume{
				{VolumeID: "vol-enc", Encrypted: true},
				{VolumeID: "vol-a", Encrypted: false},
				{VolumeID: "vol-b", Encrypted: false},
			},
		},
	}
	findings := EBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("want 2 findings for 2 unencrypted volumes, got %d", len(findings))
	}
}
