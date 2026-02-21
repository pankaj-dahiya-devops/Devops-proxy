package rules

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

func TestRDSUnencryptedRule_ID(t *testing.T) {
	r := RDSUnencryptedRule{}
	if r.ID() != "RDS_UNENCRYPTED" {
		t.Error("unexpected rule ID")
	}
}

func TestRDSUnencryptedRule_NilRegionData(t *testing.T) {
	findings := RDSUnencryptedRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

func TestRDSUnencryptedRule_EncryptedInstance_NoFinding(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.RegionData{
			Region: "us-east-1",
			RDSInstances: []models.RDSInstance{
				{DBInstanceID: "db-enc", Engine: "mysql", Status: "available", StorageEncrypted: true},
			},
		},
	}
	findings := RDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for encrypted RDS, got %d", len(findings))
	}
}

func TestRDSUnencryptedRule_UnencryptedInstance_CriticalSeverity(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "prod",
		RegionData: &models.RegionData{
			Region: "us-east-1",
			RDSInstances: []models.RDSInstance{
				{DBInstanceID: "db-prod", Engine: "postgres", DBInstanceClass: "db.t3.medium", Status: "available", StorageEncrypted: false},
			},
		},
	}
	findings := RDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ResourceID != "db-prod" {
		t.Errorf("resource_id: got %q; want db-prod", f.ResourceID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity: got %q; want CRITICAL", f.Severity)
	}
	if f.ResourceType != models.ResourceRDS {
		t.Errorf("resource_type: got %q; want RDS_INSTANCE", f.ResourceType)
	}
	if f.Region != "us-east-1" {
		t.Errorf("region: got %q; want us-east-1", f.Region)
	}
}

func TestRDSUnencryptedRule_NoInstances(t *testing.T) {
	ctx := RuleContext{
		AccountID:  "123",
		RegionData: &models.RegionData{Region: "us-west-2"},
	}
	findings := RDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings with no instances, got %d", len(findings))
	}
}

func TestRDSUnencryptedRule_MultipleUnencrypted(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.RegionData{
			Region: "ap-southeast-1",
			RDSInstances: []models.RDSInstance{
				{DBInstanceID: "db-a", StorageEncrypted: false},
				{DBInstanceID: "db-b", StorageEncrypted: true},
				{DBInstanceID: "db-c", StorageEncrypted: false},
			},
		},
	}
	findings := RDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("want 2 findings, got %d", len(findings))
	}
}
