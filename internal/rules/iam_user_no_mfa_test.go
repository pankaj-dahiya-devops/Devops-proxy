package rules

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

func TestIAMUserWithoutMFARule_ID(t *testing.T) {
	r := IAMUserWithoutMFARule{}
	if r.ID() != "IAM_USER_NO_MFA" {
		t.Error("unexpected rule ID")
	}
}

func TestIAMUserWithoutMFARule_NilRegionData(t *testing.T) {
	findings := IAMUserWithoutMFARule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

func TestIAMUserWithoutMFARule_AllMFAEnabled(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		Profile:   "test",
		RegionData: &models.RegionData{
			Security: models.SecurityData{
				IAMUsers: []models.IAMUser{
					{UserName: "alice", MFAEnabled: true, HasLoginProfile: true},
					{UserName: "bob", MFAEnabled: true, HasLoginProfile: true},
				},
			},
		},
	}
	findings := IAMUserWithoutMFARule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings when all console users have MFA, got %d", len(findings))
	}
}

func TestIAMUserWithoutMFARule_MissingMFA(t *testing.T) {
	// bob has console access but no MFA → flagged.
	ctx := RuleContext{
		AccountID: "123",
		Profile:   "test",
		RegionData: &models.RegionData{
			Security: models.SecurityData{
				IAMUsers: []models.IAMUser{
					{UserName: "alice", MFAEnabled: true, HasLoginProfile: true},
					{UserName: "bob", MFAEnabled: false, HasLoginProfile: true},
				},
			},
		},
	}
	findings := IAMUserWithoutMFARule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].ResourceID != "bob" {
		t.Errorf("resource_id: got %q; want bob", findings[0].ResourceID)
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("severity: got %q; want MEDIUM", findings[0].Severity)
	}
	if findings[0].ResourceType != models.ResourceIAMUser {
		t.Errorf("resource_type: got %q; want IAM_USER", findings[0].ResourceType)
	}
	if findings[0].Region != "global" {
		t.Errorf("region: got %q; want global", findings[0].Region)
	}
}

func TestIAMUserWithoutMFARule_NoUsers(t *testing.T) {
	ctx := RuleContext{
		AccountID:  "123",
		RegionData: &models.RegionData{Security: models.SecurityData{}},
	}
	findings := IAMUserWithoutMFARule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings with no users, got %d", len(findings))
	}
}

// TestIAMUserWithoutMFARule_APIOnlyUser verifies that users without a login
// profile (API-only users) are not flagged even if they have no MFA device.
func TestIAMUserWithoutMFARule_APIOnlyUser(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.RegionData{
			Security: models.SecurityData{
				IAMUsers: []models.IAMUser{
					{UserName: "svc-deploy", MFAEnabled: false, HasLoginProfile: false},
					{UserName: "svc-readonly", MFAEnabled: false, HasLoginProfile: false},
				},
			},
		},
	}
	findings := IAMUserWithoutMFARule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for API-only users (no login profile), got %d", len(findings))
	}
}

// TestIAMUserWithoutMFARule_ConsoleUserNoMFA verifies that a user with a
// console login profile but no MFA device is flagged.
func TestIAMUserWithoutMFARule_ConsoleUserNoMFA(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		Profile:   "test",
		RegionData: &models.RegionData{
			Security: models.SecurityData{
				IAMUsers: []models.IAMUser{
					// API-only: should not be flagged
					{UserName: "svc-bot", MFAEnabled: false, HasLoginProfile: false},
					// Console user with MFA: should not be flagged
					{UserName: "admin", MFAEnabled: true, HasLoginProfile: true},
					// Console user without MFA: MUST be flagged
					{UserName: "developer", MFAEnabled: false, HasLoginProfile: true},
				},
			},
		},
	}
	findings := IAMUserWithoutMFARule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding for console user without MFA, got %d", len(findings))
	}
	if findings[0].ResourceID != "developer" {
		t.Errorf("resource_id: got %q; want developer", findings[0].ResourceID)
	}
}

func TestIAMUserWithoutMFARule_MultipleMissing(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.RegionData{
			Security: models.SecurityData{
				IAMUsers: []models.IAMUser{
					{UserName: "alice", MFAEnabled: false, HasLoginProfile: true},
					{UserName: "bob", MFAEnabled: false, HasLoginProfile: true},
					{UserName: "carol", MFAEnabled: true, HasLoginProfile: true},
				},
			},
		},
	}
	findings := IAMUserWithoutMFARule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("want 2 findings, got %d", len(findings))
	}
}
