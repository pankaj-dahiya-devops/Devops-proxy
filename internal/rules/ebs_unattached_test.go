package rules

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

func TestEBSUnattachedRule_IDAndName(t *testing.T) {
	r := EBSUnattachedRule{}
	if r.ID() != "EBS_UNATTACHED" {
		t.Errorf("ID = %q; want EBS_UNATTACHED", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name must not be empty")
	}
}

func TestEBSUnattachedRule_NilRegionData(t *testing.T) {
	if got := (EBSUnattachedRule{}).Evaluate(RuleContext{}); got != nil {
		t.Errorf("expected nil for nil RegionData, got len=%d", len(got))
	}
}

func TestEBSUnattachedRule_Evaluate(t *testing.T) {
	const (
		account = "111122223333"
		profile = "test"
		region  = "us-east-1"
	)

	makeCtx := func(vols ...models.EBSVolume) RuleContext {
		return RuleContext{
			AccountID: account,
			Profile:   profile,
			RegionData: &models.RegionData{
				Region:     region,
				EBSVolumes: vols,
			},
		}
	}

	t.Run("attached volume is not flagged", func(t *testing.T) {
		ctx := makeCtx(models.EBSVolume{
			VolumeID: "vol-1", Region: region, VolumeType: "gp2",
			SizeGB: 100, State: "in-use", Attached: true,
		})
		if got := (EBSUnattachedRule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("expected 0 findings, got %d", len(got))
		}
	})

	t.Run("detached non-available states are not flagged", func(t *testing.T) {
		for _, state := range []string{"deleting", "deleted", "error", "creating"} {
			state := state
			t.Run(state, func(t *testing.T) {
				ctx := makeCtx(models.EBSVolume{
					VolumeID: "vol-1", Region: region, VolumeType: "gp2",
					SizeGB: 100, State: state, Attached: false,
				})
				if got := (EBSUnattachedRule{}).Evaluate(ctx); len(got) != 0 {
					t.Errorf("state=%q: expected 0 findings, got %d", state, len(got))
				}
			})
		}
	})

	t.Run("detached available volume is flagged with correct fields", func(t *testing.T) {
		vol := models.EBSVolume{
			VolumeID: "vol-abc", Region: region, VolumeType: "gp2",
			SizeGB: 100, State: "available", Attached: false,
		}
		findings := (EBSUnattachedRule{}).Evaluate(makeCtx(vol))
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		f := findings[0]

		if want := "EBS_UNATTACHED-vol-abc"; f.ID != want {
			t.Errorf("ID = %q; want %q", f.ID, want)
		}
		if f.RuleID != "EBS_UNATTACHED" {
			t.Errorf("RuleID = %q; want EBS_UNATTACHED", f.RuleID)
		}
		if f.ResourceID != "vol-abc" {
			t.Errorf("ResourceID = %q; want vol-abc", f.ResourceID)
		}
		if f.ResourceType != models.ResourceEBS {
			t.Errorf("ResourceType = %q; want %q", f.ResourceType, models.ResourceEBS)
		}
		if f.Severity != models.SeverityMedium {
			t.Errorf("Severity = %q; want MEDIUM", f.Severity)
		}
		if f.Region != region {
			t.Errorf("Region = %q; want %q", f.Region, region)
		}
		if f.AccountID != account {
			t.Errorf("AccountID = %q; want %q", f.AccountID, account)
		}
		if f.Profile != profile {
			t.Errorf("Profile = %q; want %q", f.Profile, profile)
		}
		if f.EstimatedMonthlySavings != 8.00 { // 100 * 0.08
			t.Errorf("EstimatedMonthlySavings = %.4f; want 8.00", f.EstimatedMonthlySavings)
		}
		if f.Metadata["volume_type"] != "gp2" {
			t.Errorf("Metadata[volume_type] = %v; want gp2", f.Metadata["volume_type"])
		}
		if f.Metadata["size_gb"] != int32(100) {
			t.Errorf("Metadata[size_gb] = %v (%T); want int32(100)", f.Metadata["size_gb"], f.Metadata["size_gb"])
		}
		if f.Explanation == "" {
			t.Error("Explanation must not be empty")
		}
		if f.Recommendation == "" {
			t.Error("Recommendation must not be empty")
		}
		if f.DetectedAt.IsZero() {
			t.Error("DetectedAt must not be zero")
		}
	})

	t.Run("savings are proportional to volume size", func(t *testing.T) {
		cases := []struct {
			sizeGB  int32
			wantUSD float64
		}{
			{50, 4.00},
			{200, 16.00},
			{1000, 80.00},
		}
		for _, tc := range cases {
			ctx := makeCtx(models.EBSVolume{
				VolumeID: "vol-x", Region: region, SizeGB: tc.sizeGB,
				State: "available", Attached: false,
			})
			findings := (EBSUnattachedRule{}).Evaluate(ctx)
			if len(findings) != 1 {
				t.Fatalf("sizeGB=%d: want 1 finding, got %d", tc.sizeGB, len(findings))
			}
			if findings[0].EstimatedMonthlySavings != tc.wantUSD {
				t.Errorf("sizeGB=%d: savings = %.2f; want %.2f",
					tc.sizeGB, findings[0].EstimatedMonthlySavings, tc.wantUSD)
			}
		}
	})

	t.Run("only unattached-available volumes flagged from mixed set", func(t *testing.T) {
		ctx := makeCtx(
			models.EBSVolume{VolumeID: "vol-1", Region: region, SizeGB: 10, State: "available", Attached: false}, // flagged
			models.EBSVolume{VolumeID: "vol-2", Region: region, SizeGB: 10, State: "in-use", Attached: true},    // not flagged
			models.EBSVolume{VolumeID: "vol-3", Region: region, SizeGB: 10, State: "deleting", Attached: false}, // not flagged
			models.EBSVolume{VolumeID: "vol-4", Region: region, SizeGB: 10, State: "available", Attached: false}, // flagged
		)
		findings := (EBSUnattachedRule{}).Evaluate(ctx)
		if len(findings) != 2 {
			t.Fatalf("want 2 findings, got %d", len(findings))
		}
		want := map[string]bool{"vol-1": true, "vol-4": true}
		for _, f := range findings {
			if !want[f.ResourceID] {
				t.Errorf("unexpected ResourceID %q in findings", f.ResourceID)
			}
		}
	})
}
