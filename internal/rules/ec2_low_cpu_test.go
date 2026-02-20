package rules

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

func TestEC2LowCPURule_IDAndName(t *testing.T) {
	r := EC2LowCPURule{}
	if r.ID() != "EC2_LOW_CPU" {
		t.Errorf("ID = %q; want EC2_LOW_CPU", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name must not be empty")
	}
}

func TestEC2LowCPURule_NilRegionData(t *testing.T) {
	if got := (EC2LowCPURule{}).Evaluate(RuleContext{}); got != nil {
		t.Errorf("expected nil for nil RegionData, got len=%d", len(got))
	}
}

func TestEC2LowCPURule_Evaluate(t *testing.T) {
	const (
		account = "111122223333"
		profile = "test"
		region  = "us-east-1"
	)

	makeCtx := func(instances ...models.EC2Instance) RuleContext {
		return RuleContext{
			AccountID: account,
			Profile:   profile,
			RegionData: &models.RegionData{
				Region:       region,
				EC2Instances: instances,
			},
		}
	}

	t.Run("non-running states are not flagged", func(t *testing.T) {
		for _, state := range []string{"stopped", "terminated", "pending", "shutting-down"} {
			state := state
			t.Run(state, func(t *testing.T) {
				ctx := makeCtx(models.EC2Instance{
					InstanceID:    "i-1",
					Region:        region,
					InstanceType:  "t3.medium",
					State:         state,
					AvgCPUPercent: 5.0,
				})
				if got := (EC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
					t.Errorf("state=%q: expected 0 findings, got %d", state, len(got))
				}
			})
		}
	})

	t.Run("zero AvgCPUPercent is skipped (no CloudWatch data)", func(t *testing.T) {
		ctx := makeCtx(models.EC2Instance{
			InstanceID:    "i-1",
			Region:        region,
			InstanceType:  "m5.large",
			State:         "running",
			AvgCPUPercent: 0.0,
		})
		if got := (EC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("expected 0 findings for zero CPU (no CW data), got %d", len(got))
		}
	})

	t.Run("CPU at threshold is not flagged", func(t *testing.T) {
		ctx := makeCtx(models.EC2Instance{
			InstanceID:    "i-1",
			Region:        region,
			InstanceType:  "m5.large",
			State:         "running",
			AvgCPUPercent: 10.0, // exactly at threshold — should not fire
		})
		if got := (EC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("CPU=10.0 (at threshold): expected 0 findings, got %d", len(got))
		}
	})

	t.Run("CPU above threshold is not flagged", func(t *testing.T) {
		ctx := makeCtx(models.EC2Instance{
			InstanceID:    "i-1",
			Region:        region,
			InstanceType:  "m5.large",
			State:         "running",
			AvgCPUPercent: 50.0,
		})
		if got := (EC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("CPU=50.0: expected 0 findings, got %d", len(got))
		}
	})

	t.Run("running instance with low CPU is flagged with correct fields", func(t *testing.T) {
		inst := models.EC2Instance{
			InstanceID:    "i-abc123",
			Region:        region,
			InstanceType:  "m5.large",
			State:         "running",
			AvgCPUPercent: 3.5,
		}
		findings := (EC2LowCPURule{}).Evaluate(makeCtx(inst))
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		f := findings[0]

		if want := "EC2_LOW_CPU-i-abc123"; f.ID != want {
			t.Errorf("ID = %q; want %q", f.ID, want)
		}
		if f.RuleID != "EC2_LOW_CPU" {
			t.Errorf("RuleID = %q; want EC2_LOW_CPU", f.RuleID)
		}
		if f.ResourceID != "i-abc123" {
			t.Errorf("ResourceID = %q; want i-abc123", f.ResourceID)
		}
		if f.ResourceType != models.ResourceEC2 {
			t.Errorf("ResourceType = %q; want %q", f.ResourceType, models.ResourceEC2)
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
		if f.EstimatedMonthlySavings != 30.00 {
			t.Errorf("EstimatedMonthlySavings = %.4f; want 30.00", f.EstimatedMonthlySavings)
		}
		if f.Metadata["instance_type"] != "m5.large" {
			t.Errorf("Metadata[instance_type] = %v; want m5.large", f.Metadata["instance_type"])
		}
		if f.Metadata["avg_cpu_percent"] != 3.5 {
			t.Errorf("Metadata[avg_cpu_percent] = %v; want 3.5", f.Metadata["avg_cpu_percent"])
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

	t.Run("CPU just below threshold is flagged", func(t *testing.T) {
		ctx := makeCtx(models.EC2Instance{
			InstanceID:    "i-1",
			Region:        region,
			InstanceType:  "t3.medium",
			State:         "running",
			AvgCPUPercent: 9.9,
		})
		if got := (EC2LowCPURule{}).Evaluate(ctx); len(got) != 1 {
			t.Errorf("CPU=9.9 (just below threshold): want 1 finding, got %d", len(got))
		}
	})

	t.Run("only low-CPU running instances flagged from mixed set", func(t *testing.T) {
		ctx := makeCtx(
			models.EC2Instance{InstanceID: "i-1", Region: region, InstanceType: "m5.large", State: "running", AvgCPUPercent: 5.0},  // flagged
			models.EC2Instance{InstanceID: "i-2", Region: region, InstanceType: "m5.large", State: "running", AvgCPUPercent: 0.0},  // skipped: no CW data
			models.EC2Instance{InstanceID: "i-3", Region: region, InstanceType: "m5.large", State: "running", AvgCPUPercent: 50.0}, // skipped: high CPU
			models.EC2Instance{InstanceID: "i-4", Region: region, InstanceType: "m5.large", State: "stopped", AvgCPUPercent: 3.0},  // skipped: not running
			models.EC2Instance{InstanceID: "i-5", Region: region, InstanceType: "t3.small", State: "running", AvgCPUPercent: 1.5},  // flagged
		)
		findings := (EC2LowCPURule{}).Evaluate(ctx)
		if len(findings) != 2 {
			t.Fatalf("want 2 findings, got %d", len(findings))
		}
		want := map[string]bool{"i-1": true, "i-5": true}
		for _, f := range findings {
			if !want[f.ResourceID] {
				t.Errorf("unexpected ResourceID %q in findings", f.ResourceID)
			}
		}
	})
}
