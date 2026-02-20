package rules

import (
	"fmt"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

const (
	ec2LowCPURuleID = "EC2_LOW_CPU"

	// ec2LowCPUThresholdPercent is the average CPU below which an instance is
	// considered underutilised. 10% is a conservative threshold that catches
	// clearly idle machines while avoiding noisy false positives.
	ec2LowCPUThresholdPercent = 10.0

	// ec2LowCPUSavingsUSD is a placeholder for ~30% of a typical general-purpose
	// instance monthly on-demand cost ($100 baseline → $30 saving).
	// Replace with real pricing data when a pricing service is available.
	ec2LowCPUSavingsUSD = 30.0
)

// EC2LowCPURule flags running EC2 instances whose 30-day average CPU
// utilisation is below the threshold, indicating the instance is likely
// overprovisioned for its actual workload.
//
// Instances with AvgCPUPercent == 0 are skipped: 0 means CloudWatch data
// was unavailable (non-fatal collection failure), not that CPU is truly zero.
type EC2LowCPURule struct{}

func (r EC2LowCPURule) ID() string   { return ec2LowCPURuleID }
func (r EC2LowCPURule) Name() string { return "Low CPU EC2 Instance" }

// Evaluate returns one Finding per running instance whose AvgCPUPercent is
// greater than 0 (data available) and below ec2LowCPUThresholdPercent.
func (r EC2LowCPURule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, inst := range ctx.RegionData.EC2Instances {
		if inst.State != "running" {
			continue
		}
		// 0 means CloudWatch had no data; skip to avoid false positives.
		if inst.AvgCPUPercent == 0 {
			continue
		}
		if inst.AvgCPUPercent >= ec2LowCPUThresholdPercent {
			continue
		}

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", ec2LowCPURuleID, inst.InstanceID),
			RuleID:                  ec2LowCPURuleID,
			ResourceID:              inst.InstanceID,
			ResourceType:            models.ResourceEC2,
			Region:                  inst.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                models.SeverityMedium,
			EstimatedMonthlySavings: ec2LowCPUSavingsUSD,
			Explanation:             "Instance type may be overprovisioned.",
			Recommendation:          "Review instance sizing and consider downsizing or Savings Plan.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"instance_type":   inst.InstanceType,
				"avg_cpu_percent": inst.AvgCPUPercent,
			},
		})
	}
	return findings
}
