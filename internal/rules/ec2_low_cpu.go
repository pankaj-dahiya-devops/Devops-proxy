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

	// ec2LowCPUSavingsFraction is the fraction of the instance's actual monthly
	// cost estimated as recoverable by downsizing (~30% for one size-step down).
	ec2LowCPUSavingsFraction = 0.30
)

// EC2LowCPURule flags running EC2 instances whose 30-day average CPU
// utilisation is below the threshold, indicating the instance is likely
// overprovisioned for its actual workload.
//
// Instances with AvgCPUPercent == 0 are skipped: 0 means CloudWatch data
// was unavailable (non-fatal collection failure), not that CPU is truly zero.
//
// Instances with MonthlyCostUSD == 0 are skipped: 0 means Cost Explorer data
// was unavailable; savings cannot be estimated without a known cost baseline.
type EC2LowCPURule struct{}

func (r EC2LowCPURule) ID() string   { return ec2LowCPURuleID }
func (r EC2LowCPURule) Name() string { return "Low CPU EC2 Instance" }

// Evaluate returns one Finding per running instance whose AvgCPUPercent is
// greater than 0 (data available), below ec2LowCPUThresholdPercent, and whose
// MonthlyCostUSD is greater than 0 (cost data available from Cost Explorer).
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
		// 0 means Cost Explorer had no data; skip — savings cannot be estimated.
		if inst.MonthlyCostUSD == 0 {
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
			EstimatedMonthlySavings: inst.MonthlyCostUSD * ec2LowCPUSavingsFraction,
			Explanation:             "Instance type may be overprovisioned.",
			Recommendation:          "Review instance sizing and consider downsizing or Savings Plan.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"instance_type":    inst.InstanceType,
				"avg_cpu_percent":  inst.AvgCPUPercent,
				"monthly_cost_usd": inst.MonthlyCostUSD,
			},
		})
	}
	return findings
}
