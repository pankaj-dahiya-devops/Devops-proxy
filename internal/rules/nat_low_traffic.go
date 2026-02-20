package rules

import (
	"fmt"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

const (
	natLowTrafficRuleID      = "NAT_LOW_TRAFFIC"
	natLowTrafficThresholdGB = 1.0

	// natLowTrafficSavingsUSD is the estimated monthly saving from deleting
	// an idle NAT Gateway. AWS charges ~$32/month per NAT ($0.045/hour) plus
	// data processing fees; the fixed hourly cost alone justifies removal.
	natLowTrafficSavingsUSD = 32.0
)

// NATLowTrafficRule flags available NAT Gateways whose total outbound traffic
// (BytesOutToDestination) is below 1 GB over the lookback period.
//
// A NAT Gateway with negligible traffic is almost certainly idle. The rule
// fires even when BytesProcessedGB == 0 because 0 bytes genuinely means no
// traffic passed through — unlike EC2 CPU where 0 means CloudWatch had no data.
type NATLowTrafficRule struct{}

func (r NATLowTrafficRule) ID() string   { return natLowTrafficRuleID }
func (r NATLowTrafficRule) Name() string { return "NAT Gateway Low Traffic" }

// Evaluate returns one Finding per available NAT Gateway whose
// BytesProcessedGB is strictly less than natLowTrafficThresholdGB.
func (r NATLowTrafficRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, ng := range ctx.RegionData.NATGateways {
		if ng.State != "available" {
			continue
		}
		if ng.BytesProcessedGB >= natLowTrafficThresholdGB {
			continue
		}

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", natLowTrafficRuleID, ng.NATGatewayID),
			RuleID:                  natLowTrafficRuleID,
			ResourceID:              ng.NATGatewayID,
			ResourceType:            models.ResourceNATGateway,
			Region:                  ng.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                models.SeverityHigh,
			EstimatedMonthlySavings: natLowTrafficSavingsUSD,
			Explanation:             "NAT Gateway has negligible traffic.",
			Recommendation:          "Delete NAT or consolidate egress via shared NAT.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"bytes_processed_gb": ng.BytesProcessedGB,
			},
		})
	}
	return findings
}
