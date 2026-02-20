package rules

import (
	"fmt"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

const (
	ebsUnattachedRuleID = "EBS_UNATTACHED"
	// ebsPricePerGBMonth is a conservative placeholder for gp2/gp3 pricing.
	// $0.08/GB-month covers gp2 in most regions; adjust when a pricing service
	// is available.
	ebsPricePerGBMonth = 0.08
)

// EBSUnattachedRule flags EBS volumes that are not attached to any instance.
// An unattached volume in the "available" state incurs storage charges with
// no workload benefit.
type EBSUnattachedRule struct{}

func (r EBSUnattachedRule) ID() string   { return ebsUnattachedRuleID }
func (r EBSUnattachedRule) Name() string { return "Unattached EBS Volume" }

// Evaluate iterates all EBS volumes in ctx.RegionData and returns one Finding
// per volume where Attached == false and State == "available".
func (r EBSUnattachedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, vol := range ctx.RegionData.EBSVolumes {
		if vol.Attached || vol.State != "available" {
			continue
		}

		savings := float64(vol.SizeGB) * ebsPricePerGBMonth

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", ebsUnattachedRuleID, vol.VolumeID),
			RuleID:                  ebsUnattachedRuleID,
			ResourceID:              vol.VolumeID,
			ResourceType:            models.ResourceEBS,
			Region:                  vol.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                models.SeverityMedium,
			EstimatedMonthlySavings: savings,
			Explanation:             "EBS volume is unattached.",
			Recommendation:          "Delete or attach the volume.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"volume_type": vol.VolumeType,
				"size_gb":     vol.SizeGB,
			},
		})
	}
	return findings
}
