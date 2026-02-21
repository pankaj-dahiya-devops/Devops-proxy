package rules

import (
	"fmt"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// S3PublicBucketRule flags S3 buckets that do not have all four public-access
// block settings enabled. A public S3 bucket risks unintended data exposure.
type S3PublicBucketRule struct{}

func (r S3PublicBucketRule) ID() string   { return "S3_PUBLIC_BUCKET" }
func (r S3PublicBucketRule) Name() string { return "S3 Bucket With Public Access" }

// Evaluate returns one HIGH finding per S3 bucket where Public == true.
// Security rules read ctx.RegionData.Security which is populated by the
// security collector with account-level data.
func (r S3PublicBucketRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	var findings []models.Finding
	for _, b := range ctx.RegionData.Security.Buckets {
		if !b.Public {
			continue
		}
		findings = append(findings, models.Finding{
			ID:              fmt.Sprintf("%s-%s", r.ID(), b.Name),
			RuleID:          r.ID(),
			ResourceID:      b.Name,
			ResourceType:    models.ResourceS3Bucket,
			Region:          "global",
			AccountID:       ctx.AccountID,
			Profile:         ctx.Profile,
			Severity:        models.SeverityHigh,
			Explanation:     "S3 bucket does not have all Block Public Access settings enabled.",
			Recommendation:  "Enable all four S3 Block Public Access settings at the bucket or account level.",
			DetectedAt:      time.Now().UTC(),
		})
	}
	return findings
}
