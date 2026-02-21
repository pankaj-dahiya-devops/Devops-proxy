package rules

import (
	"fmt"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// S3DefaultEncryptionMissingRule flags S3 buckets that do not have server-side
// encryption configured as the default. Without default encryption, objects
// uploaded without explicit SSE settings are stored in plaintext.
type S3DefaultEncryptionMissingRule struct{}

func (r S3DefaultEncryptionMissingRule) ID() string {
	return "S3_DEFAULT_ENCRYPTION_MISSING"
}
func (r S3DefaultEncryptionMissingRule) Name() string {
	return "S3 Bucket Without Default Encryption"
}

// Evaluate returns one HIGH finding per S3 bucket where
// DefaultEncryptionEnabled == false.
func (r S3DefaultEncryptionMissingRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	var findings []models.Finding
	for _, b := range ctx.RegionData.Security.Buckets {
		if b.DefaultEncryptionEnabled {
			continue
		}
		findings = append(findings, models.Finding{
			ID:             fmt.Sprintf("%s-%s", r.ID(), b.Name),
			RuleID:         r.ID(),
			ResourceID:     b.Name,
			ResourceType:   models.ResourceS3Bucket,
			Region:         "global",
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityHigh,
			Explanation:    fmt.Sprintf("S3 bucket %q does not have server-side encryption enabled by default.", b.Name),
			Recommendation: "Enable S3 default encryption (SSE-S3 or SSE-KMS) so that all new objects are automatically encrypted at rest.",
			DetectedAt:     time.Now().UTC(),
		})
	}
	return findings
}
