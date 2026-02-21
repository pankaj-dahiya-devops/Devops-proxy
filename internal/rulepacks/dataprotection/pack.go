// Package dataprotection provides the data-protection rule pack.
// It groups encryption-at-rest checks for EBS volumes, RDS instances,
// and S3 buckets into a single registration call.
package dataprotection

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the complete set of data-protection rules ordered by severity:
// CRITICAL first (RDS), then HIGH (EBS, S3).
func New() []rules.Rule {
	return []rules.Rule{
		rules.RDSUnencryptedRule{},              // CRITICAL
		rules.EBSUnencryptedRule{},              // HIGH
		rules.S3DefaultEncryptionMissingRule{},  // HIGH
	}
}
