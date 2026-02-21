// Package awssecurity implements the AWS security data collector.
// It collects S3, IAM, root account, and EC2 security group data for use
// by the security rule engine.
//
// Canonical data types (S3Bucket, SecurityGroupRule, IAMUser, RootAccountInfo,
// SecurityData) are defined in internal/models/security.go so they are shared
// across the engine, rules, and provider layers without circular imports.
package awssecurity

// CollectOptions configures a per-region security collection call.
// It is used internally by the security collector.
type CollectOptions struct {
	Region    string
	AccountID string
	Profile   string
}
