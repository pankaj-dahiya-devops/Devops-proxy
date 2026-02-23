// Package aws_security provides the AWS security audit rule pack.
// It groups all AWS security rules into a single New() function that the CLI
// wires into a DefaultRuleRegistry before invoking the security engine.
//
// Convention: every rule pack lives in internal/rulepacks/<domain>/pack.go
// and exposes a single New() func returning []rules.Rule.
// Future AWS security rules (e.g. CloudTrail disabled, GuardDuty not enabled)
// should be added to the slice returned by New().
package aws_security

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the default AWS security audit rule pack.
func New() []rules.Rule {
	return []rules.Rule{
		rules.AWSRootAccessKeyExistsRule{},   // CRITICAL: root access keys present
		rules.AWSS3PublicBucketRule{},         // HIGH:     S3 bucket lacks public access block
		rules.AWSSecurityGroupOpenSSHRule{},   // HIGH:     security group exposes SSH to internet
		rules.AWSIAMUserWithoutMFARule{},      // MEDIUM:   IAM user has no MFA device
	}
}
