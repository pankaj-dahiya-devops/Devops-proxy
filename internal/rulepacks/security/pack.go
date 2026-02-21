// Package security provides the security audit rule pack.
// It groups all security rules into a single New() function that the CLI
// wires into a DefaultRuleRegistry before invoking the security engine.
//
// Convention: every rule pack lives in internal/rulepacks/<domain>/pack.go
// and exposes a single New() func returning []rules.Rule.
// Future security rules (e.g. CloudTrail disabled, GuardDuty not enabled)
// should be added to the slice returned by New().
package security

import "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"

// New returns the default security audit rule pack.
func New() []rules.Rule {
	return []rules.Rule{
		rules.RootAccessKeyExistsRule{},   // CRITICAL: root access keys present
		rules.S3PublicBucketRule{},         // HIGH:     S3 bucket lacks public access block
		rules.SecurityGroupOpenSSHRule{},   // HIGH:     security group exposes SSH to internet
		rules.IAMUserWithoutMFARule{},      // MEDIUM:   IAM user has no MFA device
	}
}
