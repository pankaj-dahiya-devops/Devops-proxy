package models

// SecurityData holds raw security posture data collected from an AWS account.
// S3 buckets, IAM users, and root account info are global (account-level).
// SecurityGroupRules are aggregated from all audited regions; each entry
// carries its Region so security rules can emit correctly attributed findings.
type SecurityData struct {
	Buckets            []S3Bucket          `json:"buckets"`
	SecurityGroupRules []SecurityGroupRule `json:"security_group_rules"`
	IAMUsers           []IAMUser           `json:"iam_users"`
	Root               RootAccountInfo     `json:"root"`
}

// S3Bucket represents an S3 bucket and its security attributes.
// Public is true when GetBucketPolicyStatus reports IsPublic == true,
// meaning the bucket policy grants public access. Buckets without a policy
// and buckets with a non-public policy have Public == false.
// DefaultEncryptionEnabled is true when GetBucketEncryption returns a valid
// SSE configuration; false when no configuration exists or on any error.
type S3Bucket struct {
	Name                     string `json:"name"`
	Public                   bool   `json:"public"`
	DefaultEncryptionEnabled bool   `json:"default_encryption_enabled"`
}

// SecurityGroupRule represents a single inbound rule in an EC2 security group.
// Region carries the AWS region of the security group so that findings can be
// attributed to the correct region.
type SecurityGroupRule struct {
	GroupID string `json:"group_id"`
	Port    int    `json:"port"`
	CIDR    string `json:"cidr"`
	Region  string `json:"region"`
}

// IAMUser represents an IAM user and its relevant security attributes.
// HasLoginProfile is true when the user has a console password (login profile),
// meaning the user can sign in to the AWS Management Console.
// API-only users that have no login profile have HasLoginProfile == false and
// should not be flagged for missing MFA.
type IAMUser struct {
	UserName        string `json:"user_name"`
	MFAEnabled      bool   `json:"mfa_enabled"`
	HasLoginProfile bool   `json:"has_login_profile"`
}

// RootAccountInfo captures relevant security attributes of the AWS root account.
type RootAccountInfo struct {
	HasAccessKeys bool `json:"has_access_keys"`
}
