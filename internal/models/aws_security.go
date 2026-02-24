package models

// AWSSecurityData holds raw security posture data collected from an AWS account.
// S3 buckets, IAM users, root account info, and CloudTrail are global (account-level).
// AWSSecurityGroupRules, AWSGuardDutyStatus, and AWSConfigStatus are aggregated from
// all audited regions; each entry carries its Region for accurate finding attribution.
type AWSSecurityData struct {
	Buckets            []AWSS3Bucket          `json:"buckets"`
	SecurityGroupRules []AWSSecurityGroupRule `json:"security_group_rules"`
	IAMUsers           []AWSIAMUser           `json:"iam_users"`
	Root               AWSRootAccountInfo     `json:"root"`
	CloudTrail         AWSCloudTrailStatus    `json:"cloud_trail"`
	GuardDuty          []AWSGuardDutyStatus   `json:"guard_duty"`
	Config             []AWSConfigStatus      `json:"config"`
}

// AWSS3Bucket represents an S3 bucket and its security attributes.
// Public is true when GetBucketPolicyStatus reports IsPublic == true,
// meaning the bucket policy grants public access. Buckets without a policy
// and buckets with a non-public policy have Public == false.
// DefaultEncryptionEnabled is true when GetBucketEncryption returns a valid
// SSE configuration; false when no configuration exists or on any error.
type AWSS3Bucket struct {
	Name                     string `json:"name"`
	Public                   bool   `json:"public"`
	DefaultEncryptionEnabled bool   `json:"default_encryption_enabled"`
}

// AWSSecurityGroupRule represents a single inbound rule in an EC2 security group.
// Region carries the AWS region of the security group so that findings can be
// attributed to the correct region.
type AWSSecurityGroupRule struct {
	GroupID string `json:"group_id"`
	Port    int    `json:"port"`
	CIDR    string `json:"cidr"`
	Region  string `json:"region"`
}

// AWSIAMUser represents an IAM user and its relevant security attributes.
// HasLoginProfile is true when the user has a console password (login profile),
// meaning the user can sign in to the AWS Management Console.
// API-only users that have no login profile have HasLoginProfile == false and
// should not be flagged for missing MFA.
type AWSIAMUser struct {
	UserName        string `json:"user_name"`
	MFAEnabled      bool   `json:"mfa_enabled"`
	HasLoginProfile bool   `json:"has_login_profile"`
}

// AWSRootAccountInfo captures relevant security attributes of the AWS root account.
// DataAvailable is false when GetAccountSummary failed; rules must check this
// field before evaluating security posture to avoid false positives on collection
// failures.
type AWSRootAccountInfo struct {
	HasAccessKeys bool `json:"has_access_keys"`
	MFAEnabled    bool `json:"mfa_enabled"`
	DataAvailable bool `json:"data_available"`
}

// AWSCloudTrailStatus holds the CloudTrail configuration for an AWS account.
// HasMultiRegionTrail is true when at least one trail is configured to record
// events across all regions (IsMultiRegionTrail == true in AWS SDK response).
type AWSCloudTrailStatus struct {
	HasMultiRegionTrail bool `json:"has_multi_region_trail"`
}

// AWSGuardDutyStatus holds the GuardDuty detector status for a single region.
// Enabled is true when at least one detector exists and is in ENABLED state.
type AWSGuardDutyStatus struct {
	Region  string `json:"region"`
	Enabled bool   `json:"enabled"`
}

// AWSConfigStatus holds the AWS Config recorder status for a single region.
// Enabled is true when at least one configuration recorder exists and is
// actively recording (Recording == true in RecorderStatus).
type AWSConfigStatus struct {
	Region  string `json:"region"`
	Enabled bool   `json:"enabled"`
}
