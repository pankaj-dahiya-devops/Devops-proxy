package awssecurity

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	s3svc "github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3APIClient is the narrow S3 interface used by the security collector.
// It covers bucket listing, policy status inspection, and encryption status.
type s3APIClient interface {
	ListBuckets(ctx context.Context, params *s3svc.ListBucketsInput, optFns ...func(*s3svc.Options)) (*s3svc.ListBucketsOutput, error)
	GetBucketPolicyStatus(ctx context.Context, params *s3svc.GetBucketPolicyStatusInput, optFns ...func(*s3svc.Options)) (*s3svc.GetBucketPolicyStatusOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3svc.GetBucketEncryptionInput, optFns ...func(*s3svc.Options)) (*s3svc.GetBucketEncryptionOutput, error)
}

// ec2SecurityAPIClient is the narrow EC2 interface used for security group
// collection. Only DescribeSecurityGroups is required.
type ec2SecurityAPIClient interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2svc.DescribeSecurityGroupsInput, optFns ...func(*ec2svc.Options)) (*ec2svc.DescribeSecurityGroupsOutput, error)
}

// iamAPIClient is the narrow IAM interface used for user and account-level
// security data. It embeds ListUsersAPIClient so the SDK paginator can be
// used directly.
type iamAPIClient interface {
	iamsvc.ListUsersAPIClient
	ListMFADevices(ctx context.Context, params *iamsvc.ListMFADevicesInput, optFns ...func(*iamsvc.Options)) (*iamsvc.ListMFADevicesOutput, error)
	GetLoginProfile(ctx context.Context, params *iamsvc.GetLoginProfileInput, optFns ...func(*iamsvc.Options)) (*iamsvc.GetLoginProfileOutput, error)
	GetAccountSummary(ctx context.Context, params *iamsvc.GetAccountSummaryInput, optFns ...func(*iamsvc.Options)) (*iamsvc.GetAccountSummaryOutput, error)
}

// secClients bundles all AWS service clients used by the security collector.
type secClients struct {
	S3  s3APIClient
	EC2 ec2SecurityAPIClient
	IAM iamAPIClient
}

// secClientFactory creates secClients from an AWS config.
// Injection point: tests replace this with a function returning fake clients.
type secClientFactory func(cfg aws.Config) *secClients

// newDefaultSecClients creates production AWS SDK clients from the given config.
func newDefaultSecClients(cfg aws.Config) *secClients {
	return &secClients{
		S3:  s3svc.NewFromConfig(cfg),
		EC2: ec2svc.NewFromConfig(cfg),
		IAM: iamsvc.NewFromConfig(cfg),
	}
}
