package eks

import (
	"context"

	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// eksAPIClient is the subset of EKS API operations used by the collector.
// Using a narrow interface instead of the full SDK client makes unit testing
// trivial: create a struct that satisfies the interface and return canned data.
type eksAPIClient interface {
	DescribeCluster(
		ctx context.Context,
		params *awseks.DescribeClusterInput,
		optFns ...func(*awseks.Options),
	) (*awseks.DescribeClusterOutput, error)

	ListNodegroups(
		ctx context.Context,
		params *awseks.ListNodegroupsInput,
		optFns ...func(*awseks.Options),
	) (*awseks.ListNodegroupsOutput, error)

	DescribeNodegroup(
		ctx context.Context,
		params *awseks.DescribeNodegroupInput,
		optFns ...func(*awseks.Options),
	) (*awseks.DescribeNodegroupOutput, error)
}

// ec2LaunchTemplateClient is the subset of EC2 operations used to resolve
// the IMDSv2 (HttpTokens) setting from a nodegroup's launch template.
type ec2LaunchTemplateClient interface {
	DescribeLaunchTemplateVersions(
		ctx context.Context,
		params *ec2.DescribeLaunchTemplateVersionsInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
}
