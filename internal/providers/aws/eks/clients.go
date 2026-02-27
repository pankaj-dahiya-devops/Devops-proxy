// Package eks provides an AWS EKS data collector for Kubernetes governance rules.
// It fetches control-plane configuration (endpoint access, logging, OIDC) from
// the AWS EKS DescribeCluster API and exposes it as internal models.
package eks

import (
	"context"

	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
)

// eksAPIClient is the narrow EKS API surface consumed by this package.
// DescribeCluster fetches cluster config; ListNodegroups + DescribeNodegroup
// are used to resolve node group IAM roles for Phase 5B governance.
type eksAPIClient interface {
	DescribeCluster(ctx context.Context, params *awseks.DescribeClusterInput, optFns ...func(*awseks.Options)) (*awseks.DescribeClusterOutput, error)
	ListNodegroups(ctx context.Context, params *awseks.ListNodegroupsInput, optFns ...func(*awseks.Options)) (*awseks.ListNodegroupsOutput, error)
	DescribeNodegroup(ctx context.Context, params *awseks.DescribeNodegroupInput, optFns ...func(*awseks.Options)) (*awseks.DescribeNodegroupOutput, error)
}

// iamAPIClient is the narrow IAM API surface consumed by EKS identity governance.
// Used to verify the IAM OIDC provider (Phase 5B) and inspect node role policies.
type iamAPIClient interface {
	ListOpenIDConnectProviders(ctx context.Context, params *awsiam.ListOpenIDConnectProvidersInput, optFns ...func(*awsiam.Options)) (*awsiam.ListOpenIDConnectProvidersOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *awsiam.ListAttachedRolePoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, params *awsiam.ListRolePoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *awsiam.GetRolePolicyInput, optFns ...func(*awsiam.Options)) (*awsiam.GetRolePolicyOutput, error)
}
