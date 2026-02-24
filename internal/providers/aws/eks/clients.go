// Package eks provides an AWS EKS data collector for Kubernetes governance rules.
// It fetches control-plane configuration (endpoint access, logging, OIDC) from
// the AWS EKS DescribeCluster API and exposes it as internal models.
package eks

import (
	"context"

	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
)

// eksAPIClient is the narrow EKS API surface consumed by this package.
// Only DescribeCluster is needed; the full SDK client satisfies this interface.
type eksAPIClient interface {
	DescribeCluster(ctx context.Context, params *awseks.DescribeClusterInput, optFns ...func(*awseks.Options)) (*awseks.DescribeClusterOutput, error)
}
