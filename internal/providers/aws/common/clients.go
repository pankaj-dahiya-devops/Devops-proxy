package common

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	ce "github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ---------------------------------------------------------------------------
// Per-service client interfaces
//
// Each interface covers only the operations used by this project. Using narrow
// interfaces instead of the full SDK clients makes mocking in unit tests
// trivial: create a struct that satisfies the interface and return canned data.
// ---------------------------------------------------------------------------

// STSClient is the subset of STS operations used by the loader.
type STSClient interface {
	GetCallerIdentity(
		ctx context.Context,
		params *sts.GetCallerIdentityInput,
		optFns ...func(*sts.Options),
	) (*sts.GetCallerIdentityOutput, error)
}

// EC2RegionClient is the subset of EC2 operations used for region discovery.
// Cost-collection EC2 operations are defined in the cost package.
type EC2RegionClient interface {
	DescribeRegions(
		ctx context.Context,
		params *ec2.DescribeRegionsInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DescribeRegionsOutput, error)
}

// CostExplorerClient covers the Cost Explorer operations used during cost
// collection. Placed here so the cost package can refer to it without
// importing the SDK directly in its interface layer.
type CostExplorerClient interface {
	GetCostAndUsage(
		ctx context.Context,
		params *ce.GetCostAndUsageInput,
		optFns ...func(*ce.Options),
	) (*ce.GetCostAndUsageOutput, error)

	GetSavingsPlansCoverage(
		ctx context.Context,
		params *ce.GetSavingsPlansCoverageInput,
		optFns ...func(*ce.Options),
	) (*ce.GetSavingsPlansCoverageOutput, error)
}

// RDSClient covers the RDS operations used during cost collection.
type RDSClient interface {
	DescribeDBInstances(
		ctx context.Context,
		params *rds.DescribeDBInstancesInput,
		optFns ...func(*rds.Options),
	) (*rds.DescribeDBInstancesOutput, error)
}

// ELBv2Client covers the Elastic Load Balancing v2 operations used during
// cost collection.
type ELBv2Client interface {
	DescribeLoadBalancers(
		ctx context.Context,
		params *elbv2.DescribeLoadBalancersInput,
		optFns ...func(*elbv2.Options),
	) (*elbv2.DescribeLoadBalancersOutput, error)
}

// ---------------------------------------------------------------------------
// ClientSet and ClientFactory
// ---------------------------------------------------------------------------

// ClientSet holds fully initialised AWS service clients for a given profile
// and region. All fields are interfaces so they can be replaced with mocks in
// tests without importing the AWS SDK in test files.
type ClientSet struct {
	STS          STSClient
	EC2          EC2RegionClient
	CostExplorer CostExplorerClient
	RDS          RDSClient
	ELBv2        ELBv2Client
}

// ClientFactory creates a ClientSet from an aws.Config.
// Swap this in tests to inject mock clients.
type ClientFactory func(cfg aws.Config) *ClientSet

// NewClientSet is the production ClientFactory. It constructs real AWS SDK
// clients from cfg. Cost Explorer is always pointed at us-east-1 because it
// is a global service only reachable in that region.
func NewClientSet(cfg aws.Config) *ClientSet {
	// Cost Explorer is a global service; it must be called against us-east-1.
	ceCfg := cfg
	ceCfg.Region = "us-east-1"

	return &ClientSet{
		STS:          sts.NewFromConfig(cfg),
		EC2:          ec2.NewFromConfig(cfg),
		CostExplorer: ce.NewFromConfig(ceCfg),
		RDS:          rds.NewFromConfig(cfg),
		ELBv2:        elbv2.NewFromConfig(cfg),
	}
}
