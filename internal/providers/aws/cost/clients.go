package cost

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	ce "github.com/aws/aws-sdk-go-v2/service/costexplorer"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// ---------------------------------------------------------------------------
// Narrow client interfaces
//
// Each interface lists only the SDK operations used by this package.
// The real *ec2.Client, *rds.Client, etc. satisfy these automatically.
// Replace any field in costClients with a stub struct in unit tests.
// ---------------------------------------------------------------------------

// costEC2Client covers the EC2 operations required for cost collection.
// A single *ec2.Client satisfies all three embedded describe methods, which
// also satisfy ec2.DescribeInstancesAPIClient, ec2.DescribeVolumesAPIClient,
// and ec2.DescribeNatGatewaysAPIClient — enabling SDK v2 paginators.
type costEC2Client interface {
	DescribeInstances(
		ctx context.Context,
		params *ec2svc.DescribeInstancesInput,
		optFns ...func(*ec2svc.Options),
	) (*ec2svc.DescribeInstancesOutput, error)

	DescribeVolumes(
		ctx context.Context,
		params *ec2svc.DescribeVolumesInput,
		optFns ...func(*ec2svc.Options),
	) (*ec2svc.DescribeVolumesOutput, error)

	DescribeNatGateways(
		ctx context.Context,
		params *ec2svc.DescribeNatGatewaysInput,
		optFns ...func(*ec2svc.Options),
	) (*ec2svc.DescribeNatGatewaysOutput, error)
}

// costRDSClient covers the RDS operations required for cost collection.
// Satisfies rds.DescribeDBInstancesAPIClient for the SDK v2 paginator.
type costRDSClient interface {
	DescribeDBInstances(
		ctx context.Context,
		params *rds.DescribeDBInstancesInput,
		optFns ...func(*rds.Options),
	) (*rds.DescribeDBInstancesOutput, error)
}

// costELBv2Client covers the ELBv2 operations required for cost collection.
// Satisfies elbv2.DescribeLoadBalancersAPIClient for the SDK v2 paginator.
type costELBv2Client interface {
	DescribeLoadBalancers(
		ctx context.Context,
		params *elbv2.DescribeLoadBalancersInput,
		optFns ...func(*elbv2.Options),
	) (*elbv2.DescribeLoadBalancersOutput, error)
}

// costCWClient covers the CloudWatch operations required for metric collection.
// Metrics are fetched per-region; the client must be initialised with a
// regional aws.Config (unlike Cost Explorer which requires us-east-1).
type costCWClient interface {
	GetMetricStatistics(
		ctx context.Context,
		params *cloudwatch.GetMetricStatisticsInput,
		optFns ...func(*cloudwatch.Options),
	) (*cloudwatch.GetMetricStatisticsOutput, error)
}

// costCEClient covers the Cost Explorer operations required for cost
// collection. Cost Explorer is a global service; always use us-east-1.
type costCEClient interface {
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

// ---------------------------------------------------------------------------
// costClients and factory
// ---------------------------------------------------------------------------

// costClients holds all service clients needed for one collection run.
// All fields are interfaces — swap any with a mock in tests.
type costClients struct {
	EC2 costEC2Client
	RDS costRDSClient
	ELB costELBv2Client
	CE  costCEClient // always pointed at us-east-1 by the factory
	CW  costCWClient // regional; used for CloudWatch metric queries
}

// costClientFactory creates a costClients from an aws.Config.
type costClientFactory func(cfg aws.Config) *costClients

// newDefaultCostClients is the production costClientFactory.
// Cost Explorer is forced to us-east-1 because it is a global service.
// CloudWatch uses the regional cfg so metrics are queried in the correct region.
func newDefaultCostClients(cfg aws.Config) *costClients {
	ceCfg := cfg
	ceCfg.Region = "us-east-1"
	return &costClients{
		EC2: ec2svc.NewFromConfig(cfg),
		RDS: rds.NewFromConfig(cfg),
		ELB: elbv2.NewFromConfig(cfg),
		CE:  ce.NewFromConfig(ceCfg),
		CW:  cloudwatch.NewFromConfig(cfg),
	}
}
