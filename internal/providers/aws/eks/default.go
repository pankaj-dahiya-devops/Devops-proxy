package eks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// DefaultEKSCollector implements EKSCollector using the AWS SDK v2.
// It loads AWS credentials from the default chain (env vars, ~/.aws/credentials,
// EC2 instance profile) — no explicit profile is needed because the EKS cluster
// name and region are derived from the nodes themselves.
type DefaultEKSCollector struct{}

// NewDefaultEKSCollector returns an EKSCollector backed by the real AWS SDK.
func NewDefaultEKSCollector() *DefaultEKSCollector {
	return &DefaultEKSCollector{}
}

// CollectEKSData calls eks.DescribeCluster and converts the response to
// models.KubernetesEKSData for rule evaluation.
func (d *DefaultEKSCollector) CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config for EKS region %q: %w", region, err)
	}
	return collectWithClient(ctx, awseks.NewFromConfig(cfg), clusterName, region)
}

// collectWithClient is the testable core: it accepts an injectable eksAPIClient.
func collectWithClient(ctx context.Context, client eksAPIClient, clusterName, region string) (*models.KubernetesEKSData, error) {
	out, err := client.DescribeCluster(ctx, &awseks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return nil, fmt.Errorf("describe EKS cluster %q: %w", clusterName, err)
	}
	if out.Cluster == nil {
		return nil, fmt.Errorf("describe EKS cluster %q: empty response", clusterName)
	}

	data := &models.KubernetesEKSData{
		ClusterName: clusterName,
		Region:      region,
	}

	if out.Cluster.ResourcesVpcConfig != nil {
		data.EndpointPublicAccess = out.Cluster.ResourcesVpcConfig.EndpointPublicAccess
	}

	if out.Cluster.Logging != nil {
		for _, logConf := range out.Cluster.Logging.ClusterLogging {
			if logConf.Enabled != nil && *logConf.Enabled && len(logConf.Types) > 0 {
				data.LoggingEnabled = true
				break
			}
		}
	}

	if out.Cluster.Identity != nil && out.Cluster.Identity.Oidc != nil {
		data.OIDCIssuer = aws.ToString(out.Cluster.Identity.Oidc.Issuer)
	}

	return data, nil
}
