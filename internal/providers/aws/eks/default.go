package eks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// DefaultEKSCollector implements EKSCollector using the AWS SDK v2.
// It loads credentials from the default credential chain (env, ~/.aws/credentials,
// instance profile) and constructs real EKS and EC2 SDK clients per invocation.
type DefaultEKSCollector struct{}

// NewDefaultEKSCollector returns the production EKS collector.
func NewDefaultEKSCollector() *DefaultEKSCollector {
	return &DefaultEKSCollector{}
}

// CollectEKSData loads the default AWS config for region and calls the EKS API.
// It satisfies both EKSCollector (this package) and engine.EKSDataCollector.
func (d *DefaultEKSCollector) CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config for region %q: %w", region, err)
	}
	return collectEKSClusterData(ctx, awseks.NewFromConfig(cfg), ec2.NewFromConfig(cfg), clusterName, region)
}

// collectEKSClusterData is the testable core: it accepts interfaces so tests
// can inject fake clients without touching the AWS SDK.
func collectEKSClusterData(
	ctx context.Context,
	eksC eksAPIClient,
	ec2C ec2LaunchTemplateClient,
	clusterName, region string,
) (*models.KubernetesEKSData, error) {
	out, err := eksC.DescribeCluster(ctx, &awseks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return nil, fmt.Errorf("describe cluster %q: %w", clusterName, err)
	}

	cluster := out.Cluster
	if cluster == nil {
		return nil, fmt.Errorf("describe cluster %q: empty response", clusterName)
	}

	data := &models.KubernetesEKSData{
		ClusterName:         clusterName,
		Region:              region,
		ControlPlaneVersion: aws.ToString(cluster.Version),
	}

	// VPC / endpoint access
	if cluster.ResourcesVpcConfig != nil {
		data.EndpointPublicAccess = cluster.ResourcesVpcConfig.EndpointPublicAccess
		data.PublicAccessCidrs = cluster.ResourcesVpcConfig.PublicAccessCidrs
	}

	// Secrets envelope encryption (KMS)
	for _, enc := range cluster.EncryptionConfig {
		if enc.Provider == nil {
			continue
		}
		keyARN := aws.ToString(enc.Provider.KeyArn)
		if keyARN == "" {
			continue
		}
		for _, res := range enc.Resources {
			if res == "secrets" {
				data.EncryptionKeyARN = keyARN
				break
			}
		}
		if data.EncryptionKeyARN != "" {
			break
		}
	}

	// Control plane logging
	if cluster.Logging != nil {
		for _, logSetup := range cluster.Logging.ClusterLogging {
			if aws.ToBool(logSetup.Enabled) {
				for _, lt := range logSetup.Types {
					data.EnabledLogTypes = append(data.EnabledLogTypes, string(lt))
				}
			}
		}
	}

	// Nodegroups (non-fatal: best-effort collection)
	ngList, err := eksC.ListNodegroups(ctx, &awseks.ListNodegroupsInput{
		ClusterName: aws.String(clusterName),
	})
	if err != nil {
		// Return what we have so far; EKS rules that need nodegroup data will skip.
		return data, nil
	}

	for _, ngName := range ngList.Nodegroups {
		ngName := ngName
		ngOut, err := eksC.DescribeNodegroup(ctx, &awseks.DescribeNodegroupInput{
			ClusterName:   aws.String(clusterName),
			NodegroupName: aws.String(ngName),
		})
		if err != nil {
			continue
		}
		ng := ngOut.Nodegroup
		if ng == nil {
			continue
		}

		httpTokens := "optional" // EKS default (IMDSv2 not enforced)

		if ng.LaunchTemplate != nil {
			ltID := aws.ToString(ng.LaunchTemplate.Id)
			ltVersion := aws.ToString(ng.LaunchTemplate.Version)
			if ltID != "" {
				tokens, err := launchTemplateHttpTokens(ctx, ec2C, ltID, ltVersion)
				if err == nil && tokens != "" {
					httpTokens = tokens
				}
			}
		}

		data.NodeGroups = append(data.NodeGroups, models.KubernetesEKSNodeGroupData{
			Name:       ngName,
			Version:    aws.ToString(ng.Version),
			HttpTokens: httpTokens,
		})
	}

	return data, nil
}

// launchTemplateHttpTokens queries EC2 for the MetadataOptions.HttpTokens setting
// of the given launch template version. Returns "optional" if not explicitly set.
func launchTemplateHttpTokens(
	ctx context.Context,
	ec2C ec2LaunchTemplateClient,
	ltID, version string,
) (string, error) {
	input := &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: aws.String(ltID),
	}
	// Avoid special version tokens ($Default / $Latest) which require separate handling
	if version != "" && version != "$Default" && version != "$Latest" {
		input.Versions = []string{version}
	}

	out, err := ec2C.DescribeLaunchTemplateVersions(ctx, input)
	if err != nil {
		return "", fmt.Errorf("describe launch template versions for %q: %w", ltID, err)
	}
	if len(out.LaunchTemplateVersions) == 0 {
		return "optional", nil
	}

	ltData := out.LaunchTemplateVersions[0].LaunchTemplateData
	if ltData == nil || ltData.MetadataOptions == nil {
		return "optional", nil
	}

	tokens := string(ltData.MetadataOptions.HttpTokens)
	if tokens == "" {
		return "optional", nil
	}
	return tokens, nil
}
