package awssecurity

import (
	"context"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/common"
)

// DefaultSecurityCollector is the production SecurityCollector.
// It collects S3, IAM, and root account data from us-east-1 (global AWS
// services) and aggregates EC2 security group rules across all audited regions.
type DefaultSecurityCollector struct {
	factory secClientFactory
}

// NewDefaultSecurityCollector returns a DefaultSecurityCollector wired to
// production AWS SDK clients.
func NewDefaultSecurityCollector() *DefaultSecurityCollector {
	return &DefaultSecurityCollector{factory: newDefaultSecClients}
}

// NewDefaultSecurityCollectorWithFactory returns a DefaultSecurityCollector
// that uses the supplied factory, allowing tests to inject fake clients.
func NewDefaultSecurityCollectorWithFactory(f secClientFactory) *DefaultSecurityCollector {
	return &DefaultSecurityCollector{factory: f}
}

// CollectAll gathers account-level security data for the given profile and
// regions. Global resources (S3, IAM, root) are collected once using a
// us-east-1 config. Security group rules are collected per region and
// aggregated. All collection failures are silently skipped (non-fatal).
func (c *DefaultSecurityCollector) CollectAll(
	ctx context.Context,
	profile *common.ProfileConfig,
	provider common.AWSClientProvider,
	regions []string,
) (*models.AWSSecurityData, error) {
	// Global clients: us-east-1 is the canonical region for S3 and IAM.
	globalCfg := provider.ConfigForRegion(profile, "us-east-1")
	globalClients := c.factory(globalCfg)

	buckets, _ := collectS3Buckets(ctx, globalClients.S3)
	iamUsers, _ := collectIAMUsers(ctx, globalClients.IAM)
	root, _ := collectRootAccountInfo(ctx, globalClients.IAM)

	// Regional: collect security group rules per region and aggregate.
	var allSGRules []models.AWSSecurityGroupRule
	for _, region := range regions {
		regCfg := provider.ConfigForRegion(profile, region)
		regClients := c.factory(regCfg)
		sgRules, err := collectSecurityGroupRules(ctx, regClients.EC2, region)
		if err != nil {
			continue // non-fatal: skip region
		}
		allSGRules = append(allSGRules, sgRules...)
	}

	return &models.AWSSecurityData{
		Buckets:            buckets,
		SecurityGroupRules: allSGRules,
		IAMUsers:           iamUsers,
		Root:               root,
	}, nil
}
