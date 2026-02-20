package cost

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/common"
)

// DefaultCostCollector is the production implementation of CostCollector.
// It uses AWS SDK v2 to collect cost-relevant resources region by region.
//
// Inject a custom costClientFactory via NewDefaultCostCollectorWithFactory
// to replace real SDK clients with mocks in unit tests.
type DefaultCostCollector struct {
	factory costClientFactory
}

// NewDefaultCostCollector returns a collector backed by the real AWS SDK.
func NewDefaultCostCollector() *DefaultCostCollector {
	return &DefaultCostCollector{factory: newDefaultCostClients}
}

// NewDefaultCostCollectorWithFactory returns a collector that uses f to
// create its service clients. Pass a mock factory in tests.
func NewDefaultCostCollectorWithFactory(f costClientFactory) *DefaultCostCollector {
	return &DefaultCostCollector{factory: f}
}

// ---------------------------------------------------------------------------
// CostCollector implementation
// ---------------------------------------------------------------------------

// CollectAll is the top-level coordinator.
//
// Flow:
//  1. Compute the date range from daysBack.
//  2. Fetch account-level Cost Explorer summary (CE is global → us-east-1).
//  3. Fetch Savings Plan coverage per region (one account-level CE call).
//  4. For each region: obtain a regional aws.Config via provider, then call
//     CollectRegion to gather EC2, EBS, NAT, RDS, and LB data.
//  5. Attach the pre-fetched SP coverage to each RegionData.
//
// Regions that fail collection are skipped. CE failures result in a nil
// CostSummary (non-fatal). An error is only returned when all regions fail.
func (d *DefaultCostCollector) CollectAll(
	ctx context.Context,
	profile *common.ProfileConfig,
	provider common.AWSClientProvider,
	regions []string,
	daysBack int,
) ([]models.RegionData, *models.CostSummary, error) {
	days := effectiveDaysBack(daysBack)
	start, end := billingDateRange(days)

	// Cost Explorer is a global service — always use us-east-1.
	ceCfg := provider.ConfigForRegion(profile, "us-east-1")

	// 1. Account-level cost summary.
	costSummary, err := d.CollectCostExplorer(ctx, ceCfg, CollectOptions{
		AccountID: profile.AccountID,
		Profile:   profile.ProfileName,
		DaysBack:  days,
	})
	if err != nil {
		// Non-fatal: proceed without cost summary.
		costSummary = nil
	}

	// 2. Savings Plan coverage per region (single account-level call).
	ceClients := d.factory(ceCfg)
	spCoverage, _ := collectSavingsPlanCoverage(ctx, ceClients.CE, start, end)

	// 3. Per-region resource collection.
	var allRegionData []models.RegionData
	var lastErr error

	for _, region := range regions {
		regionalCfg := provider.ConfigForRegion(profile, region)
		opts := CollectOptions{
			Region:    region,
			AccountID: profile.AccountID,
			Profile:   profile.ProfileName,
			DaysBack:  days,
		}

		rd, regionErr := d.CollectRegion(ctx, regionalCfg, opts)
		if regionErr != nil {
			lastErr = regionErr
			continue // skip failed regions
		}

		// 4. Attach Savings Plan coverage for this region.
		if cov, ok := spCoverage[region]; ok {
			rd.SavingsPlanCoverage = []models.SavingsPlanCoverage{cov}
		}

		allRegionData = append(allRegionData, *rd)
	}

	if len(allRegionData) == 0 && lastErr != nil {
		return nil, costSummary, fmt.Errorf("all region collections failed, last error: %w", lastErr)
	}

	return allRegionData, costSummary, nil
}

// CollectRegion gathers EC2 instances, EBS volumes, NAT Gateways, RDS instances,
// and Load Balancers from a single AWS region. SavingsPlanCoverage is left
// empty — CollectAll populates it centrally from a single account-level call.
func (d *DefaultCostCollector) CollectRegion(
	ctx context.Context,
	cfg aws.Config,
	opts CollectOptions,
) (*models.RegionData, error) {
	clients := d.factory(cfg)
	rd := &models.RegionData{Region: opts.Region}

	var err error

	rd.EC2Instances, err = collectEC2Instances(ctx, clients.EC2, clients.CW, opts.Region, opts.DaysBack)
	if err != nil {
		return nil, fmt.Errorf("collect EC2 instances in %s: %w", opts.Region, err)
	}

	// Enrich EC2 instances with Cost Explorer per-instance monthly cost.
	// Non-fatal: instances without cost data retain MonthlyCostUSD == 0,
	// which causes cost-dependent rules to skip them.
	start, end := billingDateRange(effectiveDaysBack(opts.DaysBack))
	ec2Costs, _ := collectEC2InstanceCosts(ctx, clients.CE, start, end)
	for i := range rd.EC2Instances {
		if cost, ok := ec2Costs[rd.EC2Instances[i].InstanceID]; ok {
			rd.EC2Instances[i].MonthlyCostUSD = cost
		}
	}

	rd.EBSVolumes, err = collectEBSVolumes(ctx, clients.EC2, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("collect EBS volumes in %s: %w", opts.Region, err)
	}

	rd.NATGateways, err = collectNATGateways(ctx, clients.EC2, clients.CW, opts.Region, opts.DaysBack)
	if err != nil {
		return nil, fmt.Errorf("collect NAT gateways in %s: %w", opts.Region, err)
	}

	rd.RDSInstances, err = collectRDSInstances(ctx, clients.RDS, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("collect RDS instances in %s: %w", opts.Region, err)
	}

	rd.LoadBalancers, err = collectLoadBalancers(ctx, clients.ELB, opts.Region)
	if err != nil {
		return nil, fmt.Errorf("collect load balancers in %s: %w", opts.Region, err)
	}

	return rd, nil
}

// CollectCostExplorer fetches account-level Cost Explorer data. The region in
// cfg is overridden to us-east-1 internally because CE is a global service.
func (d *DefaultCostCollector) CollectCostExplorer(
	ctx context.Context,
	cfg aws.Config,
	opts CollectOptions,
) (*models.CostSummary, error) {
	// CE must always use us-east-1.
	ceCfg := cfg
	ceCfg.Region = "us-east-1"
	clients := d.factory(ceCfg)

	days := effectiveDaysBack(opts.DaysBack)
	start, end := billingDateRange(days)
	return collectCostSummary(ctx, clients.CE, start, end)
}

// ---------------------------------------------------------------------------
// Package-private helpers
// ---------------------------------------------------------------------------

// effectiveDaysBack returns daysBack if positive, otherwise the default of 30.
func effectiveDaysBack(daysBack int) int {
	if daysBack > 0 {
		return daysBack
	}
	return 30
}

// billingDateRange returns start and end dates for a Cost Explorer query.
// end is today (UTC); start is daysBack days ago. Format: "2006-01-02".
func billingDateRange(daysBack int) (start, end string) {
	now := time.Now().UTC()
	end = now.Format("2006-01-02")
	start = now.AddDate(0, 0, -daysBack).Format("2006-01-02")
	return
}
