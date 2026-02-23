package cost

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2svc "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// collectLoadBalancers pages through all ELBv2 load balancers (Application,
// Network, Gateway) in region and converts them to internal models.
//
// Classic ELB (v1) is not collected here — add the elasticloadbalancing
// package and a separate collector if needed in a future step.
//
// RequestCount is left at 0 — CloudWatch integration is a future step.
func collectLoadBalancers(ctx context.Context, client costELBv2Client, region string) ([]models.AWSLoadBalancer, error) {
	paginator := elbv2svc.NewDescribeLoadBalancersPaginator(client, &elbv2svc.DescribeLoadBalancersInput{})

	var lbs []models.AWSLoadBalancer
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeLoadBalancers page: %w", err)
		}
		for _, lb := range page.LoadBalancers {
			lbs = append(lbs, toLoadBalancer(lb, region))
		}
	}
	return lbs, nil
}

// toLoadBalancer converts an SDK ELBv2 LoadBalancer to the internal model.
func toLoadBalancer(lb elbv2types.LoadBalancer, region string) models.AWSLoadBalancer {
	var state string
	if lb.State != nil {
		state = string(lb.State.Code)
	}

	return models.AWSLoadBalancer{
		LoadBalancerARN:  aws.ToString(lb.LoadBalancerArn),
		LoadBalancerName: aws.ToString(lb.LoadBalancerName),
		Region:           region,
		Type:             string(lb.Type),
		State:            state,
		RequestCount:     0, // populated by CloudWatch in a future step
		// Tags require a separate DescribeTags API call (not included here).
	}
}
