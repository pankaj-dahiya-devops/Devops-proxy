package cost

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// collectNATGateways pages through all available NAT Gateways in region and
// converts them to internal models.
//
// BytesProcessedGB is left at 0.0 — CloudWatch integration (BytesOutToDestination
// metric) is a future step.
func collectNATGateways(ctx context.Context, client costEC2Client, region string) ([]models.NATGateway, error) {
	input := &ec2svc.DescribeNatGatewaysInput{
		Filter: []ec2types.Filter{
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	}

	paginator := ec2svc.NewDescribeNatGatewaysPaginator(client, input)

	var gateways []models.NATGateway
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeNatGateways page: %w", err)
		}
		for _, ng := range page.NatGateways {
			gateways = append(gateways, toNATGateway(ng, region))
		}
	}
	return gateways, nil
}

// toNATGateway converts an SDK NAT Gateway to the internal model.
func toNATGateway(ng ec2types.NatGateway, region string) models.NATGateway {
	return models.NATGateway{
		NATGatewayID:     aws.ToString(ng.NatGatewayId),
		Region:           region,
		State:            string(ng.State),
		VPCID:            aws.ToString(ng.VpcId),
		SubnetID:         aws.ToString(ng.SubnetId),
		BytesProcessedGB: 0, // populated by CloudWatch in a future step
		Tags:             tagsFromEC2(ng.Tags),
	}
}
