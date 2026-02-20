package cost

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	rdssvc "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// collectRDSInstances pages through all RDS database instances in region and
// converts them to internal models.
func collectRDSInstances(ctx context.Context, client costRDSClient, region string) ([]models.RDSInstance, error) {
	paginator := rdssvc.NewDescribeDBInstancesPaginator(client, &rdssvc.DescribeDBInstancesInput{})

	var instances []models.RDSInstance
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeDBInstances page: %w", err)
		}
		for _, db := range page.DBInstances {
			instances = append(instances, toRDSInstance(db, region))
		}
	}
	return instances, nil
}

// toRDSInstance converts an SDK DBInstance to the internal model.
func toRDSInstance(db rdstypes.DBInstance, region string) models.RDSInstance {
	return models.RDSInstance{
		DBInstanceID:    aws.ToString(db.DBInstanceIdentifier),
		Region:          region,
		DBInstanceClass: aws.ToString(db.DBInstanceClass),
		Engine:          aws.ToString(db.Engine),
		MultiAZ:         aws.ToBool(db.MultiAZ),
		Status:          aws.ToString(db.DBInstanceStatus),
		Tags:            tagsFromRDS(db.TagList),
	}
}

// tagsFromRDS converts RDS SDK tags to a plain string map.
func tagsFromRDS(tags []rdstypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			m[*t.Key] = *t.Value
		}
	}
	return m
}
