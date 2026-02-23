package awssecurity

import (
	"context"
	"fmt"

	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// collectRootAccountInfo retrieves the IAM account summary and checks whether
// the root account has at least one active access key.
// AccountAccessKeysPresent in the summary map is the number of root access keys.
func collectRootAccountInfo(ctx context.Context, client iamAPIClient) (models.AWSRootAccountInfo, error) {
	out, err := client.GetAccountSummary(ctx, &iamsvc.GetAccountSummaryInput{})
	if err != nil {
		return models.AWSRootAccountInfo{}, fmt.Errorf("get IAM account summary: %w", err)
	}
	return models.AWSRootAccountInfo{
		HasAccessKeys: out.SummaryMap["AccountAccessKeysPresent"] > 0,
	}, nil
}
