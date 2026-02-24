// Package eks provides the AWS EKS data collector for EKS-specific governance rules.
// It must only be used when the cluster has been identified as EKS; it is not
// invoked for GKE, AKS, or unknown cluster types.
package eks

import (
	"context"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// EKSCollector collects AWS EKS control-plane data required for EKS governance
// rule evaluation. It must not perform Kubernetes API calls; only AWS EKS API.
type EKSCollector interface {
	// CollectEKSData calls the AWS EKS API to collect cluster-level and
	// nodegroup-level governance data for the named cluster in the given region.
	// A non-nil error means collection failed; the engine treats it as non-fatal
	// and skips EKS-specific rules for that run.
	CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error)
}
