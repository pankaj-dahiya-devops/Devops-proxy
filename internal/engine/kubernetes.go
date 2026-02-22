package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/policy"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
)

// KubernetesEngine orchestrates a Kubernetes governance audit.
// It is cluster-agnostic: it does not assume any cloud provider.
// There is no multi-region or multi-profile logic; each audit targets a single
// cluster identified by a kubeconfig context name.
type KubernetesEngine struct {
	provider kube.KubeClientProvider
	registry rules.RuleRegistry
	policy   *policy.PolicyConfig
}

// NewKubernetesEngine constructs a KubernetesEngine wired to the supplied
// provider, rule registry, and optional policy config.
func NewKubernetesEngine(
	provider kube.KubeClientProvider,
	registry rules.RuleRegistry,
	policyCfg *policy.PolicyConfig,
) *KubernetesEngine {
	return &KubernetesEngine{
		provider: provider,
		registry: registry,
		policy:   policyCfg,
	}
}

// KubernetesAuditOptions carries the parameters for a single cluster audit.
type KubernetesAuditOptions struct {
	// ContextName is the kubeconfig context to connect to.
	// An empty string means use the current context.
	ContextName string

	// ReportFormat controls the output format selected by the CLI layer.
	// The engine itself does not render output; this field is passed through
	// to the report for the caller's reference.
	ReportFormat ReportFormat
}

// RunAudit connects to the cluster, collects inventory, evaluates all
// registered rules, applies policy filtering, and returns a populated AuditReport.
func (e *KubernetesEngine) RunAudit(ctx context.Context, opts KubernetesAuditOptions) (*models.AuditReport, error) {
	clientset, info, err := e.provider.ClientsetForContext(opts.ContextName)
	if err != nil {
		return nil, fmt.Errorf("connect to cluster: %w", err)
	}

	clusterData, err := kube.CollectClusterData(ctx, clientset, info)
	if err != nil {
		return nil, fmt.Errorf("collect cluster data: %w", err)
	}

	k8sData := convertClusterData(clusterData)

	rctx := rules.RuleContext{ClusterData: k8sData}
	raw := e.registry.EvaluateAll(rctx)

	merged := mergeFindings(raw)
	filtered := policy.ApplyPolicy(merged, "kubernetes", e.policy)
	sortFindings(filtered)

	return &models.AuditReport{
		ReportID:    fmt.Sprintf("k8s-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		AuditType:   "kubernetes",
		Profile:     info.ContextName,
		AccountID:   "",
		Regions:     []string{info.ContextName},
		Summary:     computeSummary(filtered),
		Findings:    filtered,
	}, nil
}

// convertClusterData translates the provider-layer ClusterData into the
// engine-layer KubernetesClusterData used by rule evaluation.
func convertClusterData(data *kube.ClusterData) *models.KubernetesClusterData {
	k := &models.KubernetesClusterData{
		ContextName: data.ClusterInfo.ContextName,
		NodeCount:   len(data.Nodes),
	}
	for _, n := range data.Nodes {
		k.Nodes = append(k.Nodes, models.KubernetesNodeData{
			Name:                 n.Name,
			CPUCapacityMillis:    n.CPUCapacityMillis,
			AllocatableCPUMillis: n.AllocatableCPUMillis,
		})
	}
	for _, ns := range data.Namespaces {
		k.Namespaces = append(k.Namespaces, models.KubernetesNamespaceData{
			Name:          ns.Name,
			HasLimitRange: ns.HasLimitRange,
		})
	}
	return k
}
