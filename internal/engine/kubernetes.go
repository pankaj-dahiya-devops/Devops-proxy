package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/policy"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
)

// EKSDataCollector collects EKS-specific cluster configuration from the AWS EKS API.
// The interface is defined here (engine layer) so the engine remains independent
// of any AWS provider implementation; callers inject the concrete collector.
// Nil means EKS data collection is disabled and EKS-specific rules are skipped.
type EKSDataCollector interface {
	CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error)
}

// KubernetesEngine orchestrates a Kubernetes governance audit.
// It supports provider-aware rule evaluation: core rules always run;
// EKS-specific rules run only when the cluster is detected as EKS.
type KubernetesEngine struct {
	provider     kube.KubeClientProvider
	coreRegistry rules.RuleRegistry // always evaluated
	eksRegistry  rules.RuleRegistry // evaluated only for EKS clusters; may be nil
	eksCollector EKSDataCollector   // optional; nil disables EKS data collection
	policy       *policy.PolicyConfig
}

// NewKubernetesEngine constructs a KubernetesEngine with core rules only.
// EKS-specific rule evaluation and data collection are disabled.
// Use NewKubernetesEngineWithEKS to enable provider-aware governance.
func NewKubernetesEngine(
	provider kube.KubeClientProvider,
	registry rules.RuleRegistry,
	policyCfg *policy.PolicyConfig,
) *KubernetesEngine {
	return &KubernetesEngine{
		provider:     provider,
		coreRegistry: registry,
		policy:       policyCfg,
	}
}

// NewKubernetesEngineWithEKS constructs a KubernetesEngine with provider-aware
// governance. When the cluster is detected as EKS:
//   - eksCollector fetches control-plane configuration (endpoint, logging, OIDC)
//   - eksRegistry rules are evaluated in addition to coreRegistry rules
//
// eksRegistry and eksCollector may be nil (each is independently optional).
func NewKubernetesEngineWithEKS(
	provider kube.KubeClientProvider,
	coreRegistry rules.RuleRegistry,
	eksRegistry rules.RuleRegistry,
	eksCollector EKSDataCollector,
	policyCfg *policy.PolicyConfig,
) *KubernetesEngine {
	return &KubernetesEngine{
		provider:     provider,
		coreRegistry: coreRegistry,
		eksRegistry:  eksRegistry,
		eksCollector: eksCollector,
		policy:       policyCfg,
	}
}

// KubernetesAuditOptions carries the parameters for a single cluster audit.
type KubernetesAuditOptions struct {
	// ContextName is the kubeconfig context to connect to.
	// An empty string means use the current context.
	ContextName string

	// ReportFormat controls the output format selected by the CLI layer.
	ReportFormat ReportFormat
}

// RunAudit connects to the cluster, collects inventory, detects the cloud
// provider, optionally collects EKS control-plane data, evaluates all
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

	// ── Provider detection ────────────────────────────────────────────────────
	k8sData.ClusterProvider = detectClusterProvider(k8sData.Nodes)

	// ── EKS-specific data collection (non-fatal) ─────────────────────────────
	if k8sData.ClusterProvider == "eks" && e.eksCollector != nil {
		clusterName, region := extractEKSInfo(k8sData.Nodes)
		if clusterName != "" && region != "" {
			eksData, eksErr := e.eksCollector.CollectEKSData(ctx, clusterName, region)
			if eksErr == nil {
				k8sData.EKSData = eksData
			}
			// EKS collection failure is non-fatal: EKS rules skip on nil check.
		}
	}

	// ── Rule evaluation ───────────────────────────────────────────────────────
	rctx := rules.RuleContext{ClusterData: k8sData}

	raw := e.coreRegistry.EvaluateAll(rctx)

	if k8sData.ClusterProvider == "eks" && e.eksRegistry != nil {
		eksRaw := e.eksRegistry.EvaluateAll(rctx)
		raw = append(raw, eksRaw...)
	}

	stampDomain(raw, "kubernetes")

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
		Metadata: map[string]any{
			"cluster_provider": k8sData.ClusterProvider,
		},
	}, nil
}

// detectClusterProvider inspects node ProviderID prefixes and well-known labels
// to determine the cloud provider. Returns "eks", "gke", "aks", or "unknown".
func detectClusterProvider(nodes []models.KubernetesNodeData) string {
	for _, n := range nodes {
		switch {
		case strings.HasPrefix(n.ProviderID, "aws://"):
			return "eks"
		case strings.HasPrefix(n.ProviderID, "gce://"):
			return "gke"
		case strings.HasPrefix(n.ProviderID, "azure://"):
			return "aks"
		}
		if _, ok := n.Labels["eks.amazonaws.com/nodegroup"]; ok {
			return "eks"
		}
		if _, ok := n.Labels["cloud.google.com/gke-nodepool"]; ok {
			return "gke"
		}
		if _, ok := n.Labels["kubernetes.azure.com/cluster"]; ok {
			return "aks"
		}
	}
	return "unknown"
}

// extractEKSInfo derives the EKS cluster name and AWS region from node labels.
// Preferred sources:
//   - cluster name: label "eks.amazonaws.com/cluster-name"
//   - region:       label "topology.kubernetes.io/region"
//
// Falls back to parsing the ProviderID AZ field for the region when the label
// is absent ("aws:///us-east-1a/i-xxx" → strip trailing AZ letter → "us-east-1").
func extractEKSInfo(nodes []models.KubernetesNodeData) (clusterName, region string) {
	for _, n := range nodes {
		if cn, ok := n.Labels["eks.amazonaws.com/cluster-name"]; ok && cn != "" {
			clusterName = cn
		}
		if r, ok := n.Labels["topology.kubernetes.io/region"]; ok && r != "" {
			region = r
		}
		// Fallback: derive region from ProviderID AZ ("aws:///us-east-1a/i-xxx").
		if region == "" && strings.HasPrefix(n.ProviderID, "aws://") {
			parts := strings.Split(n.ProviderID, "/")
			// parts: ["aws:", "", "", "us-east-1a", "i-xxx"]
			if len(parts) >= 4 && len(parts[3]) > 1 {
				az := parts[3]
				region = az[:len(az)-1] // strip trailing AZ letter
			}
		}
		if clusterName != "" && region != "" {
			return
		}
	}
	return
}

// convertClusterData translates the provider-layer ClusterData into the
// engine-layer KubernetesClusterData used by rule evaluation.
func convertClusterData(data *kube.ClusterData) *models.KubernetesClusterData {
	k := &models.KubernetesClusterData{
		ContextName: data.ClusterInfo.ContextName,
		NodeCount:   len(data.Nodes),
	}
	for _, n := range data.Nodes {
		labels := make(map[string]string, len(n.Labels))
		for key, val := range n.Labels {
			labels[key] = val
		}
		k.Nodes = append(k.Nodes, models.KubernetesNodeData{
			Name:                 n.Name,
			CPUCapacityMillis:    n.CPUCapacityMillis,
			AllocatableCPUMillis: n.AllocatableCPUMillis,
			ProviderID:           n.ProviderID,
			Labels:               labels,
		})
	}
	for _, ns := range data.Namespaces {
		k.Namespaces = append(k.Namespaces, models.KubernetesNamespaceData{
			Name:          ns.Name,
			HasLimitRange: ns.HasLimitRange,
		})
	}
	for _, pod := range data.Pods {
		pd := models.KubernetesPodData{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		}
		for _, c := range pod.Containers {
			pd.Containers = append(pd.Containers, models.KubernetesContainerData{
				Name:             c.Name,
				Privileged:       c.Privileged,
				HasCPURequest:    c.HasCPURequest,
				HasMemoryRequest: c.HasMemoryRequest,
			})
		}
		k.Pods = append(k.Pods, pd)
	}
	for _, svc := range data.Services {
		annotations := make(map[string]string, len(svc.Annotations))
		for key, val := range svc.Annotations {
			annotations[key] = val
		}
		k.Services = append(k.Services, models.KubernetesServiceData{
			Name:        svc.Name,
			Namespace:   svc.Namespace,
			Type:        svc.Type,
			Annotations: annotations,
		})
	}
	return k
}
