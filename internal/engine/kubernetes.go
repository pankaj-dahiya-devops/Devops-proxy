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

// EKSDataCollector collects AWS EKS control-plane data for EKS-specific rule evaluation.
// The engine depends on this interface; the concrete implementation lives in
// internal/providers/aws/eks to preserve the provider → engine layering.
// A nil EKSDataCollector disables EKS data collection; EKS rules will not fire.
type EKSDataCollector interface {
	CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error)
}

// KubernetesEngine orchestrates a Kubernetes governance audit.
// It is cluster-agnostic at the core level; EKS-specific rules are loaded
// optionally via eksRegistry and driven by provider detection.
type KubernetesEngine struct {
	provider     kube.KubeClientProvider
	coreRegistry rules.RuleRegistry
	eksRegistry  rules.RuleRegistry  // nil → EKS-specific rules not loaded
	eksCollector EKSDataCollector    // nil → EKS data collection disabled
	policy       *policy.PolicyConfig
}

// NewKubernetesEngine constructs a KubernetesEngine with only core rules.
// EKS-specific rules and data collection are disabled. Existing callers and
// tests are unaffected.
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

// NewKubernetesEngineWithEKS constructs a KubernetesEngine with separate core
// and EKS rule registries. The eksCollector is called when provider detection
// identifies an EKS cluster; pass nil to disable EKS data collection.
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
// provider, conditionally collects EKS data, evaluates all registered rules,
// applies policy filtering, and returns a populated AuditReport.
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

	// Detect cloud provider from node ProviderIDs and well-known labels.
	k8sData.ClusterProvider = detectClusterProvider(k8sData.Nodes)

	// Conditionally collect EKS control-plane data.
	if k8sData.ClusterProvider == "eks" && e.eksCollector != nil {
		clusterName, region := extractEKSInfo(k8sData.Nodes)
		if clusterName != "" && region != "" {
			eksData, err := e.eksCollector.CollectEKSData(ctx, clusterName, region)
			if err == nil {
				k8sData.EKSData = eksData
			}
			// Non-fatal: EKS-specific rules check EKSData == nil and skip gracefully.
		}
	}

	// Evaluate core rules (always).
	rctx := rules.RuleContext{ClusterData: k8sData}
	raw := e.coreRegistry.EvaluateAll(rctx)

	// Evaluate EKS rules only for EKS clusters.
	if e.eksRegistry != nil && k8sData.ClusterProvider == "eks" {
		raw = append(raw, e.eksRegistry.EvaluateAll(rctx)...)
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
	}, nil
}

// detectClusterProvider returns the cloud provider inferred from node ProviderIDs
// and well-known node labels. Returns "eks", "gke", "aks", or "unknown".
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

// extractEKSInfo reads EKS cluster name and region from node labels, with a
// fallback to parsing the Availability Zone from the ProviderID.
func extractEKSInfo(nodes []models.KubernetesNodeData) (clusterName, region string) {
	for _, n := range nodes {
		if cn, ok := n.Labels["eks.amazonaws.com/cluster-name"]; ok && cn != "" {
			clusterName = cn
		}
		if r, ok := n.Labels["topology.kubernetes.io/region"]; ok && r != "" {
			region = r
		}
		// Fallback: derive region from AZ in ProviderID "aws:///us-east-1a/i-xxx".
		if region == "" && strings.HasPrefix(n.ProviderID, "aws://") {
			rest := strings.TrimPrefix(n.ProviderID, "aws://")
			rest = strings.TrimLeft(rest, "/")
			parts := strings.SplitN(rest, "/", 2)
			if len(parts[0]) > 1 {
				az := parts[0]
				region = az[:len(az)-1] // strip trailing AZ letter (a/b/c/d)
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
