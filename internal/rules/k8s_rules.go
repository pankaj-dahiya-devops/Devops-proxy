package rules

import (
	"fmt"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// ── K8S_CLUSTER_SINGLE_NODE ──────────────────────────────────────────────────

// K8SClusterSingleNodeRule fires when the cluster has exactly one node,
// indicating no redundancy for workloads.
type K8SClusterSingleNodeRule struct{}

func (r K8SClusterSingleNodeRule) ID() string   { return "K8S_CLUSTER_SINGLE_NODE" }
func (r K8SClusterSingleNodeRule) Name() string { return "Kubernetes Cluster Has Single Node" }

func (r K8SClusterSingleNodeRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	if ctx.ClusterData.NodeCount != 1 {
		return nil
	}
	return []models.Finding{
		{
			ID:             fmt.Sprintf("%s:%s", r.ID(), ctx.ClusterData.ContextName),
			RuleID:         r.ID(),
			ResourceID:     ctx.ClusterData.ContextName,
			ResourceType:   models.ResourceK8sCluster,
			Region:         ctx.ClusterData.ContextName,
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityHigh,
			Explanation:    "Cluster has only 1 node; there is no redundancy for scheduled workloads.",
			Recommendation: "Add at least 2 more nodes to provide high availability for workloads.",
			DetectedAt:     time.Now().UTC(),
		},
	}
}

// ── K8S_NODE_OVERALLOCATED ───────────────────────────────────────────────────

// overallocatedCPUThresholdPercent is the minimum acceptable percentage of
// allocatable CPU relative to total capacity. Nodes below this threshold fire.
const overallocatedCPUThresholdPercent = 20.0

// K8SNodeOverallocatedRule fires for each node where the allocatable CPU is
// less than overallocatedCPUThresholdPercent of the node's total CPU capacity.
type K8SNodeOverallocatedRule struct{}

func (r K8SNodeOverallocatedRule) ID() string   { return "K8S_NODE_OVERALLOCATED" }
func (r K8SNodeOverallocatedRule) Name() string { return "Kubernetes Node CPU Overallocated" }

func (r K8SNodeOverallocatedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, node := range ctx.ClusterData.Nodes {
		if node.CPUCapacityMillis == 0 {
			continue // skip nodes with no reported CPU capacity
		}
		freePercent := float64(node.AllocatableCPUMillis) / float64(node.CPUCapacityMillis) * 100.0
		if freePercent < overallocatedCPUThresholdPercent {
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("%s:%s:%s", r.ID(), ctx.ClusterData.ContextName, node.Name),
				RuleID:       r.ID(),
				ResourceID:   node.Name,
				ResourceType: models.ResourceK8sNode,
				Region:       ctx.ClusterData.ContextName,
				AccountID:    ctx.AccountID,
				Profile:      ctx.Profile,
				Severity:     models.SeverityHigh,
				Explanation: fmt.Sprintf(
					"Node %q has only %.1f%% of CPU allocatable (threshold: %.0f%%).",
					node.Name, freePercent, overallocatedCPUThresholdPercent,
				),
				Recommendation: "Add more nodes or reduce pod resource requests on this node to restore scheduling headroom.",
				DetectedAt:     time.Now().UTC(),
			})
		}
	}
	return findings
}

// ── K8S_NAMESPACE_WITHOUT_LIMITS ─────────────────────────────────────────────

// K8SNamespaceWithoutLimitsRule fires for each namespace that has no LimitRange
// object, meaning pods can consume unbounded CPU and memory resources.
type K8SNamespaceWithoutLimitsRule struct{}

func (r K8SNamespaceWithoutLimitsRule) ID() string {
	return "K8S_NAMESPACE_WITHOUT_LIMITS"
}
func (r K8SNamespaceWithoutLimitsRule) Name() string {
	return "Kubernetes Namespace Without LimitRange"
}

func (r K8SNamespaceWithoutLimitsRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, ns := range ctx.ClusterData.Namespaces {
		if ns.HasLimitRange {
			continue
		}
		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("%s:%s:%s", r.ID(), ctx.ClusterData.ContextName, ns.Name),
			RuleID:       r.ID(),
			ResourceID:   ns.Name,
			ResourceType: models.ResourceK8sNamespace,
			Region:       ctx.ClusterData.ContextName,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityMedium,
			Explanation: fmt.Sprintf(
				"Namespace %q has no LimitRange; pods may consume unbounded CPU and memory.",
				ns.Name,
			),
			Recommendation: fmt.Sprintf(
				"Add a LimitRange to namespace %q to enforce default resource limits for pods.",
				ns.Name,
			),
			DetectedAt: time.Now().UTC(),
		})
	}
	return findings
}
