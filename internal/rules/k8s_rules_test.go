package rules_test

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
)

// newK8sCtx is a helper that builds a RuleContext with the given KubernetesClusterData.
func newK8sCtx(data *models.KubernetesClusterData) rules.RuleContext {
	return rules.RuleContext{ClusterData: data}
}

// ── K8S_CLUSTER_SINGLE_NODE ──────────────────────────────────────────────────

func TestK8SClusterSingleNode_NoFinding_MultiNode(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		NodeCount:   3,
	})
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 3-node cluster; got %d", len(findings))
	}
}

func TestK8SClusterSingleNode_Fires_OneNode(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "dev-cluster",
		NodeCount:   1,
	})
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_CLUSTER_SINGLE_NODE" {
		t.Errorf("RuleID = %q; want K8S_CLUSTER_SINGLE_NODE", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sCluster {
		t.Errorf("ResourceType = %q; want K8S_CLUSTER", f.ResourceType)
	}
	if f.ResourceID != "dev-cluster" {
		t.Errorf("ResourceID = %q; want dev-cluster", f.ResourceID)
	}
}

func TestK8SClusterSingleNode_NilClusterData(t *testing.T) {
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

func TestK8SClusterSingleNode_ZeroNodes(t *testing.T) {
	// NodeCount == 0 should not fire (not a single node).
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "empty",
		NodeCount:   0,
	})
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 0-node cluster; got %d", len(findings))
	}
}

// ── K8S_NODE_OVERALLOCATED ───────────────────────────────────────────────────

func TestK8SNodeOverallocated_NoFinding_HealthyNode(t *testing.T) {
	// 3800m / 4000m = 95% allocatable → well above 20% threshold
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-1", CPUCapacityMillis: 4000, AllocatableCPUMillis: 3800},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings; got %d", len(findings))
	}
}

func TestK8SNodeOverallocated_Fires_BelowThreshold(t *testing.T) {
	// 500m / 4000m = 12.5% allocatable → below 20% threshold
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-overloaded", CPUCapacityMillis: 4000, AllocatableCPUMillis: 500},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_NODE_OVERALLOCATED" {
		t.Errorf("RuleID = %q; want K8S_NODE_OVERALLOCATED", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sNode {
		t.Errorf("ResourceType = %q; want K8S_NODE", f.ResourceType)
	}
	if f.ResourceID != "node-overloaded" {
		t.Errorf("ResourceID = %q; want node-overloaded", f.ResourceID)
	}
}

func TestK8SNodeOverallocated_ExactThreshold_NoFinding(t *testing.T) {
	// exactly 20% allocatable → must NOT fire (threshold is strictly less than)
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-exact", CPUCapacityMillis: 4000, AllocatableCPUMillis: 800},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings at exactly 20%% threshold; got %d", len(findings))
	}
}

func TestK8SNodeOverallocated_MultiNode_OnlyFiringNodes(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "healthy", CPUCapacityMillis: 4000, AllocatableCPUMillis: 3000},  // 75% → ok
			{Name: "overloaded", CPUCapacityMillis: 4000, AllocatableCPUMillis: 400}, // 10% → fires
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "overloaded" {
		t.Errorf("ResourceID = %q; want overloaded", findings[0].ResourceID)
	}
}

func TestK8SNodeOverallocated_ZeroCPUCapacity_Skipped(t *testing.T) {
	// CPUCapacityMillis == 0 should be skipped to avoid division-by-zero.
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "broken-node", CPUCapacityMillis: 0, AllocatableCPUMillis: 0},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for zero-capacity node; got %d", len(findings))
	}
}

func TestK8SNodeOverallocated_NilClusterData(t *testing.T) {
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

// ── K8S_NAMESPACE_WITHOUT_LIMITS ─────────────────────────────────────────────

func TestK8SNamespaceWithoutLimits_NoFinding_AllHaveLimits(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "default", HasLimitRange: true},
			{Name: "kube-system", HasLimitRange: true},
		},
	})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings; got %d", len(findings))
	}
}

func TestK8SNamespaceWithoutLimits_Fires_MissingLimitRange(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "staging", HasLimitRange: false},
		},
	})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_NAMESPACE_WITHOUT_LIMITS" {
		t.Errorf("RuleID = %q; want K8S_NAMESPACE_WITHOUT_LIMITS", f.RuleID)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sNamespace {
		t.Errorf("ResourceType = %q; want K8S_NAMESPACE", f.ResourceType)
	}
	if f.ResourceID != "staging" {
		t.Errorf("ResourceID = %q; want staging", f.ResourceID)
	}
}

func TestK8SNamespaceWithoutLimits_OnlyMissingFiresNotAll(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "with-limits", HasLimitRange: true},
			{Name: "no-limits", HasLimitRange: false},
			{Name: "also-with-limits", HasLimitRange: true},
		},
	})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "no-limits" {
		t.Errorf("ResourceID = %q; want no-limits", findings[0].ResourceID)
	}
}

func TestK8SNamespaceWithoutLimits_EmptyNamespaces(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{ContextName: "prod"})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty namespace list; got %d", len(findings))
	}
}

func TestK8SNamespaceWithoutLimits_NilClusterData(t *testing.T) {
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}
