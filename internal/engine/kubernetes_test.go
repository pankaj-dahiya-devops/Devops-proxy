package engine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/policy"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
	k8spack "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rulepacks/kubernetes"
)

// fakeKubeProvider is a test double for kube.KubeClientProvider that returns
// a pre-built fake clientset.
type fakeKubeProvider struct {
	clientset k8sclient.Interface
	info      kube.ClusterInfo
}

func (f *fakeKubeProvider) ClientsetForContext(_ string) (k8sclient.Interface, kube.ClusterInfo, error) {
	return f.clientset, f.info, nil
}

// k8sNode builds a corev1.Node for use with the fake clientset.
func k8sNode(name, cpuCap, memCap, cpuAlloc, memAlloc string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpuCap),
				corev1.ResourceMemory: resource.MustParse(memCap),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpuAlloc),
				corev1.ResourceMemory: resource.MustParse(memAlloc),
			},
		},
	}
}

// k8sNamespace builds a corev1.Namespace for use with the fake clientset.
func k8sNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// k8sLimitRange builds a corev1.LimitRange in the given namespace.
func k8sLimitRange(namespace, name string) *corev1.LimitRange {
	return &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
}

// newK8sEngine builds a KubernetesEngine backed by the full rule pack and the
// supplied fake provider.
func newK8sEngine(provider kube.KubeClientProvider, policyCfg *policy.PolicyConfig) *KubernetesEngine {
	registry := rules.NewDefaultRuleRegistry()
	for _, r := range k8spack.New() {
		registry.Register(r)
	}
	return NewKubernetesEngine(provider, registry, policyCfg)
}

// TestKubernetesEngine_SingleNodeCluster verifies that a single-node cluster
// triggers K8S_CLUSTER_SINGLE_NODE (HIGH) and that namespaces without
// LimitRanges trigger K8S_NAMESPACE_WITHOUT_LIMITS (MEDIUM).
func TestKubernetesEngine_SingleNodeCluster(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		// 1 node with healthy CPU — only cluster-single-node fires, not overallocated
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("default"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "test-ctx", Server: "https://127.0.0.1:6443"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// Expect: K8S_CLUSTER_SINGLE_NODE (HIGH) + K8S_NAMESPACE_WITHOUT_LIMITS (MEDIUM)
	if report.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings; got %d", report.Summary.TotalFindings)
	}
	if report.Summary.HighFindings < 1 {
		t.Error("expected at least 1 HIGH finding (cluster single node)")
	}
	if report.Summary.MediumFindings < 1 {
		t.Error("expected at least 1 MEDIUM finding (namespace without limits)")
	}

	// AuditType must be "kubernetes"
	if report.AuditType != "kubernetes" {
		t.Errorf("AuditType = %q; want kubernetes", report.AuditType)
	}
	// Profile must reflect context name
	if report.Profile != "test-ctx" {
		t.Errorf("Profile = %q; want test-ctx", report.Profile)
	}
}

// TestKubernetesEngine_SortingDeterministic verifies that findings are sorted
// HIGH before MEDIUM regardless of rule evaluation order.
func TestKubernetesEngine_SortingDeterministic(t *testing.T) {
	// 1 node (→ K8S_CLUSTER_SINGLE_NODE HIGH), 2 namespaces without limits (→ MEDIUM each)
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("ns-a"),
		k8sNamespace("ns-b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "sort-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// First finding must be HIGH.
	if len(report.Findings) == 0 {
		t.Fatal("no findings returned")
	}
	if report.Findings[0].Severity != models.SeverityHigh {
		t.Errorf("findings[0].Severity = %q; want HIGH", report.Findings[0].Severity)
	}
	// All subsequent findings must be <= severity of previous (non-ascending order).
	for i := 1; i < len(report.Findings); i++ {
		prev := severityRank[report.Findings[i-1].Severity]
		curr := severityRank[report.Findings[i].Severity]
		if curr < prev {
			t.Errorf("findings not sorted: position %d (%s) is more severe than position %d (%s)",
				i, report.Findings[i].Severity, i-1, report.Findings[i-1].Severity)
		}
	}
}

// TestKubernetesEngine_PolicyDomainDisabled verifies that when the kubernetes
// domain is disabled in the policy, all findings are suppressed.
func TestKubernetesEngine_PolicyDomainDisabled(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("default"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "policy-ctx"},
	}

	policyCfg := &policy.PolicyConfig{
		Version: 1,
		Domains: map[string]policy.DomainConfig{
			"kubernetes": {Enabled: false},
		},
	}

	eng := newK8sEngine(provider, policyCfg)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	if report.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings with domain disabled; got %d", report.Summary.TotalFindings)
	}
}

// TestKubernetesEngine_PolicyRuleDisabled verifies that a specific rule can be
// suppressed via the rules section of the policy config.
func TestKubernetesEngine_PolicyRuleDisabled(t *testing.T) {
	disabled := false
	policyCfg := &policy.PolicyConfig{
		Version: 1,
		Rules: map[string]policy.RuleConfig{
			"K8S_CLUSTER_SINGLE_NODE": {Enabled: &disabled},
		},
	}

	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("default"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "rule-disabled-ctx"},
	}

	eng := newK8sEngine(provider, policyCfg)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// K8S_CLUSTER_SINGLE_NODE should be suppressed; only MEDIUM namespace finding remains.
	for _, f := range report.Findings {
		if f.RuleID == "K8S_CLUSTER_SINGLE_NODE" {
			t.Errorf("K8S_CLUSTER_SINGLE_NODE finding present despite rule being disabled")
		}
	}
}

// TestKubernetesEngine_NodeOverallocated verifies that an overallocated node
// triggers K8S_NODE_OVERALLOCATED.
func TestKubernetesEngine_NodeOverallocated(t *testing.T) {
	// 400m / 4000m = 10% < 20% threshold → should fire
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "400m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "400m", "7Gi"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "overalloc-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var overallocCount int
	for _, f := range report.Findings {
		if f.RuleID == "K8S_NODE_OVERALLOCATED" {
			overallocCount++
		}
	}
	if overallocCount != 2 {
		t.Errorf("expected 2 K8S_NODE_OVERALLOCATED findings; got %d", overallocCount)
	}
}

// TestKubernetesEngine_NamespaceWithLimitRange verifies that a namespace that
// has a LimitRange does NOT trigger K8S_NAMESPACE_WITHOUT_LIMITS.
func TestKubernetesEngine_NamespaceWithLimitRange(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"), // 2 nodes: no single-node rule
		k8sNamespace("default"),
		k8sLimitRange("default", "resource-limits"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "lr-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "K8S_NAMESPACE_WITHOUT_LIMITS" {
			t.Errorf("K8S_NAMESPACE_WITHOUT_LIMITS fired for namespace with LimitRange")
		}
	}
}
