package engine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// chainPrivAndSysAdminPod creates a pod that is both privileged and adds
// SYS_ADMIN capability. Fires K8S_PRIVILEGED_CONTAINER + K8S_POD_PRIVILEGED_CONTAINER
// (both CRITICAL) and K8S_POD_CAP_SYS_ADMIN (HIGH) — all merged into one finding.
func chainPrivAndSysAdminPod(name, ns string) *corev1.Pod {
	priv := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv,
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_ADMIN"},
						},
					},
				},
			},
		},
	}
}

// chainSysAdminPod creates a pod that adds SYS_ADMIN capability only (not privileged).
// Fires K8S_POD_CAP_SYS_ADMIN (HIGH).
func chainSysAdminPod(name, ns string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_ADMIN"},
						},
					},
				},
			},
		},
	}
}

// correlationEngine builds a KubernetesEngine backed by the full kubernetes_core
// pack using the given fake clientset and context name.
func correlationEngine(cs *fake.Clientset, contextName string) *KubernetesEngine {
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: contextName, Server: "https://fake"},
	}
	return newK8sEngine(provider, nil)
}

// ── Unit tests: ruleIDsForFinding ─────────────────────────────────────────────

// TestRuleIDsForFinding_PrimaryOnly verifies that a finding with no merged rules
// returns only the primary RuleID.
func TestRuleIDsForFinding_PrimaryOnly(t *testing.T) {
	f := models.Finding{RuleID: "K8S_PRIVILEGED_CONTAINER"}
	ids := ruleIDsForFinding(&f)
	if len(ids) != 1 || ids[0] != "K8S_PRIVILEGED_CONTAINER" {
		t.Errorf("expected [K8S_PRIVILEGED_CONTAINER]; got %v", ids)
	}
}

// TestRuleIDsForFinding_WithMergedRules verifies that rule IDs in
// Metadata["rules"] are included alongside the primary RuleID.
func TestRuleIDsForFinding_WithMergedRules(t *testing.T) {
	f := models.Finding{
		RuleID: "K8S_PRIVILEGED_CONTAINER",
		Metadata: map[string]any{
			"rules": []string{"K8S_POD_PRIVILEGED_CONTAINER", "K8S_POD_CAP_SYS_ADMIN"},
		},
	}
	ids := ruleIDsForFinding(&f)
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs; got %v", ids)
	}
	want := map[string]struct{}{
		"K8S_PRIVILEGED_CONTAINER":    {},
		"K8S_POD_PRIVILEGED_CONTAINER": {},
		"K8S_POD_CAP_SYS_ADMIN":       {},
	}
	for _, id := range ids {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected rule ID %q in result", id)
		}
	}
}

// TestRuleIDsForFinding_NilMetadata verifies that nil Metadata does not panic
// and only the primary RuleID is returned.
func TestRuleIDsForFinding_NilMetadata(t *testing.T) {
	f := models.Finding{RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nil}
	ids := ruleIDsForFinding(&f)
	if len(ids) != 1 || ids[0] != "K8S_POD_RUN_AS_ROOT" {
		t.Errorf("expected [K8S_POD_RUN_AS_ROOT]; got %v", ids)
	}
}

// ── Unit tests: buildNamespaceRuleIndex ───────────────────────────────────────

// TestBuildNamespaceRuleIndex_BasicMapping verifies that the index correctly
// maps each namespace to the rule IDs of its findings.
func TestBuildNamespaceRuleIndex_BasicMapping(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_POD_RUN_AS_ROOT",
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_DEFAULT_SERVICEACCOUNT_USED",
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			// No namespace — cluster-scoped; must not appear in index.
		},
	}
	index := buildNamespaceRuleIndex(findings)

	if !nsIndexHas(index, "production", "K8S_SERVICE_PUBLIC_LOADBALANCER") {
		t.Error("expected K8S_SERVICE_PUBLIC_LOADBALANCER in production index")
	}
	if !nsIndexHas(index, "production", "K8S_POD_RUN_AS_ROOT") {
		t.Error("expected K8S_POD_RUN_AS_ROOT in production index")
	}
	if !nsIndexHas(index, "apps", "K8S_DEFAULT_SERVICEACCOUNT_USED") {
		t.Error("expected K8S_DEFAULT_SERVICEACCOUNT_USED in apps index")
	}
	if _, ok := index[""]; ok {
		t.Error("cluster-scoped finding (empty namespace) must not appear in the index")
	}
}

// TestBuildNamespaceRuleIndex_MergedRulesExpanded verifies that merged rule IDs
// from Metadata["rules"] are expanded into the namespace index.
func TestBuildNamespaceRuleIndex_MergedRulesExpanded(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_PRIVILEGED_CONTAINER",
			ResourceType: models.ResourceK8sPod,
			Metadata: map[string]any{
				"namespace": "production",
				"rules":     []string{"K8S_POD_CAP_SYS_ADMIN"},
			},
		},
	}
	index := buildNamespaceRuleIndex(findings)
	if !nsIndexHas(index, "production", "K8S_PRIVILEGED_CONTAINER") {
		t.Error("expected K8S_PRIVILEGED_CONTAINER in production index")
	}
	if !nsIndexHas(index, "production", "K8S_POD_CAP_SYS_ADMIN") {
		t.Error("expected merged K8S_POD_CAP_SYS_ADMIN in production index")
	}
}

// ── Unit tests: correlateRiskChains direct calls ──────────────────────────────

// TestCorrelateRiskChains_NoFindings verifies that nil and empty input do not panic.
func TestCorrelateRiskChains_NoFindings(t *testing.T) {
	correlateRiskChains(nil)
	correlateRiskChains([]models.Finding{})
}

// TestCorrelateRiskChains_Chain1_DirectUnit verifies that chain 1 annotates
// both the LB service finding and the pod-with-run-as-root finding in the same
// namespace with score=80.
func TestCorrelateRiskChains_Chain1_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_POD_RUN_AS_ROOT",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "root-pod",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("finding %q: risk_chain_score = %v; want 80", f.ResourceID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Public service exposes privileged workload" {
			t.Errorf("finding %q: risk_chain_reason = %q; want 'Public service exposes privileged workload'", f.ResourceID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain1_CapSysAdmin verifies that K8S_POD_CAP_SYS_ADMIN
// also triggers chain 1 (not just K8S_POD_RUN_AS_ROOT).
func TestCorrelateRiskChains_Chain1_CapSysAdmin(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "staging"},
		},
		{
			RuleID:       "K8S_POD_CAP_SYS_ADMIN",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "cap-pod",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "staging"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("finding %q: risk_chain_score = %v; want 80", f.ResourceID, f.Metadata["risk_chain_score"])
		}
	}
}

// TestCorrelateRiskChains_Chain1_NegativeDifferentNamespaces verifies that chain 1
// does NOT fire when LB and privileged pod are in different namespaces.
func TestCorrelateRiskChains_Chain1_NegativeDifferentNamespaces(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_POD_RUN_AS_ROOT",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "root-pod",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "staging"}, // different namespace
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("finding %q should have no chain annotation; got risk_chain_score=%v",
				f.ResourceID, f.Metadata["risk_chain_score"])
		}
	}
}

// TestCorrelateRiskChains_Chain1_NegativeLBOnly verifies that a standalone LB
// finding with no privileged pod in the same namespace is not annotated.
func TestCorrelateRiskChains_Chain1_NegativeLBOnly(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
	}
	correlateRiskChains(findings)
	if _, ok := findings[0].Metadata["risk_chain_score"]; ok {
		t.Errorf("standalone LB finding should not have chain annotation; got %v",
			findings[0].Metadata["risk_chain_score"])
	}
}

// TestCorrelateRiskChains_Chain2_DirectUnit verifies that chain 2 annotates
// both the default-SA pod finding and the SA automount finding in the same
// namespace with score=60.
func TestCorrelateRiskChains_Chain2_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_DEFAULT_SERVICEACCOUNT_USED",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "app-pod",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT",
			ResourceType: models.ResourceK8sServiceAccount,
			ResourceID:   "default",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "apps"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 60 {
			t.Errorf("finding %q: risk_chain_score = %v; want 60", f.ResourceID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Default service account with auto-mounted token" {
			t.Errorf("finding %q: risk_chain_reason = %q; want 'Default service account with auto-mounted token'",
				f.ResourceID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain2_NegativeNoDefaultSA verifies that chain 2 does
// NOT fire when there is an SA automount finding but no default-SA pod finding
// in the same namespace.
func TestCorrelateRiskChains_Chain2_NegativeNoDefaultSA(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT",
			ResourceType: models.ResourceK8sServiceAccount,
			ResourceID:   "custom-sa",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		// No K8S_DEFAULT_SERVICEACCOUNT_USED in "apps".
	}
	correlateRiskChains(findings)
	if _, ok := findings[0].Metadata["risk_chain_score"]; ok {
		t.Errorf("SA automount finding without default SA should not have chain annotation; got %v",
			findings[0].Metadata["risk_chain_score"])
	}
}

// TestCorrelateRiskChains_Chain3_DirectUnit verifies that chain 3 annotates
// both the K8S_CLUSTER_SINGLE_NODE finding and the CRITICAL pod finding with
// score=50.
func TestCorrelateRiskChains_Chain3_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "test-cluster",
			Severity:     models.SeverityHigh,
			// No namespace — cluster-scoped.
		},
		{
			RuleID:       "K8S_POD_PRIVILEGED_CONTAINER",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "priv-pod",
			Severity:     models.SeverityCritical,
			Metadata:     map[string]any{"namespace": "production"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 50 {
			t.Errorf("finding %q: risk_chain_score = %v; want 50", f.ResourceID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Single-node cluster with critical pod security violation" {
			t.Errorf("finding %q: risk_chain_reason = %q; want 'Single-node cluster with critical pod security violation'",
				f.ResourceID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain3_NegativeNoCritical verifies that chain 3 does
// NOT fire when the cluster has a single node but no CRITICAL finding exists.
func TestCorrelateRiskChains_Chain3_NegativeNoCritical(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "test-cluster",
			Severity:     models.SeverityHigh, // HIGH, not CRITICAL
		},
		{
			RuleID:       "K8S_NAMESPACE_WITHOUT_LIMITS",
			ResourceType: models.ResourceK8sNamespace,
			ResourceID:   "default",
			Severity:     models.SeverityMedium,
		},
	}
	correlateRiskChains(findings)
	for _, f := range findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("finding %q should have no chain annotation (no CRITICAL); got %v",
				f.ResourceID, f.Metadata["risk_chain_score"])
		}
	}
}

// TestCorrelateRiskChains_HighestScoreWins_DirectUnit verifies that when a
// finding participates in multiple chains, the highest score is kept.
func TestCorrelateRiskChains_HighestScoreWins_DirectUnit(t *testing.T) {
	// bad-pod finding: has K8S_POD_CAP_SYS_ADMIN (chain 1 eligible) and is CRITICAL (chain 3 eligible).
	// LB finding in same namespace triggers chain 1 (score 80) for bad-pod.
	// single-node finding triggers chain 3 (score 50) for bad-pod.
	// Highest should win: 80.
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_POD_CAP_SYS_ADMIN",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "bad-pod",
			Severity:     models.SeverityCritical, // CRITICAL so chain 3 also considers it
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "test-cluster",
			Severity:     models.SeverityHigh,
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		if f.ResourceID != "bad-pod" {
			continue
		}
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("bad-pod: risk_chain_score = %v; want 80 (chain 1 > chain 3)", f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Public service exposes privileged workload" {
			t.Errorf("bad-pod: risk_chain_reason = %q; want chain 1 reason", reason)
		}
		return
	}
	t.Error("expected bad-pod finding")
}

// ── Engine-level integration tests ───────────────────────────────────────────

// TestCorrelationEngine_Chain1_BothFindingsAnnotated verifies that at engine level,
// both the public LB service finding and the run-as-root pod finding in the same
// namespace receive risk_chain_score=80.
func TestCorrelationEngine_Chain1_BothFindingsAnnotated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "chain1-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var lbAnnotated, podAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = ok && score == 80
		}
		if idsContain(ids, "K8S_POD_RUN_AS_ROOT") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			podAnnotated = ok && score == 80
		}
	}
	if !lbAnnotated {
		t.Error("K8S_SERVICE_PUBLIC_LOADBALANCER finding should have risk_chain_score=80")
	}
	if !podAnnotated {
		t.Error("K8S_POD_RUN_AS_ROOT finding should have risk_chain_score=80")
	}
}

// TestCorrelationEngine_Chain1_DifferentNamespaces verifies that chain 1 does
// NOT fire when the LB service and the privileged pod are in different namespaces.
func TestCorrelationEngine_Chain1_DifferentNamespaces(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "staging"), // different namespace
	)
	report, err := correlationEngine(cs, "chain1-diff-ns-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (different namespaces); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_Chain2_BothFindingsAnnotated verifies that both the
// default-SA pod finding and the SA automount finding in the same namespace
// receive risk_chain_score=60 at engine level.
func TestCorrelationEngine_Chain2_BothFindingsAnnotated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		nsWithPSA("apps", "restricted"), // suppress namespace-level PSS/limits findings
		saAutoMountFake("default", "apps"),
		podWithDefaultSA("app-pod", "apps"),
	)
	report, err := correlationEngine(cs, "chain2-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var saAnnotated, podAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			saAnnotated = ok && score == 60
		}
		if idsContain(ids, "K8S_DEFAULT_SERVICEACCOUNT_USED") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			podAnnotated = ok && score == 60
		}
	}
	if !saAnnotated {
		t.Error("K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT finding should have risk_chain_score=60")
	}
	if !podAnnotated {
		t.Error("K8S_DEFAULT_SERVICEACCOUNT_USED finding should have risk_chain_score=60")
	}
}

// TestCorrelationEngine_Chain2_NoDefaultSA verifies that chain 2 does NOT fire
// when the pod uses a custom (non-default) ServiceAccount even if the SA has
// automount enabled.
func TestCorrelationEngine_Chain2_NoDefaultSA(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		nsWithPSA("apps", "restricted"),
		saAutoMountFake("custom-sa", "apps"),
		podWithCustomSA("app-pod", "apps", "custom-sa"),
	)
	report, err := correlationEngine(cs, "chain2-no-default-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (custom SA); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_Chain3_BothFindingsAnnotated verifies that both the
// K8S_CLUSTER_SINGLE_NODE finding and the CRITICAL pod finding receive
// risk_chain_score=50.
func TestCorrelationEngine_Chain3_BothFindingsAnnotated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"), // single node — fires K8S_CLUSTER_SINGLE_NODE
		pssPrivilegedPod("priv-pod", "production"),      // CRITICAL
	)
	report, err := correlationEngine(cs, "chain3-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var singleNodeAnnotated, criticalAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_CLUSTER_SINGLE_NODE") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			singleNodeAnnotated = ok && score == 50
		}
		if f.Severity == models.SeverityCritical {
			score, ok := f.Metadata["risk_chain_score"].(int)
			criticalAnnotated = ok && score == 50
		}
	}
	if !singleNodeAnnotated {
		t.Error("K8S_CLUSTER_SINGLE_NODE finding should have risk_chain_score=50")
	}
	if !criticalAnnotated {
		t.Error("CRITICAL finding should have risk_chain_score=50")
	}
}

// TestCorrelationEngine_Chain3_MultipleNodes verifies that chain 3 does NOT fire
// when the cluster has multiple nodes (no K8S_CLUSTER_SINGLE_NODE finding).
func TestCorrelationEngine_Chain3_MultipleNodes(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"), // multiple nodes
		pssPrivilegedPod("priv-pod", "production"),      // CRITICAL
	)
	report, err := correlationEngine(cs, "chain3-multi-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (multiple nodes); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_Chain3_NoCritical verifies that chain 3 does NOT fire
// when the cluster has a single node but no CRITICAL findings exist.
func TestCorrelationEngine_Chain3_NoCritical(t *testing.T) {
	// 1 node fires K8S_CLUSTER_SINGLE_NODE (HIGH) only; no pods = no CRITICAL.
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
	)
	report, err := correlationEngine(cs, "chain3-no-crit-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (no CRITICAL finding); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_HighestScoreWins verifies that a finding participating in
// both chain 1 (score 80) and chain 3 (score 50) keeps the highest score (80).
// Setup: 1 node + public LB in "apps" + pod with SYS_ADMIN+privileged in "apps".
// The merged pod finding is CRITICAL (chain 3: 50) and has K8S_POD_CAP_SYS_ADMIN
// with LB in same namespace (chain 1: 80).  Chain 1 wins.
func TestCorrelationEngine_HighestScoreWins(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sService("apps", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		chainPrivAndSysAdminPod("bad-pod", "apps"),
	)
	report, err := correlationEngine(cs, "highest-score-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// bad-pod merges: K8S_PRIVILEGED_CONTAINER + K8S_POD_PRIVILEGED_CONTAINER (CRITICAL)
	// + K8S_POD_CAP_SYS_ADMIN (HIGH) → one CRITICAL merged finding with K8S_POD_CAP_SYS_ADMIN
	// in ruleIDsForFinding.
	// Chain 1: nsHasLB=true, isPriv=true (K8S_POD_CAP_SYS_ADMIN) → score 80.
	// Chain 3: isCritical=true, hasSingleNode=true → score 50.
	// Highest = 80.
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if !idsContain(ids, "K8S_POD_CAP_SYS_ADMIN") {
			continue
		}
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("bad-pod finding: risk_chain_score = %v; want 80", f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Public service exposes privileged workload" {
			t.Errorf("bad-pod finding: risk_chain_reason = %q; want chain 1 reason", reason)
		}
		return
	}
	t.Error("expected finding with K8S_POD_CAP_SYS_ADMIN in ruleIDsForFinding; not found")
}

// TestCorrelationEngine_SortingUnaffected verifies that risk_chain annotations
// do not change the CRITICAL → HIGH → MEDIUM sort order of findings.
func TestCorrelationEngine_SortingUnaffected(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssPrivilegedPod("priv-pod", "production"), // CRITICAL
		pssRunAsRootPod("root-pod", "production"),  // HIGH (+ chain 1)
	)
	report, err := correlationEngine(cs, "sort-unaffected-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	if len(report.Findings) < 2 {
		t.Fatal("expected at least 2 findings")
	}
	// Findings must remain sorted highest severity first.
	for i := 1; i < len(report.Findings); i++ {
		prev := severityRank[report.Findings[i-1].Severity]
		curr := severityRank[report.Findings[i].Severity]
		if curr < prev {
			t.Errorf("findings not sorted at position %d (%s) vs %d (%s)",
				i, report.Findings[i].Severity, i-1, report.Findings[i-1].Severity)
		}
	}
	// CRITICAL finding must be first.
	if report.Findings[0].Severity != models.SeverityCritical {
		t.Errorf("findings[0].Severity = %q; want CRITICAL", report.Findings[0].Severity)
	}
}

// TestCorrelationEngine_Chain1_CapSysAdmin_Engine verifies that K8S_POD_CAP_SYS_ADMIN
// (not just K8S_POD_RUN_AS_ROOT) also triggers chain 1 at engine level.
func TestCorrelationEngine_Chain1_CapSysAdmin_Engine(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		chainSysAdminPod("sysadmin-pod", "production"),
	)
	report, err := correlationEngine(cs, "chain1-cap-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var lbAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = ok && score == 80
		}
	}
	if !lbAnnotated {
		t.Error("K8S_SERVICE_PUBLIC_LOADBALANCER should have risk_chain_score=80 when CAP_SYS_ADMIN pod is in same namespace")
	}
}

// TestCorrelationEngine_ExcludeSystem_ChainStillFires verifies that correlation
// works correctly when ExcludeSystem=true; workload findings still get annotated.
func TestCorrelationEngine_ExcludeSystem_ChainStillFires(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		// Workload namespace findings — should be correlated.
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
		// System namespace pod — excluded before correlation.
		k8sPod("kube-system", "sys-priv", true, "100m", "128Mi"),
	)
	report, err := correlationEngine(cs, "excl-chain-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		ExcludeSystem: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var lbAnnotated bool
	for _, f := range report.Findings {
		// No system findings should survive.
		if nst, ok := f.Metadata["namespace_type"].(string); ok && nst == "system" {
			t.Errorf("system finding %q survived ExcludeSystem=true", f.ResourceID)
		}
		ids := ruleIDsForFinding(&f)
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = ok && score == 80
		}
	}
	if !lbAnnotated {
		t.Error("workload LB finding should still have risk_chain_score=80 with ExcludeSystem=true")
	}
}

// ── Unit tests: getRiskScore ──────────────────────────────────────────────────

// TestGetRiskScore_Present verifies that getRiskScore returns the stored int score.
func TestGetRiskScore_Present(t *testing.T) {
	f := models.Finding{
		RuleID:   "K8S_SERVICE_PUBLIC_LOADBALANCER",
		Metadata: map[string]any{"risk_chain_score": 80},
	}
	if got := getRiskScore(f); got != 80 {
		t.Errorf("getRiskScore = %d; want 80", got)
	}
}

// TestGetRiskScore_Absent verifies that getRiskScore returns 0 when the key is missing.
func TestGetRiskScore_Absent(t *testing.T) {
	f := models.Finding{RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: map[string]any{"namespace": "prod"}}
	if got := getRiskScore(f); got != 0 {
		t.Errorf("getRiskScore = %d; want 0", got)
	}
}

// TestGetRiskScore_NilMetadata verifies that getRiskScore does not panic on nil Metadata.
func TestGetRiskScore_NilMetadata(t *testing.T) {
	f := models.Finding{RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nil}
	if got := getRiskScore(f); got != 0 {
		t.Errorf("getRiskScore = %d; want 0", got)
	}
}

// ── Engine-level summary.risk_score tests ─────────────────────────────────────

// TestCorrelationEngine_SummaryRiskScore_Chain1 verifies that when chain 1 fires
// (public LB + privileged workload in same namespace), report.Summary.RiskScore == 80.
func TestCorrelationEngine_SummaryRiskScore_Chain1(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "summary-risk-chain1-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if report.Summary.RiskScore != 80 {
		t.Errorf("Summary.RiskScore = %d; want 80 (chain 1 triggered)", report.Summary.RiskScore)
	}
}

// TestCorrelationEngine_SummaryRiskScore_NoChain verifies that when no risk chain
// fires, report.Summary.RiskScore == 0.
func TestCorrelationEngine_SummaryRiskScore_NoChain(t *testing.T) {
	// Two nodes, no pods, no services — only K8S_NAMESPACE_WITHOUT_LIMITS on default ns.
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
	)
	report, err := correlationEngine(cs, "summary-risk-nochain-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if report.Summary.RiskScore != 0 {
		t.Errorf("Summary.RiskScore = %d; want 0 (no chain triggered)", report.Summary.RiskScore)
	}
}

// ── Unit tests: filterByMinRiskScore ─────────────────────────────────────────

// TestFilterByMinRiskScore_KeepsAboveMin verifies that findings at or above the
// minimum score are retained.
func TestFilterByMinRiskScore_KeepsAboveMin(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"risk_chain_score": 60}},
		{RuleID: "C", Metadata: map[string]any{"risk_chain_score": 50}},
	}
	got := filterByMinRiskScore(findings, 60)
	if len(got) != 2 {
		t.Fatalf("filterByMinRiskScore(60) returned %d findings; want 2", len(got))
	}
	for _, f := range got {
		if getRiskScore(f) < 60 {
			t.Errorf("finding %q has score %d; should have been excluded", f.RuleID, getRiskScore(f))
		}
	}
}

// TestFilterByMinRiskScore_ExcludesNoScore verifies that findings with no
// risk_chain_score (score == 0) are excluded when min > 0.
func TestFilterByMinRiskScore_ExcludesNoScore(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"namespace": "prod"}}, // no score
		{RuleID: "C", Metadata: nil},                                  // nil metadata
	}
	got := filterByMinRiskScore(findings, 10)
	if len(got) != 1 || got[0].RuleID != "A" {
		t.Errorf("filterByMinRiskScore(10) returned %v; want [A]", got)
	}
}

// TestFilterByMinRiskScore_AllExcluded verifies that a threshold higher than any
// chain score results in an empty slice.
func TestFilterByMinRiskScore_AllExcluded(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"risk_chain_score": 60}},
	}
	got := filterByMinRiskScore(findings, 90)
	if len(got) != 0 {
		t.Errorf("filterByMinRiskScore(90) returned %d findings; want 0", len(got))
	}
}

// TestFilterByMinRiskScore_ZeroMinReturnsAll verifies that min==0 is a no-op
// (all findings returned). The engine guards with opts.MinRiskScore > 0 before
// calling filterByMinRiskScore, but the function itself must also be safe at 0.
func TestFilterByMinRiskScore_ZeroMinReturnsAll(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"namespace": "prod"}},
	}
	got := filterByMinRiskScore(findings, 0)
	if len(got) != 2 {
		t.Errorf("filterByMinRiskScore(0) returned %d findings; want 2 (all)", len(got))
	}
}

// ── Engine-level integration tests: MinRiskScore ─────────────────────────────

// TestCorrelationEngine_MinRiskScore_Chain1_PassesAt60 verifies that with
// MinRiskScore=60, chain 1 findings (score 80) are retained in the report.
func TestCorrelationEngine_MinRiskScore_Chain1_PassesAt60(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "min-risk-60-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 60,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected findings with MinRiskScore=60 when chain 1 (score 80) fires")
	}
	for _, f := range report.Findings {
		if getRiskScore(f) < 60 {
			t.Errorf("finding %q has score %d; should have been excluded by MinRiskScore=60",
				f.RuleID, getRiskScore(f))
		}
	}
}

// TestCorrelationEngine_MinRiskScore_Chain1_ExcludedAt90 verifies that with
// MinRiskScore=90, chain 1 findings (score 80) are excluded and the report is empty.
func TestCorrelationEngine_MinRiskScore_Chain1_ExcludedAt90(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "min-risk-90-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 90,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings with MinRiskScore=90 (chain 1 score is 80); got %d", len(report.Findings))
	}
}

// TestCorrelationEngine_MinRiskScore_NoChain_ExcludedAt10 verifies that when no
// chain fires (all scores are 0), MinRiskScore=10 excludes all findings.
func TestCorrelationEngine_MinRiskScore_NoChain_ExcludedAt10(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
	)
	report, err := correlationEngine(cs, "min-risk-no-chain-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 10,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings with MinRiskScore=10 and no chain; got %d", len(report.Findings))
	}
}

// TestCorrelationEngine_MinRiskScore_SummaryRiskScoreUnchanged verifies that
// Summary.RiskScore reflects the pre-filter risk picture even when MinRiskScore
// causes all findings to be excluded.
func TestCorrelationEngine_MinRiskScore_SummaryRiskScoreUnchanged(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "min-risk-summary-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 90, // excludes all (chain 1 score is 80)
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	// Findings filtered out, but Summary.RiskScore must still show the chain 1 score.
	if report.Summary.RiskScore != 80 {
		t.Errorf("Summary.RiskScore = %d; want 80 (pre-filter chain 1 score preserved)", report.Summary.RiskScore)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings (all excluded by MinRiskScore=90); got %d", len(report.Findings))
	}
}

// TestCorrelationEngine_MinRiskScore_SortingUnaffected verifies that findings
// retained after MinRiskScore filtering remain in CRITICAL → HIGH → MEDIUM order.
func TestCorrelationEngine_MinRiskScore_SortingUnaffected(t *testing.T) {
	// Chain 1 (score 80): LB in production + run-as-root pod in production
	// Chain 3 (score 50): single node + CRITICAL pod
	// MinRiskScore=60 → only chain 1 findings (80) survive
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssPrivilegedPod("priv-pod", "production"), // CRITICAL — chain 3 (50)
		pssRunAsRootPod("root-pod", "production"),  // HIGH — chain 1 (80)
	)
	report, err := correlationEngine(cs, "min-risk-sort-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 60,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	for i := 1; i < len(report.Findings); i++ {
		prev := severityRank[report.Findings[i-1].Severity]
		curr := severityRank[report.Findings[i].Severity]
		if curr < prev {
			t.Errorf("findings not sorted at position %d (%s) after MinRiskScore filter",
				i, report.Findings[i].Severity)
		}
	}
}
