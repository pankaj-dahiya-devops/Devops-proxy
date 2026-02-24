package engine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
	ekspack "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rulepacks/kubernetes_eks"
)

// fakeEKSCollector is a test double for EKSDataCollector.
type fakeEKSCollector struct {
	data *models.KubernetesEKSData
	err  error
}

func (f *fakeEKSCollector) CollectEKSData(_ context.Context, _, _ string) (*models.KubernetesEKSData, error) {
	return f.data, f.err
}

// eksNode builds a corev1.Node with EKS-specific ProviderID and labels so that
// detectClusterProvider and extractEKSInfo identify it as an EKS node.
func eksNode(name, clusterName, region, az string) *corev1.Node {
	providerID := "aws:///" + az + "/i-" + name
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"eks.amazonaws.com/cluster-name":  clusterName,
				"topology.kubernetes.io/region":   region,
				"eks.amazonaws.com/nodegroup":     "ng-workers",
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: providerID,
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("3800m"),
				corev1.ResourceMemory: resource.MustParse("7Gi"),
			},
		},
	}
}

// newEKSEngine builds a KubernetesEngine with both core and EKS rule registries.
func newEKSEngine(provider kube.KubeClientProvider, collector EKSDataCollector) *KubernetesEngine {
	coreReg := rules.NewDefaultRuleRegistry()
	eksReg := rules.NewDefaultRuleRegistry()
	for _, r := range ekspack.New() {
		eksReg.Register(r)
	}
	return NewKubernetesEngineWithEKS(provider, coreReg, eksReg, collector, nil)
}

// ── detectClusterProvider ─────────────────────────────────────────────────────

func TestDetectClusterProvider_EKS_ProviderIDPrefix(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{ProviderID: "aws:///us-east-1a/i-0abc123"},
	}
	if got := detectClusterProvider(nodes); got != "eks" {
		t.Errorf("detectClusterProvider = %q; want eks", got)
	}
}

func TestDetectClusterProvider_GKE_ProviderIDPrefix(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{ProviderID: "gce://my-project/us-central1-a/gke-node"},
	}
	if got := detectClusterProvider(nodes); got != "gke" {
		t.Errorf("detectClusterProvider = %q; want gke", got)
	}
}

func TestDetectClusterProvider_AKS_ProviderIDPrefix(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{ProviderID: "azure:///subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/node"},
	}
	if got := detectClusterProvider(nodes); got != "aks" {
		t.Errorf("detectClusterProvider = %q; want aks", got)
	}
}

func TestDetectClusterProvider_EKS_LabelFallback(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{
			ProviderID: "",
			Labels:     map[string]string{"eks.amazonaws.com/nodegroup": "ng-workers"},
		},
	}
	if got := detectClusterProvider(nodes); got != "eks" {
		t.Errorf("detectClusterProvider = %q; want eks (label fallback)", got)
	}
}

func TestDetectClusterProvider_Unknown_NoProviderInfo(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "bare-node", ProviderID: "", Labels: map[string]string{}},
	}
	if got := detectClusterProvider(nodes); got != "unknown" {
		t.Errorf("detectClusterProvider = %q; want unknown", got)
	}
}

// ── extractEKSInfo ────────────────────────────────────────────────────────────

func TestExtractEKSInfo_FromLabels(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{
			Labels: map[string]string{
				"eks.amazonaws.com/cluster-name": "my-cluster",
				"topology.kubernetes.io/region":  "us-west-2",
			},
		},
	}
	clusterName, region := extractEKSInfo(nodes)
	if clusterName != "my-cluster" {
		t.Errorf("clusterName = %q; want my-cluster", clusterName)
	}
	if region != "us-west-2" {
		t.Errorf("region = %q; want us-west-2", region)
	}
}

func TestExtractEKSInfo_RegionFromAZInProviderID(t *testing.T) {
	// Only ProviderID provided; region derived from AZ.
	nodes := []models.KubernetesNodeData{
		{
			Labels:     map[string]string{"eks.amazonaws.com/cluster-name": "inferred-cluster"},
			ProviderID: "aws:///eu-west-1b/i-0abc",
		},
	}
	clusterName, region := extractEKSInfo(nodes)
	if clusterName != "inferred-cluster" {
		t.Errorf("clusterName = %q; want inferred-cluster", clusterName)
	}
	if region != "eu-west-1" {
		t.Errorf("region = %q; want eu-west-1 (derived from AZ eu-west-1b)", region)
	}
}

func TestExtractEKSInfo_EmptyNodes_ReturnsEmpty(t *testing.T) {
	clusterName, region := extractEKSInfo(nil)
	if clusterName != "" || region != "" {
		t.Errorf("expected empty strings; got clusterName=%q region=%q", clusterName, region)
	}
}

// ── NewKubernetesEngineWithEKS (integration) ──────────────────────────────────

func TestKubernetesEngineWithEKS_EKSRulesSkipped_NonEKSCluster(t *testing.T) {
	// Plain node with no EKS ProviderID or labels → provider = "unknown".
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "non-eks-ctx"},
	}

	// Collector that should never be called for a non-EKS cluster.
	collector := &fakeEKSCollector{
		data: &models.KubernetesEKSData{EncryptionKeyARN: ""}, // would trigger finding
	}

	eng := newEKSEngine(provider, collector)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "EKS_SECRETS_ENCRYPTION_DISABLED" {
			t.Errorf("EKS rule fired on non-EKS cluster: %s", f.RuleID)
		}
	}
}

func TestKubernetesEngineWithEKS_EKSRulesFire_OnEKSCluster(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "prod-cluster", "us-east-1", "us-east-1a"),
		eksNode("node-2", "prod-cluster", "us-east-1", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-ctx"},
	}

	// Return EKSData with secrets encryption disabled → EKS_SECRETS_ENCRYPTION_DISABLED fires.
	collector := &fakeEKSCollector{
		data: &models.KubernetesEKSData{
			ClusterName:          "prod-cluster",
			Region:               "us-east-1",
			EncryptionKeyARN:     "", // triggers EKS_SECRETS_ENCRYPTION_DISABLED
			EndpointPublicAccess: false,
		},
	}

	eng := newEKSEngine(provider, collector)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var found bool
	for _, f := range report.Findings {
		if f.RuleID == "EKS_SECRETS_ENCRYPTION_DISABLED" {
			found = true
		}
	}
	if !found {
		t.Error("expected EKS_SECRETS_ENCRYPTION_DISABLED finding; not found")
	}
}

func TestKubernetesEngineWithEKS_NilCollector_EKSRulesSkipGracefully(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "prod-cluster", "us-east-1", "us-east-1a"),
		eksNode("node-2", "prod-cluster", "us-east-1", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-nil-collector"},
	}

	// nil collector → EKS rules have nil EKSData → all skip gracefully.
	eng := newEKSEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		switch f.RuleID {
		case "EKS_PUBLIC_ENDPOINT_WIDE_OPEN",
			"EKS_SECRETS_ENCRYPTION_DISABLED",
			"EKS_CLUSTER_LOGGING_PARTIAL",
			"EKS_NODEGROUP_IMDSV2_NOT_ENFORCED",
			"EKS_NODE_VERSION_SKEW":
			t.Errorf("EKS rule %q fired with nil collector", f.RuleID)
		}
	}
}

// allReportRuleIDs returns a set of all rule IDs mentioned in the report,
// including those merged into Metadata["rules"] by mergeFindings.
func allReportRuleIDs(report *models.AuditReport) map[string]bool {
	ids := make(map[string]bool)
	for _, f := range report.Findings {
		ids[f.RuleID] = true
		if merged, ok := f.Metadata["rules"]; ok {
			if ruleList, ok := merged.([]string); ok {
				for _, rid := range ruleList {
					ids[rid] = true
				}
			}
		}
	}
	return ids
}

func TestKubernetesEngineWithEKS_MultipleEKSRulesFire(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "prod-cluster", "us-east-1", "us-east-1a"),
		eksNode("node-2", "prod-cluster", "us-east-1", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "multi-eks-ctx"},
	}

	// Configure EKSData to trigger all 5 EKS rules simultaneously.
	collector := &fakeEKSCollector{
		data: &models.KubernetesEKSData{
			ClusterName:          "prod-cluster",
			Region:               "us-east-1",
			ControlPlaneVersion:  "1.29",
			EndpointPublicAccess: true,
			PublicAccessCidrs:    []string{"0.0.0.0/0"}, // EKS_PUBLIC_ENDPOINT_WIDE_OPEN
			EncryptionKeyARN:     "",                    // EKS_SECRETS_ENCRYPTION_DISABLED
			EnabledLogTypes:      []string{"audit"},     // EKS_CLUSTER_LOGGING_PARTIAL
			NodeGroups: []models.KubernetesEKSNodeGroupData{
				{Name: "ng-1", HttpTokens: "optional", Version: "1.26"}, // IMDSv2 + skew
			},
		},
	}

	eng := newEKSEngine(provider, collector)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// mergeFindings groups by {resourceID, region}, so findings for the same cluster
	// or nodegroup are merged. Use allReportRuleIDs to check across merged findings.
	wantRules := []string{
		"EKS_PUBLIC_ENDPOINT_WIDE_OPEN",
		"EKS_SECRETS_ENCRYPTION_DISABLED",
		"EKS_CLUSTER_LOGGING_PARTIAL",
		"EKS_NODEGROUP_IMDSV2_NOT_ENFORCED",
		"EKS_NODE_VERSION_SKEW",
	}
	ruleIDs := allReportRuleIDs(report)
	for _, want := range wantRules {
		if !ruleIDs[want] {
			t.Errorf("expected finding for EKS rule %q; not present in report (checked RuleID + Metadata[rules])", want)
		}
	}
}
