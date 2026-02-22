package kubernetes

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// makeNode is a test helper that builds a corev1.Node with the given name,
// CPU capacity, memory capacity, allocatable CPU, and allocatable memory.
func makeNode(name, cpuCap, memCap, cpuAlloc, memAlloc string) *corev1.Node {
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

// makeNamespace is a test helper that builds a corev1.Namespace.
func makeNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
}

// makeLimitRange is a test helper that builds a corev1.LimitRange in a namespace.
func makeLimitRange(namespace, name string) *corev1.LimitRange {
	return &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

// TestCollectClusterData_TwoNodesThreeNamespaces verifies that CollectClusterData
// correctly populates Nodes and Namespaces from a cluster with known objects.
func TestCollectClusterData_TwoNodesThreeNamespaces(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makeNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		makeNode("node-2", "8", "16Gi", "7600m", "15Gi"),
		makeNamespace("default"),
		makeNamespace("kube-system"),
		makeNamespace("production"),
	)

	info := ClusterInfo{ContextName: "test-context", Server: "https://127.0.0.1:6443"}
	data, err := CollectClusterData(context.Background(), fakeClient, info)
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}

	if data.ClusterInfo != info {
		t.Errorf("ClusterInfo = %+v; want %+v", data.ClusterInfo, info)
	}
	if len(data.Nodes) != 2 {
		t.Errorf("Nodes count = %d; want 2", len(data.Nodes))
	}
	if len(data.Namespaces) != 3 {
		t.Errorf("Namespaces count = %d; want 3", len(data.Namespaces))
	}
}

// TestCollectClusterData_NodeFields verifies that all NodeInfo fields are
// populated from the node's capacity and allocatable resource lists.
func TestCollectClusterData_NodeFields(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makeNode("worker-1", "4", "8Gi", "3800m", "7168Mi"),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Nodes) != 1 {
		t.Fatalf("Nodes count = %d; want 1", len(data.Nodes))
	}

	n := data.Nodes[0]
	if n.Name != "worker-1" {
		t.Errorf("Name = %q; want worker-1", n.Name)
	}
	if n.CPUCapacity == "" {
		t.Error("CPUCapacity must not be empty")
	}
	if n.MemoryCapacity == "" {
		t.Error("MemoryCapacity must not be empty")
	}
	if n.AllocatableCPU == "" {
		t.Error("AllocatableCPU must not be empty")
	}
	if n.AllocatableMemory == "" {
		t.Error("AllocatableMemory must not be empty")
	}
}

// TestCollectClusterData_NodeCPUMillis verifies that CPUCapacityMillis and
// AllocatableCPUMillis are correctly parsed from the node's resource quantities.
func TestCollectClusterData_NodeCPUMillis(t *testing.T) {
	// node-a: 4 CPUs capacity, 3800m allocatable
	fakeClient := fake.NewSimpleClientset(
		makeNode("node-a", "4", "8Gi", "3800m", "7Gi"),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Nodes) != 1 {
		t.Fatalf("Nodes count = %d; want 1", len(data.Nodes))
	}

	n := data.Nodes[0]
	if n.CPUCapacityMillis != 4000 {
		t.Errorf("CPUCapacityMillis = %d; want 4000", n.CPUCapacityMillis)
	}
	if n.AllocatableCPUMillis != 3800 {
		t.Errorf("AllocatableCPUMillis = %d; want 3800", n.AllocatableCPUMillis)
	}
}

// TestCollectClusterData_HasLimitRange_True verifies that HasLimitRange is true
// when a LimitRange object exists in a namespace.
func TestCollectClusterData_HasLimitRange_True(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makeNamespace("staging"),
		makeLimitRange("staging", "default-limits"),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Namespaces) != 1 {
		t.Fatalf("Namespaces count = %d; want 1", len(data.Namespaces))
	}
	if !data.Namespaces[0].HasLimitRange {
		t.Error("HasLimitRange = false; want true for namespace with LimitRange")
	}
}

// TestCollectClusterData_HasLimitRange_False verifies that HasLimitRange is false
// when no LimitRange exists in a namespace.
func TestCollectClusterData_HasLimitRange_False(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makeNamespace("production"),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Namespaces) != 1 {
		t.Fatalf("Namespaces count = %d; want 1", len(data.Namespaces))
	}
	if data.Namespaces[0].HasLimitRange {
		t.Error("HasLimitRange = true; want false for namespace without LimitRange")
	}
}

// TestCollectClusterData_NamespaceNames verifies that all namespace names are
// collected without duplication or omission.
func TestCollectClusterData_NamespaceNames(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makeNamespace("default"),
		makeNamespace("monitoring"),
		makeNamespace("staging"),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}

	want := map[string]bool{"default": true, "monitoring": true, "staging": true}
	for _, ns := range data.Namespaces {
		if !want[ns.Name] {
			t.Errorf("unexpected namespace %q in results", ns.Name)
		}
		delete(want, ns.Name)
	}
	for missing := range want {
		t.Errorf("namespace %q missing from results", missing)
	}
}

// TestCollectClusterData_EmptyCluster verifies that an empty cluster returns
// empty slices (not nil) and no error.
func TestCollectClusterData_EmptyCluster(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{ContextName: "empty"})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Nodes) != 0 {
		t.Errorf("Nodes count = %d; want 0", len(data.Nodes))
	}
	if len(data.Namespaces) != 0 {
		t.Errorf("Namespaces count = %d; want 0", len(data.Namespaces))
	}
	if data.ClusterInfo.ContextName != "empty" {
		t.Errorf("ClusterInfo.ContextName = %q; want empty", data.ClusterInfo.ContextName)
	}
}
