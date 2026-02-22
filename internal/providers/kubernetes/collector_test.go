package kubernetes

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// boolPtr is a helper that returns a pointer to the given bool value.
func boolPtr(b bool) *bool { return &b }

// makePod is a test helper that builds a corev1.Pod with the given name,
// namespace, and containers.
func makePod(namespace, name string, containers []corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.PodSpec{Containers: containers},
	}
}

// makeContainer is a test helper that builds a corev1.Container.
func makeContainer(name string, privileged bool, cpuReq, memReq string) corev1.Container {
	sc := &corev1.SecurityContext{
		Privileged: boolPtr(privileged),
	}
	requests := corev1.ResourceList{}
	if cpuReq != "" {
		requests[corev1.ResourceCPU] = resource.MustParse(cpuReq)
	}
	if memReq != "" {
		requests[corev1.ResourceMemory] = resource.MustParse(memReq)
	}
	return corev1.Container{
		Name:            name,
		SecurityContext: sc,
		Resources: corev1.ResourceRequirements{
			Requests: requests,
		},
	}
}

// makeService is a test helper that builds a corev1.Service.
func makeService(namespace, name string, svcType corev1.ServiceType, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{Type: svcType},
	}
}

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

// TestCollectClusterData_PrivilegedContainer verifies that a pod with a
// privileged container has ContainerInfo.Privileged == true.
func TestCollectClusterData_PrivilegedContainer(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makePod("default", "priv-pod", []corev1.Container{
			makeContainer("priv-container", true, "100m", "128Mi"),
		}),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Pods) != 1 {
		t.Fatalf("Pods count = %d; want 1", len(data.Pods))
	}
	pod := data.Pods[0]
	if pod.Name != "priv-pod" {
		t.Errorf("pod Name = %q; want priv-pod", pod.Name)
	}
	if pod.Namespace != "default" {
		t.Errorf("pod Namespace = %q; want default", pod.Namespace)
	}
	if len(pod.Containers) != 1 {
		t.Fatalf("Containers count = %d; want 1", len(pod.Containers))
	}
	if !pod.Containers[0].Privileged {
		t.Error("Privileged = false; want true for privileged container")
	}
}

// TestCollectClusterData_NonPrivilegedContainer verifies that a pod without
// privileged containers has ContainerInfo.Privileged == false.
func TestCollectClusterData_NonPrivilegedContainer(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makePod("default", "normal-pod", []corev1.Container{
			makeContainer("app", false, "100m", "128Mi"),
		}),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Pods) != 1 {
		t.Fatalf("Pods count = %d; want 1", len(data.Pods))
	}
	if data.Pods[0].Containers[0].Privileged {
		t.Error("Privileged = true; want false for non-privileged container")
	}
}

// TestCollectClusterData_ContainerResourceRequests verifies that HasCPURequest
// and HasMemoryRequest are correctly detected.
func TestCollectClusterData_ContainerResourceRequests(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		// container-with: CPU + memory set; container-without: neither set
		makePod("default", "mixed-pod", []corev1.Container{
			makeContainer("with-requests", false, "250m", "256Mi"),
			makeContainer("no-requests", false, "", ""),
		}),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Pods) != 1 {
		t.Fatalf("Pods count = %d; want 1", len(data.Pods))
	}
	containers := data.Pods[0].Containers
	if len(containers) != 2 {
		t.Fatalf("Containers count = %d; want 2", len(containers))
	}

	withReq := containers[0]
	if !withReq.HasCPURequest {
		t.Error("HasCPURequest = false; want true for container with 250m CPU request")
	}
	if !withReq.HasMemoryRequest {
		t.Error("HasMemoryRequest = false; want true for container with 256Mi memory request")
	}

	noReq := containers[1]
	if noReq.HasCPURequest {
		t.Error("HasCPURequest = true; want false for container with no CPU request")
	}
	if noReq.HasMemoryRequest {
		t.Error("HasMemoryRequest = true; want false for container with no memory request")
	}
}

// TestCollectClusterData_ServiceLoadBalancer verifies that a LoadBalancer
// Service is collected with the correct type.
func TestCollectClusterData_ServiceLoadBalancer(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makeService("production", "web-lb", corev1.ServiceTypeLoadBalancer, nil),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Services) != 1 {
		t.Fatalf("Services count = %d; want 1", len(data.Services))
	}
	svc := data.Services[0]
	if svc.Name != "web-lb" {
		t.Errorf("Service Name = %q; want web-lb", svc.Name)
	}
	if svc.Namespace != "production" {
		t.Errorf("Service Namespace = %q; want production", svc.Namespace)
	}
	if svc.Type != "LoadBalancer" {
		t.Errorf("Service Type = %q; want LoadBalancer", svc.Type)
	}
}

// TestCollectClusterData_ServiceInternalAnnotation verifies that the internal
// load-balancer annotation is copied into ServiceInfo.Annotations.
func TestCollectClusterData_ServiceInternalAnnotation(t *testing.T) {
	annotations := map[string]string{
		"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
	}
	fakeClient := fake.NewSimpleClientset(
		makeService("default", "internal-lb", corev1.ServiceTypeLoadBalancer, annotations),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Services) != 1 {
		t.Fatalf("Services count = %d; want 1", len(data.Services))
	}
	svc := data.Services[0]
	got := svc.Annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
	if got != "true" {
		t.Errorf("internal annotation = %q; want true", got)
	}
}

// TestCollectClusterData_ServiceClusterIP verifies that a ClusterIP Service
// is collected with the correct type.
func TestCollectClusterData_ServiceClusterIP(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		makeService("default", "internal-svc", corev1.ServiceTypeClusterIP, nil),
	)

	data, err := CollectClusterData(context.Background(), fakeClient, ClusterInfo{})
	if err != nil {
		t.Fatalf("CollectClusterData error: %v", err)
	}
	if len(data.Services) != 1 {
		t.Fatalf("Services count = %d; want 1", len(data.Services))
	}
	if data.Services[0].Type != "ClusterIP" {
		t.Errorf("Service Type = %q; want ClusterIP", data.Services[0].Type)
	}
}
