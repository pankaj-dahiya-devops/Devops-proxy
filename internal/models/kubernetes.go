package models

// KubernetesNodeData holds processed node resource data consumed by K8s rules.
type KubernetesNodeData struct {
	// Name is the Kubernetes node name.
	Name string

	// CPUCapacityMillis is the total CPU capacity in millicores
	// (e.g. a "4" CPU node → 4000).
	CPUCapacityMillis int64

	// AllocatableCPUMillis is the allocatable CPU in millicores
	// (capacity minus system and kubelet reservations).
	AllocatableCPUMillis int64
}

// KubernetesNamespaceData holds processed namespace data consumed by K8s rules.
type KubernetesNamespaceData struct {
	// Name is the Kubernetes namespace name.
	Name string

	// HasLimitRange is true when at least one LimitRange object exists
	// in the namespace, indicating default resource limits are configured.
	HasLimitRange bool
}

// KubernetesClusterData holds all cluster inventory consumed by Kubernetes rules.
// It is the K8s equivalent of RegionData and is passed via RuleContext.ClusterData.
type KubernetesClusterData struct {
	// ContextName is the kubeconfig context name identifying the cluster.
	ContextName string

	// NodeCount is the total number of nodes in the cluster.
	NodeCount int

	// Nodes holds per-node CPU resource data.
	Nodes []KubernetesNodeData

	// Namespaces holds per-namespace governance data.
	Namespaces []KubernetesNamespaceData
}
