package kubernetes

// ClusterInfo identifies a Kubernetes cluster and the kubeconfig context used
// to connect to it.
type ClusterInfo struct {
	// ContextName is the kubeconfig context name used to connect.
	ContextName string

	// Server is the Kubernetes API server URL resolved from the kubeconfig.
	Server string
}

// NodeInfo holds basic capacity and allocatable resource data for a cluster node.
type NodeInfo struct {
	Name string

	// CPUCapacity and MemoryCapacity are the total resources reported in
	// node.status.capacity, formatted as Kubernetes quantity strings (e.g. "4", "8Gi").
	CPUCapacity    string
	MemoryCapacity string

	// AllocatableCPU and AllocatableMemory are the resources available for
	// scheduling (capacity minus system/kubelet reservations).
	AllocatableCPU    string
	AllocatableMemory string
}

// NamespaceInfo holds basic namespace metadata.
type NamespaceInfo struct {
	Name string
}

// ClusterData is the inventory collected from a single Kubernetes cluster.
// It is the k8s equivalent of models.RegionData and is the input to k8s rules.
type ClusterData struct {
	ClusterInfo ClusterInfo
	Nodes       []NodeInfo
	Namespaces  []NamespaceInfo
}
