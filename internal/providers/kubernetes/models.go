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

	// CPUCapacityMillis is CPUCapacity expressed in millicores for arithmetic
	// comparisons without string parsing in rule code.
	CPUCapacityMillis int64

	// AllocatableCPUMillis is AllocatableCPU expressed in millicores.
	AllocatableCPUMillis int64
}

// NamespaceInfo holds basic namespace metadata.
type NamespaceInfo struct {
	Name string

	// HasLimitRange is true when at least one LimitRange object exists in
	// this namespace, indicating default resource limits are configured.
	HasLimitRange bool
}

// ContainerInfo holds per-container security and resource request data.
type ContainerInfo struct {
	// Name is the container name within the pod spec.
	Name string

	// Privileged is true when securityContext.privileged == true.
	Privileged bool

	// HasCPURequest is true when the container declares a non-zero CPU resource request.
	HasCPURequest bool

	// HasMemoryRequest is true when the container declares a non-zero memory resource request.
	HasMemoryRequest bool
}

// PodInfo holds basic pod metadata and its container list.
type PodInfo struct {
	// Name is the pod name.
	Name string

	// Namespace is the Kubernetes namespace that owns this pod.
	Namespace string

	// Containers holds per-container security and resource data.
	Containers []ContainerInfo
}

// ServiceInfo holds basic Service metadata used for network exposure checks.
type ServiceInfo struct {
	// Name is the Service name.
	Name string

	// Namespace is the Kubernetes namespace that owns this Service.
	Namespace string

	// Type is the Service type string (e.g. "ClusterIP", "NodePort", "LoadBalancer").
	Type string

	// Annotations is a copy of the Service's annotation map.
	Annotations map[string]string
}

// ClusterData is the inventory collected from a single Kubernetes cluster.
// It is the k8s equivalent of models.AWSRegionData and is the input to k8s rules.
type ClusterData struct {
	ClusterInfo ClusterInfo
	Nodes       []NodeInfo
	Namespaces  []NamespaceInfo
	Pods        []PodInfo
	Services    []ServiceInfo
}
