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

// KubernetesContainerData holds processed container data consumed by K8s rules.
type KubernetesContainerData struct {
	// Name is the container name within the pod spec.
	Name string

	// Privileged is true when securityContext.privileged == true.
	Privileged bool

	// HasCPURequest is true when the container declares a non-zero CPU resource request.
	HasCPURequest bool

	// HasMemoryRequest is true when the container declares a non-zero memory resource request.
	HasMemoryRequest bool
}

// KubernetesPodData holds processed pod data consumed by K8s rules.
type KubernetesPodData struct {
	// Name is the pod name.
	Name string

	// Namespace is the Kubernetes namespace that owns this pod.
	Namespace string

	// Containers holds per-container security and resource data.
	Containers []KubernetesContainerData
}

// KubernetesServiceData holds processed Service data consumed by K8s rules.
type KubernetesServiceData struct {
	// Name is the Service name.
	Name string

	// Namespace is the Kubernetes namespace that owns this Service.
	Namespace string

	// Type is the Service type string (e.g. "ClusterIP", "NodePort", "LoadBalancer").
	Type string

	// Annotations is a copy of the Service's annotation map.
	Annotations map[string]string
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

	// Pods holds per-pod workload security and resource data.
	Pods []KubernetesPodData

	// Services holds per-Service network exposure data.
	Services []KubernetesServiceData
}
