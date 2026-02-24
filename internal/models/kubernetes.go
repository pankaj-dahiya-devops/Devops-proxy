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

	// ProviderID is the cloud-provider instance identifier from node.spec.providerID.
	// Used for cloud-provider detection: "aws://" → EKS, "gce://" → GKE, "azure://" → AKS.
	ProviderID string `json:"provider_id,omitempty"`

	// Labels is a copy of the node's label map used for cloud-provider detection
	// and EKS cluster/region extraction.
	Labels map[string]string `json:"labels,omitempty"`
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

// KubernetesEKSNodeGroupData holds per-nodegroup data for EKS-specific governance checks.
type KubernetesEKSNodeGroupData struct {
	// Name is the EKS managed nodegroup name.
	Name string `json:"name"`

	// Version is the Kubernetes minor version running on this nodegroup (e.g. "1.29").
	Version string `json:"version"`

	// HttpTokens is the IMDSv2 enforcement setting for this nodegroup.
	// "required" enforces IMDSv2; "optional" permits both IMDSv1 and IMDSv2.
	HttpTokens string `json:"http_tokens"`
}

// KubernetesEKSData holds AWS EKS control-plane data collected via the EKS API.
// It is populated only when the cluster is identified as EKS.
type KubernetesEKSData struct {
	// ClusterName is the EKS cluster name as registered in AWS.
	ClusterName string `json:"cluster_name"`

	// Region is the AWS region hosting the cluster.
	Region string `json:"region"`

	// ControlPlaneVersion is the Kubernetes version of the EKS control plane (e.g. "1.29").
	ControlPlaneVersion string `json:"control_plane_version"`

	// EndpointPublicAccess indicates whether the EKS API server endpoint is publicly accessible.
	EndpointPublicAccess bool `json:"endpoint_public_access"`

	// PublicAccessCidrs is the list of CIDR blocks allowed to access the public endpoint.
	// AWS defaults to ["0.0.0.0/0"] when public access is enabled and no CIDRs are set.
	PublicAccessCidrs []string `json:"public_access_cidrs,omitempty"`

	// EncryptionKeyARN is the KMS key ARN used for Kubernetes secrets envelope encryption.
	// Empty string means secrets encryption is not configured.
	EncryptionKeyARN string `json:"encryption_key_arn,omitempty"`

	// EnabledLogTypes is the list of control plane log types currently enabled in CloudWatch.
	// Possible values: api, audit, authenticator, controllerManager, scheduler.
	EnabledLogTypes []string `json:"enabled_log_types,omitempty"`

	// NodeGroups holds per-managed-nodegroup data for EKS-specific governance checks.
	NodeGroups []KubernetesEKSNodeGroupData `json:"node_groups,omitempty"`
}

// KubernetesClusterData holds all cluster inventory consumed by Kubernetes rules.
// It is the K8s equivalent of RegionData and is passed via RuleContext.ClusterData.
type KubernetesClusterData struct {
	// ContextName is the kubeconfig context name identifying the cluster.
	ContextName string

	// NodeCount is the total number of nodes in the cluster.
	NodeCount int

	// ClusterProvider is the detected cloud provider: "eks", "gke", "aks", or "unknown".
	ClusterProvider string `json:"cluster_provider,omitempty"`

	// Nodes holds per-node CPU resource data.
	Nodes []KubernetesNodeData

	// Namespaces holds per-namespace governance data.
	Namespaces []KubernetesNamespaceData

	// Pods holds per-pod workload security and resource data.
	Pods []KubernetesPodData

	// Services holds per-Service network exposure data.
	Services []KubernetesServiceData

	// EKSData holds AWS EKS control-plane data populated when ClusterProvider == "eks".
	// Nil for non-EKS clusters or when EKS data collection is disabled.
	EKSData *KubernetesEKSData `json:"eks_data,omitempty"`
}
