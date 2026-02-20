package kubernetes

import k8sclient "k8s.io/client-go/kubernetes"

// KubeClientProvider creates kubernetes clientsets for named kubeconfig contexts.
// It abstracts kubeconfig loading so callers and tests can inject any clientset
// without touching the filesystem.
type KubeClientProvider interface {
	// ClientsetForContext returns a clientset and the resolved ClusterInfo for
	// the given kubeconfig context. Pass an empty string to use the current
	// context from the loaded kubeconfig.
	ClientsetForContext(contextName string) (k8sclient.Interface, ClusterInfo, error)
}

// DefaultKubeClientProvider loads kubeconfig from $KUBECONFIG or ~/.kube/config
// and builds a real kubernetes clientset.
type DefaultKubeClientProvider struct{}

// NewDefaultKubeClientProvider returns a provider backed by the system kubeconfig.
func NewDefaultKubeClientProvider() *DefaultKubeClientProvider {
	return &DefaultKubeClientProvider{}
}

// ClientsetForContext implements KubeClientProvider.
func (p *DefaultKubeClientProvider) ClientsetForContext(contextName string) (k8sclient.Interface, ClusterInfo, error) {
	return LoadClientset(resolveKubeconfigPath(), contextName)
}
