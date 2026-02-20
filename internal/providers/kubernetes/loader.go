package kubernetes

import (
	"fmt"
	"os"
	"path/filepath"

	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// resolveKubeconfigPath returns the effective kubeconfig file path.
// Prefers $KUBECONFIG if set; falls back to ~/.kube/config.
func resolveKubeconfigPath() string {
	if path := os.Getenv("KUBECONFIG"); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

// LoadClientset builds a kubernetes clientset from the kubeconfig file at path,
// targeting the given context (empty = current context).
//
// Returns the clientset and the resolved ClusterInfo (context name + server URL).
// The clientset is ready for immediate use; no additional configuration is needed.
func LoadClientset(kubeconfigPath, contextName string) (k8sclient.Interface, ClusterInfo, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{
		ExplicitPath: kubeconfigPath,
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	cfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	// Resolve the effective context name and server URL from the raw config.
	rawCfg, err := cfg.RawConfig()
	if err != nil {
		return nil, ClusterInfo{}, fmt.Errorf("load kubeconfig %q: %w", kubeconfigPath, err)
	}

	effectiveContext := rawCfg.CurrentContext
	if contextName != "" {
		effectiveContext = contextName
	}

	server := ""
	if ctx, ok := rawCfg.Contexts[effectiveContext]; ok {
		if cluster, ok := rawCfg.Clusters[ctx.Cluster]; ok {
			server = cluster.Server
		}
	}

	restCfg, err := cfg.ClientConfig()
	if err != nil {
		return nil, ClusterInfo{}, fmt.Errorf("build REST config for context %q: %w", effectiveContext, err)
	}

	clientset, err := k8sclient.NewForConfig(restCfg)
	if err != nil {
		return nil, ClusterInfo{}, fmt.Errorf("build clientset for context %q: %w", effectiveContext, err)
	}

	return clientset, ClusterInfo{
		ContextName: effectiveContext,
		Server:      server,
	}, nil
}
