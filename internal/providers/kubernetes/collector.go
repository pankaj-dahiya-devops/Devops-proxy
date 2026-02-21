package kubernetes

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
)

// CollectClusterData collects nodes and namespaces from the cluster using
// the provided clientset and attaches the resolved ClusterInfo to the result.
//
// Both collections are attempted; an error from either aborts the collection.
// The clientset parameter is an interface so tests can inject a fake clientset.
func CollectClusterData(ctx context.Context, clientset k8sclient.Interface, info ClusterInfo) (*ClusterData, error) {
	nodes, err := collectNodes(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("collect nodes: %w", err)
	}

	namespaces, err := collectNamespaces(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("collect namespaces: %w", err)
	}

	return &ClusterData{
		ClusterInfo: info,
		Nodes:       nodes,
		Namespaces:  namespaces,
	}, nil
}

// collectNodes lists all nodes and converts them to NodeInfo.
// CPU and memory values are formatted as Kubernetes quantity strings.
func collectNodes(ctx context.Context, clientset k8sclient.Interface) ([]NodeInfo, error) {
	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	nodes := make([]NodeInfo, 0, len(nodeList.Items))
	for _, n := range nodeList.Items {
		nodes = append(nodes, NodeInfo{
			Name:              n.Name,
			CPUCapacity:       n.Status.Capacity.Cpu().String(),
			MemoryCapacity:    n.Status.Capacity.Memory().String(),
			AllocatableCPU:    n.Status.Allocatable.Cpu().String(),
			AllocatableMemory: n.Status.Allocatable.Memory().String(),
		})
	}
	return nodes, nil
}

// collectNamespaces lists all namespaces and converts them to NamespaceInfo.
func collectNamespaces(ctx context.Context, clientset k8sclient.Interface) ([]NamespaceInfo, error) {
	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	namespaces := make([]NamespaceInfo, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		namespaces = append(namespaces, NamespaceInfo{Name: ns.Name})
	}
	return namespaces, nil
}
