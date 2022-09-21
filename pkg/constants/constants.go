package constants

const (
	// PodInfoLabelsPath is the filepath that pod labels will be stored
	// This is typically set by the downward API
	PodInfoLabelsPath = "./etc/istio/pod/labels"

	// PodInfoAnnotationsPath is the filepath that pod annotations will be stored
	// This is typically set by the downward API
	PodInfoAnnotationsPath = "./etc/istio/pod/annotations"

	// DefaultDeploymentUniqueLabelKey is the default key of the selector that is added
	// to existing ReplicaSets (and label key that is added to its pods) to prevent the existing ReplicaSets
	// to select new pods (and old pods being select by new ReplicaSet).
	DefaultDeploymentUniqueLabelKey string = "pod-template-hash"
)
