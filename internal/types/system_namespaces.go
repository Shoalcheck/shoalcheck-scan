package types

// SystemNamespaces are the namespaces the workload rules skip unless the run passes --include-system: the
// components there run privileged and unprobed by design, and reporting them would bury every cluster's own
// findings under its distribution's.
//
// ONE LIST. internal/rules and internal/collect each carried their own copy, and the report — which may not
// import either — could not say which namespaces were skipped at all, so a skipped namespace read as a clean one.
func SystemNamespaces() []string {
	return []string{"kube-system", "kube-public", "kube-node-lease", "local-path-storage"}
}

// IsSystemNamespace reports whether ns is one of SystemNamespaces.
func IsSystemNamespace(ns string) bool {
	for _, s := range SystemNamespaces() {
		if ns == s {
			return true
		}
	}
	return false
}
