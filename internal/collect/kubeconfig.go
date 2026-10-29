package collect

import (
	"path/filepath"
	"sort"

	"k8s.io/client-go/tools/clientcmd"
)

// CurrentContext reads the kubeconfig's current context name without contacting anything. It lives here
// because this package is the one place client-go is imported (scripts/transport-gate.sh keeps it so): a
// command that only wants to know which cluster the operator means still asks through the recorded door.
func CurrentContext(kubeconfig string) string {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cfg, err := rules.Load()
	if err != nil || cfg == nil {
		return ""
	}
	return cfg.CurrentContext
}

// ContextNames lists the contexts of the kubeconfig a run would read: the explicit file when one is given, else
// the colon-separated KUBECONFIG list given as kubeconfigEnv, else the default (~/.kube/config). It is passed the
// list rather than reading the environment itself, because the caller asking — a schedule install — needs the
// answer for the environment a TIMER will have, which it records before it asks.
func ContextNames(explicit, kubeconfigEnv string) ([]string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	switch {
	case explicit != "":
		rules.ExplicitPath = explicit
	case kubeconfigEnv != "":
		rules.Precedence = filepath.SplitList(kubeconfigEnv)
	default:
		rules.Precedence = []string{clientcmd.RecommendedHomeFile}
	}
	cfg, err := rules.Load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Contexts))
	for n := range cfg.Contexts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
