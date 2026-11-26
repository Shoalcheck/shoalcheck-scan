package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// UnmodelledControllers is every kind of controller owning running pods that this reading does not model as a
// workload, with its controller and pod counts (ENG-12). Modelled: Deployments (through their ReplicaSets),
// StatefulSets, DaemonSets, Jobs and CronJobs, and a Node's static pods. Anything else — an Argo Rollout's
// ReplicaSet, a CloudNativePG Cluster, a Strimzi pod set, an OpenKruise CloneSet — has its pods judged one spec per
// controller and no workload-level rule. A pod whose controller is of a modelled kind that was not read (denied)
// is a coverage fact the unread record already states, and is not counted here.
func UnmodelledControllers(inv *collect.Inventory, opts Options) []types.UnmodelledController {
	idx := derived(inv, opts).ownerIndex()
	type agg struct {
		owners map[string]bool
		pods   int
	}
	by := map[string]*agg{}
	for i := range inv.Pods {
		p := inv.Pods[i]
		if (!opts.IncludeSystem && isSystemNamespace(p.Namespace)) || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		chain := idx.chain(p)
		if len(chain) == 0 {
			continue // a bare pod is judged as itself, which is all there is of it
		}
		kind := chain[0].Kind
		switch kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Node", "Rollout":
			continue // a Rollout is modelled when it is read (ENG-11); unread, its pods stay with their ReplicaSet
		case "ReplicaSet":
			if controllerUnread(inv, kind) {
				continue
			}
		}
		a := by[kind]
		if a == nil {
			a = &agg{owners: map[string]bool{}}
			by[kind] = a
		}
		a.owners[p.Namespace+"/"+chain[0].Name] = true
		a.pods++
	}
	out := make([]types.UnmodelledController, 0, len(by))
	for k, a := range by {
		out = append(out, types.UnmodelledController{Kind: k, Controllers: len(a.owners), Pods: a.pods})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pods != out[j].Pods {
			return out[i].Pods > out[j].Pods
		}
		return out[i].Kind < out[j].Kind
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// UnmodelledSentence is the methodology's line for UnmodelledControllers, built from the counts: "38 pods under 15
// controllers of kinds this reading does not model: ReplicaSet with no Deployment ×12, Cluster ×3 …". Empty for none.
func UnmodelledSentence(u []types.UnmodelledController) string {
	if len(u) == 0 {
		return ""
	}
	pods, ctrls := 0, 0
	var kinds []string
	for _, c := range u {
		pods += c.Pods
		ctrls += c.Controllers
		name := c.Kind
		if name == "ReplicaSet" {
			name = "ReplicaSet with no Deployment of this reading (Argo Rollouts' are)"
		}
		kinds = append(kinds, fmt.Sprintf("%s ×%d", name, c.Controllers))
	}
	return fmt.Sprintf("%s under %s of kinds this reading does not model: %s. Their pod specs are judged once per "+
		"controller; no workload-level rule — replicas, disruption budgets, spread, rightsizing — covers them.",
		nWord(pods, "pod", "pods"), nWord(ctrls, "controller", "controllers"), strings.Join(kinds, ", "))
}
