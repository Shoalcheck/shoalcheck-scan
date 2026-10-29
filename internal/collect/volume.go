package collect

import (
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// volumeOf measures what this reading read: objects per kind, and the bytes each kind occupies as
// `kubectl get -o yaml` prints it. kubectl omits managedFields unless asked, so they are cleared on a COPY
// before measuring — the inventory itself is not touched, because rules read it after this.
//
// Two things a kubectl listing carries that this does not: the apiVersion/kind lines a typed list item lacks
// (tens of bytes an object), and the List wrapper. Both make this an undercount, which is the safe direction
// for a figure that is presented as a floor.
func volumeOf(inv *Inventory) *types.ReadVolume {
	kinds := []types.KindVolume{
		measure("nodes", inv.Nodes),
		measure("namespaces", inv.Namespaces),
		measure("deployments", inv.Deployments),
		measure("statefulsets", inv.StatefulSets),
		measure("daemonsets", inv.DaemonSets),
		measure("pods", inv.Pods),
		measure("services", inv.Services),
		measure("poddisruptionbudgets", inv.PDBs),
		measure("clusterrolebindings", inv.ClusterRoleBindings),
		measure("rolebindings", inv.RoleBindings),
		measure("clusterroles", inv.ClusterRoles),
		measure("roles", inv.Roles),
		measure("serviceaccounts", inv.ServiceAccounts),
		measure("networkpolicies", inv.NetworkPolicies),
		measure("ingresses", inv.Ingresses),
		measure("endpointslices", inv.EndpointSlices),
		measure("resourcequotas", inv.ResourceQuotas),
		measure("limitranges", inv.LimitRanges),
		measure("horizontalpodautoscalers", inv.HPAs),
		measure("cronjobs", inv.CronJobs),
		measure("jobs", inv.Jobs),
		measure("persistentvolumes", inv.PVs),
		measure("persistentvolumeclaims", inv.PVCs),
		measure("storageclasses", inv.StorageClasses),
		measure("ingressclasses", inv.IngressClasses),
		measure("priorityclasses", inv.PriorityClasses),
	}
	v := &types.ReadVolume{}
	for _, k := range kinds {
		if k.Objects == 0 {
			continue
		}
		v.ByKind = append(v.ByKind, k)
		v.Objects += k.Objects
		v.YAMLBytes += k.Bytes
	}
	if v.Objects == 0 {
		return nil
	}
	sort.SliceStable(v.ByKind, func(i, j int) bool {
		if v.ByKind[i].Bytes != v.ByKind[j].Bytes {
			return v.ByKind[i].Bytes > v.ByKind[j].Bytes
		}
		return v.ByKind[i].Kind < v.ByKind[j].Kind
	})
	return v
}

// measure sizes one kind. T is a Kubernetes object type whose pointer implements metav1.Object, which every
// typed slice in Inventory satisfies.
//
// SPREAD OVER THE MACHINE'S CORES. Printing every object as YAML is most of what a large reading's collection
// costs in CPU — on the 2,000-node synthetic cluster, 2.2 of 3.3 seconds, and seven gigabytes of allocation for
// its 33,000 pods. Each object is sized independently and the sizes are summed, so the parts can run at once and
// the total is the serial one to the byte (TestVolume_AParallelMeasureIsTheSerialSum).
//
// FOUR, NOT EVERY CORE. On a 12-core machine every core finished the audit no sooner and raised its peak RSS from
// ~850 MB to ~1,050 MB: twelve goroutines producing garbage that fast outran the collector.
func measure[T any](kind string, items []T) types.KindVolume {
	kv := types.KindVolume{Kind: kind, Objects: len(items)}
	workers := min(4, runtime.GOMAXPROCS(0), len(items)/256+1)
	if workers <= 1 {
		kv.Bytes = yamlBytes(items)
		return kv
	}
	var total atomic.Int64
	var wg sync.WaitGroup
	per := (len(items) + workers - 1) / workers
	for lo := 0; lo < len(items); lo += per {
		part := items[lo:min(lo+per, len(items))]
		wg.Add(1)
		go func() {
			defer wg.Done()
			total.Add(yamlBytes(part))
		}()
	}
	wg.Wait()
	kv.Bytes = total.Load()
	return kv
}

// yamlBytes is the bytes these objects occupy as `kubectl get -o yaml` prints them, managedFields omitted.
func yamlBytes[T any](items []T) int64 {
	var n int64
	for i := range items {
		c := items[i] // a shallow copy: clearing a field on it leaves the inventory's object alone
		if o, ok := any(&c).(metav1.Object); ok {
			o.SetManagedFields(nil)
		}
		b, err := yaml.Marshal(c)
		if err != nil {
			continue // an object that cannot be printed is still counted; its bytes are not guessed
		}
		n += int64(len(b))
	}
	return n
}
