package rules

import (
	"fmt"
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// dangling_class.go — A NAME THIS PRODUCT USED TO ECHO IS NOW A NAME IT RESOLVES.
//
// Phase 1 of the engine-ceiling spec, reference integrity first, and every rule here was cleared through the
// OVERLAP census (docs/qa/2026-08-30-phase1-overlap-census.md) against all 57 shipped rules before it was
// written — because F-2's counter-example, RolloutPassesThroughZero colliding with RiskyRolloutStrategy,
// showed that a new rule overlapping a shipped rule's subject is a change to an existing claim arriving
// sideways.
//
// THE FAMILY THESE EXTEND. dangling.go already reports a workload naming a ServiceAccount that is not there,
// a binding naming a role that is not there, and an autoscaler naming a workload that is not there. These
// four add the CLASS objects and the two remaining name references, and they share that family's discipline
// exactly:
//
//	THE REFERENCE, NEVER ITS CONSEQUENCE. A PVC naming a StorageClass that does not exist may be bound
//	already — it was provisioned when the class existed and the class was deleted afterwards — or it may
//	never bind. The snapshot cannot tell those apart, and neither does the finding.
//
//	NOT FROM A LIST WE DID NOT READ. Every claim is an ABSENCE claim over the target list, so both the
//	source kind and the target kind are checked before anything is said. A denied `storageclasses` list
//	would otherwise make every claim in the cluster look broken.
//
//	AN EMPTY NAME IS NOT A MISSING ONE. An unset storageClassName means "use the default class", an unset
//	ingressClassName means "use the default controller", and an unset priorityClassName means zero
//	priority. All three are ordinary and none is a dangling reference.
//
//	NO DOLLARS.

// ── Rule: a claim naming a StorageClass that is not there ────────────────────────────────────────

// DanglingStorageClass reports PVCs whose spec.storageClassName names no collected StorageClass.
//
// silent_failures.go:277 already prints this name beside the words "the class object itself was not read".
// That sentence was true and is now false: the class list is collected, so the name can be resolved instead
// of echoed. This rule is the resolution; that rule's wording is untouched.
type DanglingStorageClass struct{}

func (DanglingStorageClass) ID() string      { return "k8s.config.storageclass-unresolved" }
func (DanglingStorageClass) Version() string { return "1.0.0" }

func (DanglingStorageClass) RequiredKinds() []string {
	return sortedKinds([]string{"persistentvolumeclaims", "storageclasses"})
}

func (r DanglingStorageClass) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "persistentvolumeclaims", "storageclasses") {
		return nil
	}
	have := map[string]bool{}
	for _, sc := range inv.StorageClasses {
		have[sc.Name] = true
	}
	var out []types.Finding
	for i := range inv.PVCs {
		pvc := &inv.PVCs[i]
		if !opts.IncludeSystem && isSystemNamespace(pvc.Namespace) {
			continue
		}
		// AN UNSET CLASS NAME MEANS "THE DEFAULT CLASS", and an EMPTY STRING means "no class at all,
		// bind statically". Both are deliberate and neither is a dangling reference; reading either as a
		// name would report most claims on most clusters.
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName == "" {
			continue
		}
		name := *pvc.Spec.StorageClassName
		if have[name] {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PersistentVolumeClaim", pvc.Namespace, pvc.Name),
			IDBasis:     &types.ResourceRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("PVC %s/%s names a StorageClass this reading did not find",
				pvc.Namespace, pvc.Name),
			Description: fmt.Sprintf("PersistentVolumeClaim %s/%s sets spec.storageClassName to %q, and no "+
				"StorageClass by that name exists in this reading. Its phase is %s. What that means depends "+
				"on when the class went away: a claim bound while the class existed keeps its volume, and a "+
				"claim created afterwards has nothing to provision it — and this reading cannot tell those "+
				"apart.", pvc.Namespace, pvc.Name, name, emptyAs(string(pvc.Status.Phase), "unset")),
			WhyItMatters: "A StorageClass name is resolved by the provisioner at bind time, not by the API " +
				"server at admission, so a claim naming a class that is gone is accepted and simply never " +
				"provisioned. It is also the shape a cluster migration leaves behind: the workloads keep " +
				"the old class name long after the class is deleted.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("PVC %s/%s: spec.storageClassName = %q, status.phase = %s",
					pvc.Namespace, pvc.Name, name, emptyAs(string(pvc.Status.Phase), "unset")),
				fmt.Sprintf("%s were read, and none is named %q", nWord(len(inv.StorageClasses), "StorageClass", "StorageClasses"), name),
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── Rule: an Ingress naming an IngressClass that is not there ────────────────────────────────────

// DanglingIngressClass reports Ingresses whose spec.ingressClassName names no collected IngressClass.
type DanglingIngressClass struct{}

func (DanglingIngressClass) ID() string      { return "k8s.config.ingressclass-unresolved" }
func (DanglingIngressClass) Version() string { return "1.0.0" }

func (DanglingIngressClass) RequiredKinds() []string {
	return sortedKinds([]string{"ingressclasses", "ingresses"})
}

func (r DanglingIngressClass) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "ingresses", "ingressclasses") {
		return nil
	}
	have := map[string]bool{}
	for _, ic := range inv.IngressClasses {
		have[ic.Name] = true
	}
	var out []types.Finding
	for i := range inv.Ingresses {
		ing := &inv.Ingresses[i]
		if !opts.IncludeSystem && isSystemNamespace(ing.Namespace) {
			continue
		}
		// UNSET MEANS "THE DEFAULT CONTROLLER", which is how most Ingresses are written. The deprecated
		// kubernetes.io/ingress.class ANNOTATION is deliberately not read here: it names a controller
		// rather than an object, so there is nothing to resolve it against and an absence would be
		// unfalsifiable.
		if ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName == "" {
			continue
		}
		name := *ing.Spec.IngressClassName
		if have[name] {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Ingress", ing.Namespace, ing.Name),
			IDBasis:     &types.ResourceRef{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("Ingress %s/%s names an IngressClass this reading did not find",
				ing.Namespace, ing.Name),
			Description: fmt.Sprintf("Ingress %s/%s sets spec.ingressClassName to %q, and no IngressClass "+
				"by that name exists in this reading. An IngressClass is what tells a controller the "+
				"Ingress is addressed to it, so a name matching no class is a rule no controller has "+
				"claimed. Whether anything is serving these hosts is not readable from here.",
				ing.Namespace, ing.Name, name),
			WhyItMatters: "Nothing rejects an Ingress whose class does not exist — it is accepted, stored, " +
				"and ignored. The routes it declares read as configured in every manifest and in kubectl, " +
				"and no controller has picked them up.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("Ingress %s/%s: spec.ingressClassName = %q", ing.Namespace, ing.Name, name),
				fmt.Sprintf("%s were read, and none is named %q", nWord(len(inv.IngressClasses), "IngressClass", "IngressClasses"), name),
				"the deprecated kubernetes.io/ingress.class annotation names a controller rather than an " +
					"object and is not resolved here",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── Rule: a workload naming a PriorityClass that is not there ────────────────────────────────────

// DanglingPriorityClass reports workloads whose pod template names an absent PriorityClass.
type DanglingPriorityClass struct{}

func (DanglingPriorityClass) ID() string      { return "k8s.config.priorityclass-unresolved" }
func (DanglingPriorityClass) Version() string { return "1.0.0" }

func (DanglingPriorityClass) RequiredKinds() []string { return withWorkloads("priorityclasses") }

func (r DanglingPriorityClass) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "priorityclasses", "deployments", "statefulsets", "daemonsets") {
		return nil
	}
	have := map[string]bool{}
	for _, pc := range inv.PriorityClasses {
		have[pc.Name] = true
	}
	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		name := w.PodSpec.PriorityClassName
		// UNSET MEANS ZERO PRIORITY, which is the overwhelming majority of workloads.
		if name == "" || have[name] {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s/%s names a PriorityClass this reading did not find",
				w.Kind, w.Namespace, w.Name),
			Description: fmt.Sprintf("The pod template of %s %s/%s sets priorityClassName to %q, and no "+
				"PriorityClass by that name exists in this reading. Pods already running kept the priority "+
				"value they were admitted with; what happens to the next one this reading does not say.",
				w.Kind, w.Namespace, w.Name, name),
			WhyItMatters: "Priority is resolved at admission and written onto the pod as a number, so a " +
				"class that has been deleted leaves running pods untouched and their manifests unchanged. " +
				"The workload reads as prioritised everywhere except where it matters.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("%s %s/%s: spec.template.spec.priorityClassName = %q", w.Kind, w.Namespace, w.Name, name),
				fmt.Sprintf("%s were read, and none is named %q", nWord(len(inv.PriorityClasses), "PriorityClass", "PriorityClasses"), name),
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── Rule: a StatefulSet naming a governing Service that is not there ─────────────────────────────

// DanglingGoverningService reports StatefulSets whose spec.serviceName names no collected Service.
//
// SEPARATE FROM THE SERVICE FAMILY, DELIBERATELY. rotation.go reports Services with no ready endpoints;
// this reports a StatefulSet naming a Service that does not exist at all, which that rule cannot see
// because it iterates Services and this one is absent from the list.
type DanglingGoverningService struct{}

func (DanglingGoverningService) ID() string      { return "k8s.config.governing-service-unresolved" }
func (DanglingGoverningService) Version() string { return "1.0.0" }

func (DanglingGoverningService) RequiredKinds() []string {
	return sortedKinds([]string{"services", "statefulsets"})
}

func (r DanglingGoverningService) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "statefulsets", "services") {
		return nil
	}
	have := map[string]bool{}
	for i := range inv.Services {
		have[inv.Services[i].Namespace+"/"+inv.Services[i].Name] = true
	}
	var out []types.Finding
	for i := range inv.StatefulSets {
		sts := &inv.StatefulSets[i]
		if !opts.IncludeSystem && isSystemNamespace(sts.Namespace) {
			continue
		}
		name := sts.Spec.ServiceName
		// An unset serviceName is legal and means the pods get no stable DNS. That is a different claim
		// from naming one that is missing, and it is not this rule's.
		if name == "" || have[sts.Namespace+"/"+name] {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "StatefulSet", sts.Namespace, sts.Name),
			IDBasis:     &types.ResourceRef{Kind: "StatefulSet", Namespace: sts.Namespace, Name: sts.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("StatefulSet %s/%s names a governing Service this reading did not find",
				sts.Namespace, sts.Name),
			Description: fmt.Sprintf("StatefulSet %s/%s sets spec.serviceName to %q, and no Service by that "+
				"name exists in namespace %s in this reading. The governing Service is what gives a "+
				"StatefulSet's pods their stable per-pod DNS names; without the object, those names have "+
				"nothing publishing them.", sts.Namespace, sts.Name, name, sts.Namespace),
			WhyItMatters: "Nothing validates serviceName at admission — the StatefulSet is accepted and its " +
				"pods start normally. What is missing is the per-pod DNS every clustered database and " +
				"quorum system addresses its peers by, and that failure appears as a peer-discovery " +
				"problem inside the application rather than as anything Kubernetes reports.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("StatefulSet %s/%s: spec.serviceName = %q, spec.replicas = %s",
					sts.Namespace, sts.Name, name, replicasText(sts.Spec.Replicas)),
				fmt.Sprintf("%s were read in namespace %s, and none is named %q", nWord(countServicesIn(inv, sts.Namespace), "Service", "Services"), sts.Namespace, name),
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "StatefulSet", Namespace: sts.Namespace, Name: sts.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func countServicesIn(inv *collect.Inventory, ns string) int {
	n := 0
	for i := range inv.Services {
		if inv.Services[i].Namespace == ns {
			n++
		}
	}
	return n
}

func replicasText(r *int32) string {
	if r == nil {
		return "unset (defaults to 1)"
	}
	return fmt.Sprintf("%d", *r)
}
