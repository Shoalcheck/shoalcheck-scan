package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// declaration_validity.go — A DECLARATION THAT CONTRADICTS ITSELF INSIDE ONE OBJECT.
//
// Phase 1, and every rule here was cleared through the overlap census against the shipped registry. What
// binds them is the narrowest possible claim: the contradiction is entirely WITHIN one object's own spec, so
// nothing has to be joined, nothing has to be observed, and there is no second list whose absence could
// fabricate the finding. That makes them the cheapest honest claims this product can make — and the ones a
// reader can check without leaving the card.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THEY DO NOT SAY
//
//	NOT WHETHER IT WORKS. A probe naming a port the container does not declare still works if the process
//	listens on it — containerPort is documentation, not a binding. So the claim is about the DECLARATION
//	disagreeing with itself, and the finding says so in the sentence.
//
//	NOT WHICH VALUE IS CORRECT. Two env vars of one name: the last wins at runtime, and which one the
//	author meant is not in the snapshot.
//
//	NO DOLLARS.

// ── Rule: a probe targets a port the container does not declare ──────────────────────────────────

// ProbePortNotDeclared reports probes whose port matches no containerPort on the same container.
type ProbePortNotDeclared struct{}

func (ProbePortNotDeclared) ID() string      { return "k8s.config.probe-port-not-declared" }
func (ProbePortNotDeclared) Version() string { return "1.0.0" }

func (ProbePortNotDeclared) RequiredKinds() []string { return withWorkloads() }

func (r ProbePortNotDeclared) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		if !observed(inv, workloadKindToList(w.Kind)) {
			continue
		}
		var evidence []string
		for _, ac := range assessedContainers(w.PodSpec) {
			c := ac.c
			// A container that declares NO ports at all is not judged. Declaring containerPort is
			// optional and widely skipped, so an empty list means "not documented", never "port absent" —
			// and a rule reading it the other way would fire on most containers in the world.
			if len(c.Ports) == 0 {
				continue
			}
			declared := map[int32]bool{}
			named := map[string]bool{}
			for _, p := range c.Ports {
				declared[p.ContainerPort] = true
				if p.Name != "" {
					named[p.Name] = true
				}
			}
			for _, pr := range []struct {
				label string
				p     *corev1.Probe
			}{
				{"livenessProbe", c.LivenessProbe},
				{"readinessProbe", c.ReadinessProbe},
				{"startupProbe", c.StartupProbe},
			} {
				port, ok := probePort(pr.p)
				if !ok {
					continue
				}
				if port.Type == intstr.String {
					if named[port.StrVal] {
						continue
					}
					evidence = append(evidence, fmt.Sprintf(
						"%s %s in %s %s/%s: %s targets port %q, and this container declares no port of that "+
							"name (it declares: %s)",
						ac.noun, c.Name, w.Kind, w.Namespace, w.Name, pr.label, port.StrVal,
						containerPortsText(c)))
					continue
				}
				if declared[port.IntVal] {
					continue
				}
				evidence = append(evidence, fmt.Sprintf(
					"%s %s in %s %s/%s: %s targets port %d, and this container declares no such "+
						"containerPort (it declares: %s)",
					ac.noun, c.Name, w.Kind, w.Namespace, w.Name, pr.label, port.IntVal,
					containerPortsText(c)))
			}
		}
		if len(evidence) == 0 {
			continue
		}
		evidence = append([]string{snapshotNote(inv)}, evidence...)
		evidence = append(evidence, "containerPort is documentation rather than a binding — a process may "+
			"listen on a port it never declared — so what is reported here is the spec disagreeing with "+
			"itself, and nothing about the outcome")
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("A probe on %s %s/%s targets an undeclared port", w.Kind, w.Namespace, w.Name),
			Description: fmt.Sprintf("%s %s/%s has a probe whose port matches no containerPort declared on "+
				"the same container. The container DOES declare ports, which is what makes the mismatch "+
				"readable: the spec names one set of ports and probes a different one.",
				w.Kind, w.Namespace, w.Name),
			WhyItMatters: "A probe and a port declaration that name different things are two halves of " +
				"one intention, written at different times. Whether the port the probe names is the one " +
				"the process listens on is outside this reading — which is exactly why the disagreement " +
				"is worth surfacing rather than resolving: it is the kind of mismatch that survives " +
				"review, because both numbers look plausible beside each other.",
			Evidence:          evidence,
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

func probePort(p *corev1.Probe) (intstr.IntOrString, bool) {
	if p == nil {
		return intstr.IntOrString{}, false
	}
	if p.HTTPGet != nil {
		return p.HTTPGet.Port, true
	}
	if p.TCPSocket != nil {
		return p.TCPSocket.Port, true
	}
	// exec and grpc probes name no port on the container, so there is nothing to disagree with.
	return intstr.IntOrString{}, false
}

func containerPortsText(c corev1.Container) string {
	parts := make([]string, 0, len(c.Ports))
	for _, p := range c.Ports {
		if p.Name != "" {
			parts = append(parts, fmt.Sprintf("%q/%d", p.Name, p.ContainerPort))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d", p.ContainerPort))
	}
	return strings.Join(parts, ", ")
}

// ── Rule: one container declares the same environment variable twice ─────────────────────────────

// DuplicateEnvVar reports containers declaring the same env var name more than once.
type DuplicateEnvVar struct{}

func (DuplicateEnvVar) ID() string      { return "k8s.config.duplicate-env-var" }
func (DuplicateEnvVar) Version() string { return "1.0.0" }

func (DuplicateEnvVar) RequiredKinds() []string { return withWorkloads() }

func (r DuplicateEnvVar) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		if !observed(inv, workloadKindToList(w.Kind)) {
			continue
		}
		var evidence []string
		for _, ac := range assessedContainers(w.PodSpec) {
			c := ac.c
			seen := map[string]int{}
			var order []string
			for _, e := range c.Env {
				if seen[e.Name] == 0 {
					order = append(order, e.Name)
				}
				seen[e.Name]++
			}
			for _, name := range order {
				if seen[name] < 2 {
					continue
				}
				// THE VALUE IS NOT QUOTED. An env var's value is customer-authored and routinely holds a
				// connection string or a token; the NAME is what the finding is about and the name is
				// enough to find it. This is the same boundary internal/redact exists for.
				evidence = append(evidence, fmt.Sprintf(
					"%s %s in %s %s/%s: env name %q is declared %d times",
					ac.noun, c.Name, w.Kind, w.Namespace, w.Name, name, seen[name]))
			}
		}
		if len(evidence) == 0 {
			continue
		}
		evidence = append([]string{snapshotNote(inv)}, evidence...)
		evidence = append(evidence, "the last declaration wins at runtime; which one the author meant is "+
			"not readable from the spec, and the values are not quoted here because an env value is "+
			"customer data")
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("%s %s/%s declares an environment variable twice", w.Kind, w.Namespace, w.Name),
			Description: fmt.Sprintf("A container in %s %s/%s declares the same environment variable name "+
				"more than once. Kubernetes accepts this and the last one wins, so the earlier value is "+
				"silently discarded — the manifest reads as though both were set.",
				w.Kind, w.Namespace, w.Name),
			WhyItMatters: "This is almost always a merge artefact — two overlays, a base and a patch, or " +
				"a copy-paste — and the discarded value is usually the one somebody added deliberately. " +
				"Nothing warns about it at apply time.",
			Evidence:          evidence,
			Severity:          types.SeverityLow,
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

// ── Rule: a Service port whose targetPort names nothing the selected pods declare ────────────────

// ServiceTargetPortUndeclared reports Service ports whose targetPort matches no port on the pods the
// Service selects.
//
// NOT AN OVERLAP WITH THE ENDPOINT FAMILY, and the distinction is the reason this is a separate rule
// rather than a branch: rotation.go reports what a CONTROLLER published — zero ready addresses — which is
// a fact about the cluster's current state. This reports two DECLARATIONS disagreeing, which is true
// whether or not anything is running, and remains true on a cluster whose EndpointSlices were denied.
type ServiceTargetPortUndeclared struct{}

func (ServiceTargetPortUndeclared) ID() string      { return "k8s.config.service-targetport-undeclared" }
func (ServiceTargetPortUndeclared) Version() string { return "1.0.0" }

func (ServiceTargetPortUndeclared) RequiredKinds() []string { return withWorkloads("services") }

func (r ServiceTargetPortUndeclared) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "services") {
		return nil
	}
	all := workloads(inv, opts)
	// A SELECTOR IS NAMESPACED: each Service is matched against its own namespace's workloads, in the order the
	// walk over all of them visited them, rather than against every workload in the cluster.
	inNamespace := map[string][]workload{}
	for _, w := range all {
		inNamespace[w.Namespace] = append(inNamespace[w.Namespace], w)
	}

	var out []types.Finding
	for i := range inv.Services {
		svc := &inv.Services[i]
		if !opts.IncludeSystem && isSystemNamespace(svc.Namespace) {
			continue
		}
		// A selectorless Service has manual Endpoints and declares nothing about pods; an ExternalName
		// has no ports to match. Neither is judged.
		if len(svc.Spec.Selector) == 0 || svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		matched := workloadsSelectedBy(inNamespace[svc.Namespace], svc)
		// WITH NO SELECTED WORKLOAD THERE IS NOTHING TO DISAGREE WITH. That a Service selects nothing is a
		// different claim and another rule's — saying it here would be two cards for one fact.
		if len(matched) == 0 {
			continue
		}
		var evidence []string
		for _, sp := range svc.Spec.Ports {
			// An unset targetPort defaults to the service port, and a numeric targetPort is a real port
			// number that a container need not declare — containerPort is documentation. Only a NAMED
			// targetPort is a reference that must resolve, which is what makes this claim exact.
			if sp.TargetPort.Type != intstr.String || sp.TargetPort.StrVal == "" {
				continue
			}
			var declaredBy []string
			for _, w := range matched {
				for _, ac := range assessedContainers(w.PodSpec) {
					for _, p := range ac.c.Ports {
						if p.Name == sp.TargetPort.StrVal {
							declaredBy = append(declaredBy, w.Name)
						}
					}
				}
			}
			if len(declaredBy) > 0 {
				continue
			}
			names := make([]string, 0, len(matched))
			for _, w := range matched {
				names = append(names, fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name))
			}
			evidence = append(evidence, fmt.Sprintf(
				"Service %s/%s port %s targets the named port %q, and no container of the %s it "+
					"selects declares a port of that name (%s)",
				svc.Namespace, svc.Name, servicePortLabel(sp), sp.TargetPort.StrVal, nWord(len(matched), "workload", "workloads"), strings.Join(names, ", ")))
		}
		if len(evidence) == 0 {
			continue
		}
		evidence = append([]string{snapshotNote(inv)}, evidence...)
		evidence = append(evidence, "a NAMED targetPort must resolve to a containerPort of that name; a "+
			"numeric one need not, because declaring containerPort is optional — so only the named form "+
			"is judged here")
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Service", svc.Namespace, svc.Name),
			IDBasis:     &types.ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("Service %s/%s targets a port name its pods do not declare",
				svc.Namespace, svc.Name),
			Description: fmt.Sprintf("Service %s/%s names a targetPort that no container of the workloads "+
				"it selects declares. A named targetPort is resolved against the pod's own containerPort "+
				"names, so a name that matches nothing has nothing to forward to.",
				svc.Namespace, svc.Name),
			WhyItMatters: "This is accepted at apply time and produces a Service that looks correct in " +
				"every manifest. It is the shape a renamed container port leaves behind, and the Service " +
				"is usually edited by someone other than whoever renamed it.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func servicePortLabel(sp corev1.ServicePort) string {
	if sp.Name != "" {
		return fmt.Sprintf("%q/%d", sp.Name, sp.Port)
	}
	return fmt.Sprintf("%d", sp.Port)
}

// workloadsSelectedBy returns the workloads whose pod labels a Service's selector matches.
func workloadsSelectedBy(all []workload, svc *corev1.Service) []workload {
	var out []workload
	for _, w := range all {
		if w.Namespace != svc.Namespace || len(w.PodLabels) == 0 {
			continue
		}
		ok := true
		for k, v := range svc.Spec.Selector {
			if w.PodLabels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, w)
		}
	}
	return out
}
