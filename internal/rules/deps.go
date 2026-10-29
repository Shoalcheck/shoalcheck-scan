package rules

import "sort"

// Rule dependencies — what a finding rests on, so a comparison between two audits can tell a changed
// cluster from a changed reading.
//
// The problem this solves. A finding present in Monday's audit and absent from Tuesday's has at least
// two explanations: the cluster changed, or Tuesday's run could not read what the rule needed. Those
// are not the same statement and only one of them is about the cluster. Without a declaration the
// comparison cannot distinguish them, so it would report the operator's revoked RBAC as their own fix.
//
// Why the finding's own resource kind is not enough. NoNetworkPolicy writes a finding about a
// NAMESPACE, but its claim rests on the NetworkPolicy list. Deny that list and the rule falls silent
// while namespaces still list fine — a comparison keyed on the finding's own kind would see a collected
// kind and report the finding as gone from the cluster. The dependency is on the EVIDENCE, and only the
// rule knows what its evidence was.
//
// What belongs in the list, and what deliberately does not. A kind belongs here when the rule's claim
// changes if that list is missing — either it cannot fire, or it fires when it should not. A kind that
// only changes the WORDING of a finding that fired anyway does not belong: the drain rules append an
// endpoint-registration count as evidence, and a run without EndpointSlices still makes exactly the same
// claim about exactly the same nodes. Declaring that dependency would make the report say a rule was not
// evaluated when it was, which is a false statement about our own run — the honest direction is to
// declare what is load-bearing and nothing more.
//
// This list gates the COMPARISON, not the run. Gating the run would mean a rule that walks Deployments,
// StatefulSets and DaemonSets loses its real Deployment findings when only DaemonSets was denied — and,
// worse, a typo in a declaration would silently disable a rule forever. Gating the comparison makes the
// same typo merely over-cautious: it withholds a comparison it could have made. That asymmetry is why
// the declaration lives here rather than in the pipeline's rule loop.

// Dependencies is everything a comparison needs to know about one rule, addressed by rule ID so that a
// consumer never has to import the rule itself or hold a registry in sync with a hand-written list.
type Dependencies struct {
	// Kinds are collector step names, verbatim as the collector records them in Meta.Collected and
	// Methodology.CollectedKinds, so a comparison can check membership without translating anything.
	Kinds []string

	// Usage marks a rule whose findings exist only when Prometheus usage was resolved. Without it the
	// rule emits nothing, so an audit run against Prometheus followed by one without it would show
	// every such finding as gone from the cluster. This is a run SETTING rather than a collected kind,
	// which is why it cannot be expressed as a kind name.
	Usage bool
}

// usageDependent is an optional interface: only the rules that read Options.Usage implement it, so
// adding the concept costs the other rules nothing. Declaring it falsely is worse than not declaring
// it — it suppresses a comparison that was safe to make — so the test asserts both directions.
type usageDependent interface {
	RequiresUsage() bool
}

// DependenciesByRule maps rule ID to what that rule's findings rest on. Built from the registry, so it
// cannot drift from it.
func DependenciesByRule() map[string]Dependencies {
	out := make(map[string]Dependencies, len(All()))
	for _, r := range All() {
		d := Dependencies{Kinds: r.RequiredKinds()}
		if u, ok := r.(usageDependent); ok {
			d.Usage = u.RequiresUsage()
		}
		out[r.ID()] = d
	}
	return out
}

// workloadKinds is the set every rule that walks workloads() depends on, named once so a rule cannot
// declare a subset of it by accident.
func workloadKinds() []string { return []string{"daemonsets", "deployments", "statefulsets"} }

// withWorkloads returns the workload kinds plus extra, sorted. Rules call it so the sorted-order
// invariant holds without every rule maintaining it by hand.
func withWorkloads(extra ...string) []string { return sortedKinds(append(workloadKinds(), extra...)) }

func sortedKinds(k []string) []string {
	sort.Strings(k)
	return k
}
