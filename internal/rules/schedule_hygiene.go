package rules

import (
	"fmt"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// schedule_hygiene.go — two rows about scheduled work, and one about who a binding grants to.
//
//	NO DOLLARS.

// ── Rule: a CronJob with no startingDeadlineSeconds ──────────────────────────────────────────────

// CronJobNoStartingDeadline reports CronJobs that leave startingDeadlineSeconds unset.
//
// NOT AN OVERLAP WITH cronjob-no-recent-success, and the census checked it by reading: that rule reports
// what the CronJob's STATUS says about whether it has succeeded lately. This reports a SPEC field, is true
// on a CronJob that has never missed a run, and says nothing about whether anything has failed.
type CronJobNoStartingDeadline struct{}

func (CronJobNoStartingDeadline) ID() string      { return "k8s.config.cronjob-no-starting-deadline" }
func (CronJobNoStartingDeadline) Version() string { return "1.0.0" }

func (CronJobNoStartingDeadline) RequiredKinds() []string { return sortedKinds([]string{"cronjobs"}) }

func (r CronJobNoStartingDeadline) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "cronjobs") {
		return nil
	}
	var out []types.Finding
	for i := range inv.CronJobs {
		cj := &inv.CronJobs[i]
		if !opts.IncludeSystem && isSystemNamespace(cj.Namespace) {
			continue
		}
		if cj.Spec.StartingDeadlineSeconds != nil {
			continue
		}
		// A SUSPENDED CronJob schedules nothing, so a missed-start policy has nothing to govern.
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "CronJob", cj.Namespace, cj.Name),
			IDBasis:     &types.ResourceRef{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("CronJob %s/%s sets no startingDeadlineSeconds", cj.Namespace, cj.Name),
			Description: fmt.Sprintf("CronJob %s/%s leaves spec.startingDeadlineSeconds unset. The "+
				"controller then has no bound on how late a missed run may start: after an outage it "+
				"counts every schedule it missed, and past a hundred it stops scheduling the CronJob "+
				"entirely until the next window. With the deadline set, runs older than it are skipped and "+
				"the count never accumulates.",
				cj.Namespace, cj.Name),
			WhyItMatters: "This is a field that costs nothing while everything works and decides what " +
				"happens after a control-plane outage — which is exactly when nobody is reading CronJob " +
				"specs. Whether this cluster has ever hit it is not readable from a snapshot.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("CronJob %s/%s: spec.startingDeadlineSeconds is unset, spec.schedule = %q, "+
					"spec.concurrencyPolicy = %s", cj.Namespace, cj.Name, cj.Spec.Schedule,
					emptyAs(string(cj.Spec.ConcurrencyPolicy), "Allow (default)")),
				"suspended CronJobs are not reported: they schedule nothing, so a missed-start policy has " +
					"nothing to govern",
			},
			Severity:          types.SeverityLow,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── Rule: a binding whose ServiceAccount subject does not exist ──────────────────────────────────

// DanglingBindingSubject reports RoleBindings and ClusterRoleBindings naming a ServiceAccount that is not
// in this reading.
//
// SEPARATE FROM roleref-unresolved BY THE END OF THE ARROW. That rule resolves what a binding grants; this
// resolves who it grants TO. Both can be wrong independently and a binding can be wrong in both ways at
// once, which is why they are two rules rather than one with two branches.
//
// USER AND GROUP SUBJECTS ARE OUT OF REACH AND ARE COUNTED, NEVER JUDGED. Kubernetes has no User object —
// identity comes from the authenticator — so a User subject naming nobody is unfalsifiable from inside the
// cluster. Reporting those would be inventing an absence.
type DanglingBindingSubject struct{}

func (DanglingBindingSubject) ID() string      { return "k8s.rbac.binding-subject-unresolved" }
func (DanglingBindingSubject) Version() string { return "1.0.0" }

func (DanglingBindingSubject) RequiredKinds() []string {
	return sortedKinds([]string{"clusterrolebindings", "rolebindings", "serviceaccounts"})
}

func (r DanglingBindingSubject) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "serviceaccounts", "rolebindings", "clusterrolebindings") {
		return nil
	}
	have := map[string]bool{}
	for i := range inv.ServiceAccounts {
		have[inv.ServiceAccounts[i].Namespace+"/"+inv.ServiceAccounts[i].Name] = true
	}

	type binding struct {
		kind, ns, name string
		subjects       []rbacv1.Subject
	}
	// A binding the API server wrote for itself is skipped — label and exact upstream tuple (see kubernetesOwnBinding):
	// system:controller:service-controller and its siblings name ServiceAccounts for cloud controllers a kind
	// or managed cluster may never run, so their absence is the distribution's, not a finding about anybody's.
	var all []binding
	for i := range inv.RoleBindings {
		b := &inv.RoleBindings[i]
		if kubernetesOwnBinding("RoleBinding", b.Namespace, b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		all = append(all, binding{"RoleBinding", b.Namespace, b.Name, b.Subjects})
	}
	for i := range inv.ClusterRoleBindings {
		b := &inv.ClusterRoleBindings[i]
		if kubernetesOwnBinding("ClusterRoleBinding", "", b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		all = append(all, binding{"ClusterRoleBinding", "", b.Name, b.Subjects})
	}

	var out []types.Finding
	for _, b := range all {
		if b.ns != "" && !opts.IncludeSystem && isSystemNamespace(b.ns) {
			continue
		}
		var missing []string
		var offCluster int
		for _, s := range b.subjects {
			if s.Kind != rbacv1.ServiceAccountKind {
				// User and Group: no object exists to resolve them against, at all.
				offCluster++
				continue
			}
			ns := s.Namespace
			if ns == "" {
				ns = b.ns
			}
			if ns == "" {
				// A ClusterRoleBinding subject with no namespace names nothing resolvable.
				offCluster++
				continue
			}
			if !have[ns+"/"+s.Name] {
				missing = append(missing, ns+"/"+s.Name)
			}
		}
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)
		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("%s %s names %s absent from this reading: %s",
				b.kind, bindingRef(b.kind, b.ns, b.name), nWord(len(missing), "ServiceAccount subject", "ServiceAccount subjects"), commaJoin(missing)),
		}
		if offCluster > 0 {
			evidence = append(evidence, fmt.Sprintf("%s are Users or Groups and are "+
				"NOT judged: Kubernetes has no object for them — identity comes from the authenticator — "+
				"so an absence could not be established from inside the cluster", nWord(offCluster, "further subject", "further subjects")))
		}
		evidence = append(evidence, "whether this binding ever granted anything is in an audit log this "+
			"reading does not have; a name that resolves to nothing is what it reports")

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), b.kind, b.ns, b.name),
			IDBasis:     &types.ResourceRef{Kind: b.kind, Namespace: b.ns, Name: b.name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s grants to a ServiceAccount that is not there",
				b.kind, bindingRef(b.kind, b.ns, b.name)),
			Description: fmt.Sprintf("%s %s names %s that do not exist in this "+
				"reading. The binding is still stored and still evaluated; it simply matches nobody. If "+
				"a ServiceAccount of that name is created later — by a re-install, or by a chart with the "+
				"same values — it inherits this grant immediately and silently.",
				b.kind, bindingRef(b.kind, b.ns, b.name), nWord(len(missing), "ServiceAccount subject", "ServiceAccount subjects")),
			WhyItMatters: "A grant to a subject that does not exist is dormant rather than harmless: it " +
				"is the permission nobody audits, because the account it points at is not there to be " +
				"reviewed alongside it.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategorySecurity,
			AffectedResources: []types.ResourceRef{{Kind: b.kind, Namespace: b.ns, Name: b.name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func bindingRef(kind, ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}
