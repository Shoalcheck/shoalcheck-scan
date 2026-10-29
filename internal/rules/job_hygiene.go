package rules

import (
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// job_hygiene.go — finished Jobs nothing will ever delete, and the truncation that makes the count honest.

// JobNoTTL reports finished Jobs with no ttlSecondsAfterFinished and no controller to clean them up.
//
// THE TRUNCATION IS PART OF THE CLAIM. The collector caps the Job list, because a cluster running nightly
// work for a year holds tens of thousands, and it records that it capped. A count over a truncated list
// rendered as a total would be absence-as-fact wearing a number — so where the list was cut, this rule says
// "at least N" and says why.
type JobNoTTL struct{}

func (JobNoTTL) ID() string      { return "k8s.config.job-no-ttl" }
func (JobNoTTL) Version() string { return "1.0.0" }

func (JobNoTTL) RequiredKinds() []string { return sortedKinds([]string{"jobs"}) }

func (r JobNoTTL) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "jobs") {
		return nil
	}
	byNS := map[string][]string{}
	for i := range inv.Jobs {
		j := &inv.Jobs[i]
		if !opts.IncludeSystem && isSystemNamespace(j.Namespace) {
			continue
		}
		// A RUNNING JOB IS NOT LITTER. TTL applies from completion, so a Job that has not finished has
		// nothing to expire — and reporting it would fire on every job in flight during the audit.
		if j.Status.CompletionTime == nil && j.Status.Failed == 0 {
			continue
		}
		if j.Spec.TTLSecondsAfterFinished != nil {
			continue
		}
		// A CRONJOB-OWNED JOB IS ALREADY BOUNDED by its parent's history limits, which default to 3 and 1.
		// Reporting those would report the controller doing its job, and it is why "collect only
		// CronJob-owned jobs" would have excluded this rule's entire subject.
		if ownedByCronJob(inv, j.Namespace, j.OwnerReferences) {
			continue
		}
		byNS[j.Namespace] = append(byNS[j.Namespace], j.Name)
	}

	nss := make([]string, 0, len(byNS))
	for ns := range byNS {
		nss = append(nss, ns)
	}
	sort.Strings(nss)

	var out []types.Finding
	for _, ns := range nss {
		names := byNS[ns]
		sort.Strings(names)
		count := fmt.Sprintf("%d", len(names))
		countWord := pick(len(names), "finished Job", "finished Jobs")
		if inv.JobsTruncated {
			count = fmt.Sprintf("at least %d", len(names))
			countWord = "finished Jobs, and the true number is not known"
		}
		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("%s %s in %s with no spec.ttlSecondsAfterFinished and no CronJob owner: %s",
				count, countWord, ns, joinList(names)),
			"a Job still running is not reported: ttlSecondsAfterFinished applies from completion, so " +
				"there is nothing yet to expire",
			"a Job owned by a CronJob is not reported either — its parent's successfulJobsHistoryLimit " +
				"and failedJobsHistoryLimit already bound it, and reporting those would report the " +
				"controller working",
		}
		if inv.JobsTruncated {
			evidence = append(evidence, "THE JOB LIST WAS TRUNCATED by this reading's own cap, so the "+
				"number above is a floor and not a total. A bounded list presented as complete would be "+
				"the defect this disclosure exists to prevent.")
		}
		refs := make([]types.ResourceRef, 0, len(names))
		for _, n := range names {
			refs = append(refs, types.ResourceRef{Kind: "Job", Namespace: ns, Name: n})
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Namespace", ns, "jobs-without-ttl"),
			IDBasis:     &types.ResourceRef{Kind: "Namespace", Namespace: ns, Name: "jobs-without-ttl"},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s finished %s in %s will never be cleaned up", count,
				pick(len(names), "Job", "Jobs"), ns),
			Description: fmt.Sprintf("%s %s in namespace %s set no "+
				"ttlSecondsAfterFinished and %s owned by no CronJob. Nothing deletes %s: a finished "+
				"Job and its pods stay in etcd until somebody removes them by hand, and each keeps a pod "+
				"object with it.", count, pick(len(names), "finished Job", "finished Jobs"), ns,
				pick(len(names), "is", "are"), pick(len(names), "it", "them")),
			WhyItMatters: "Finished Jobs accumulate silently and are counted by everything that lists " +
				"pods — the scheduler's view, kubectl output, and this audit's own pod-scoped rules. The " +
				"cost is not the disk; it is that every later reading of the namespace is noisier.",
			Evidence:          evidence,
			Severity:          types.SeverityLow,
			Category:          types.CategoryConfig,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

// ownedByCronJob reports whether a Job's controller is a CronJob. It matches on the owner's KIND rather
// than resolving the CronJob object, because a CronJob deleted after its Jobs still leaves that owner
// reference — and those Jobs are then genuinely unowned litter, which is the case this rule is for.
func ownedByCronJob(inv *collect.Inventory, ns string, owners []metav1.OwnerReference) bool {
	for _, o := range owners {
		if o.Kind != "CronJob" {
			continue
		}
		for i := range inv.CronJobs {
			if inv.CronJobs[i].Namespace == ns && inv.CronJobs[i].Name == o.Name {
				return true
			}
		}
	}
	return false
}
