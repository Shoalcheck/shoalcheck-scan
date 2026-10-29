package history

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// refdata_gate.go — GATE 3: was this produced from the same reference data?
//
// Everything else in the comparison layer asks about the cluster. This gate asks about US: our price table,
// our Kubernetes API-removal schedule, our control text. When one of those moves between two readings, a
// number derived from it moves too — and every sentence the comparison can print about a moving number
// attributes it to the customer.
//
// `gates_test.go:267-269` states the doctrine: "a price table that gains a region between two runs would make
// the strip announce '+$1,200/mo identified' when nothing about the cluster moved at all." Replace "gains a
// region" with "is refreshed" and it describes the shipped product the moment `shoalcheck update` exists.
//
// WHY THE EXISTING GUARD CANNOT SEE IT. pricingCoverageChanged compares two SETS — UnpricedNodeTypes and
// UnpricedStorageClasses. A table update that changes the price of an already-covered instance type leaves
// both sets identical, so the guard returns false and the delta renders. The two are siblings, not
// alternatives: coverage and version are different ways for a sum to move for a non-cluster reason.
//
// THE VERSION IS COMPARED AND THE SOURCE IS NOT. The same table read from the embedded snapshot on Monday and
// from a bundle on Friday is the same table; refusing over provenance would withhold a comparison we are
// entitled to make.

// dataVersions reads a reading's stamps, tolerating every shape of absence — a nil RunBasis, a nil map, a
// report written before the field existed.
func dataVersions(ar *types.AuditReport) map[string]types.DataVersion {
	if ar == nil || ar.Methodology.RunBasis == nil {
		return nil
	}
	return ar.Methodology.RunBasis.DataVersions
}

// datasetVersionsDiffer reports whether one named dataset was read from different versions, and returns the
// two version strings for the caveat.
//
// AN ABSENT STAMP COUNTS AS DIFFERENT. A snapshot written before this shipped has no DataVersions, so its
// figures cannot be confirmed to come from the same table — and `diff.go`'s own precedent settles it: "an
// unconfirmed equivalence is not an equivalence." Consequence, stated rather than discovered: every snapshot
// already on disk loses its dollar delta on the first comparison after this ships, and the label says why.
// One audit cycle later it stops happening.
func datasetVersionsDiffer(name string, prev, cur *types.AuditReport) (differ bool, prevVer, curVer string) {
	pv, pok := dataVersions(prev)[name]
	cv, cok := dataVersions(cur)[name]
	switch {
	case !pok && !cok:
		// NEITHER reading claims a version. That is not an unconfirmed equivalence — it is two readings from
		// the same binary, before this dataset was stamped at all, and withholding on it would withhold every
		// comparison forever for a dataset nothing reads. The gate speaks about datasets a reading names.
		return false, "", ""
	case !pok:
		return true, "", cv.Version
	case !cok:
		return true, pv.Version, ""
	}
	return pv.Version != cv.Version, pv.Version, cv.Version
}

// referenceDataChanged is Gate 3's whole-diff half: which datasets moved, and the prose to print beside the
// withheld sum.
//
// It considers EVERY dataset either reading names, not only the ones a producer declared, because SavingsDelta
// is a sum over the whole report and a dataset feeding any finding in it feeds the sum.
func referenceDataChanged(prev, cur *types.AuditReport) ([]string, string) {
	seen := map[string]bool{}
	for name := range dataVersions(prev) {
		seen[name] = true
	}
	for name := range dataVersions(cur) {
		seen[name] = true
	}

	var moved []string
	var reasons []string
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		differ, pv, cvv := datasetVersionsDiffer(name, prev, cur)
		if !differ {
			continue
		}
		moved = append(moved, name)
		reasons = append(reasons, versionCaveat(name, pv, cvv))
	}
	if len(moved) == 0 {
		return nil, ""
	}
	// THE FOUNDER'S PHRASING, verbatim, because a surface prints it beside a number it did not compute.
	return moved, "not compared — our table changed, not your cluster: " + strings.Join(reasons, "; ")
}

// versionCaveat names the dataset and BOTH versions. A caveat without the two values is unfalsifiable, and an
// absent stamp gets its own sentence rather than an empty one — "the earlier reading does not record which
// version it used" is a different fact from "these two versions differ", and an operator acts differently on
// each.
func versionCaveat(name, prevVer, curVer string) string {
	switch {
	case prevVer == "":
		return fmt.Sprintf("the earlier reading does not record which version of our %s data it used, so the "+
			"two figures cannot be confirmed to come from the same table (this reading used %s)", name, curVer)
	case curVer == "":
		return fmt.Sprintf("this reading does not record which version of our %s data it used, so the two "+
			"figures cannot be confirmed to come from the same table (the earlier reading used %s)", name, prevVer)
	}
	return fmt.Sprintf("these two readings used different versions of our %s data (%s and %s)",
		name, prevVer, curVer)
}

// movedValueDatasets is Gate 3's per-finding half for a VALUE-bearing dataset: the finding exists in both
// readings, so what a moved dataset invalidates is only the derived figure.
//
// Returns the dataset names, which become Change.ValueNotCompared. Empty means the value comparison stays
// armed — and that is what makes the disarm selective rather than total.
func movedValueDatasets(f types.Finding, prev, cur *types.AuditReport, deps map[string]Deps) []string {
	var out []string
	for _, dep := range deps[f.RuleID].Datasets {
		if dep.Presence {
			continue // handled by presenceDatasetMoved, on the way in
		}
		if differ, _, _ := datasetVersionsDiffer(dep.Name, prev, cur); differ {
			out = append(out, dep.Name)
		}
	}
	sort.Strings(out)
	return out
}

// presenceDatasetMoved is Gate 3's per-finding half for a PRESENCE-bearing dataset — one that decides whether
// the finding exists at all.
//
// The finding is in one reading and not the other, and the table that decides whether it can exist moved. So
// we cannot say it arrived and we cannot say it left: we may simply have started, or stopped, listing it. That
// is Gate 1's sentence exactly, which is why it is Gate 1's bucket.
//
// side is which reading the finding came from, and it changes the wording: a current-side entry cannot claim
// arrival, a previous-side entry cannot claim departure.
func presenceDatasetMoved(f types.Finding, prev, cur *types.AuditReport, deps map[string]Deps, side Side) (string, bool) {
	for _, dep := range deps[f.RuleID].Datasets {
		if !dep.Presence {
			continue
		}
		differ, pv, cvv := datasetVersionsDiffer(dep.Name, prev, cur)
		if !differ {
			continue
		}
		verdict := "we cannot say whether it arrived or whether we started listing it"
		if side == SidePrevious {
			verdict = "we cannot say whether it left or whether we stopped listing it"
		}
		return fmt.Sprintf("this finding rests on our %s data, and %s, so %s",
			dep.Name, presenceVersions(pv, cvv), verdict), true
	}
	return "", false
}

func presenceVersions(prevVer, curVer string) string {
	switch {
	case prevVer == "":
		return "the earlier reading does not record which version of it was used (this reading used " + curVer + ")"
	case curVer == "":
		return "this reading does not record which version of it was used (the earlier reading used " + prevVer + ")"
	}
	return fmt.Sprintf("the two readings used different versions of it (%s and %s)", prevVer, curVer)
}
