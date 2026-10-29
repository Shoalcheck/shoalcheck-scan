package rules

import (
	"fmt"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/kubeversions"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// hoursPerMonth matches internal/pricing's convention so an hourly surcharge becomes a monthly
// figure the same way every other rate in the report does.
const versionHoursPerMonth = 730

// VersionPastStandardSupport reports a cluster running a Kubernetes minor whose ordinary support
// window has closed.
//
// WHY THIS IS A COST RULE AND NOT A HYGIENE ONE. "Your version is old" is advice everyone has
// already heard and nobody costed. Past ordinary support, EKS and AKS bill a per-cluster surcharge
// every hour — a charge that appears on the invoice, is caused by a field the cluster reports about
// itself, and is visible NOWHERE from inside the cluster. It is the rare case where a snapshot can
// name money that is leaving right now, rather than money that could be saved by rearranging things.
//
// WHY THE UNSUPPORTED CASE CARRIES NO DOLLAR. Past the paid extension too, or on a provider that
// sells no extension, there is no surcharge to stop — the exposure is that security patches have
// stopped, which is a different claim and not one denominated in dollars. Reporting a figure there
// would be inventing one.
//
// WHAT IT REFUSES. It says nothing when the version cannot be placed in a published window: an
// unrecognised provider, a minor the table does not carry, or a server version string that does not
// parse. Silence there is the honest reading — StatusUnknown is not StatusSupported, and the
// methodology carries the reason.
type VersionPastStandardSupport struct{}

func (VersionPastStandardSupport) ID() string {
	return "k8s.cost.kubernetes-version-past-standard-support"
}
func (VersionPastStandardSupport) Version() string { return "1.0.0" }

func (VersionPastStandardSupport) RequiredKinds() []string { return []string{"nodes"} }

func (r VersionPastStandardSupport) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	provider := providerFromNodes(inv.Nodes)
	// The KEY indexes the table; the NAME is what a person reads. They are different strings and this rule
	// printed the key in five places, including the title, which travels to every surface this product has.
	name := kubeversions.ProviderName(provider)
	minor := kubeversions.Minor(inv.Meta.ServerVersion)
	if provider == "" || minor == "" {
		return nil
	}
	// THE SNAPSHOT'S OWN CLOCK, NOT THE WALL CLOCK. Re-rendering yesterday's collection must not
	// produce a different verdict today; the question is where the version stood when it was read.
	status, window := kubeversions.StatusOn(provider, minor, inv.Meta.StartedAt)
	if status != kubeversions.StatusExtended && status != kubeversions.StatusUnsupported {
		return nil
	}

	var dollar float64
	var basis types.PriceBasis
	var priceNote string
	switch {
	case status == kubeversions.StatusExtended:
		if hourly, ok := opts.prices().ExtendedSupportHourly(provider); ok {
			dollar = hourly * versionHoursPerMonth
			basis = types.PricePriced
			priceNote = fmt.Sprintf(
				"%s bills $%.4f per cluster-hour on top of the ordinary control-plane rate while a version is "+
					"in extended support — about $%.2f a month for this cluster, every month until it is "+
					"upgraded. The figure is the SURCHARGE alone: the ordinary control plane is billed either "+
					"way, so an upgrade stops this amount and not the whole control-plane bill.",
				name, hourly, dollar)
		} else {
			basis = types.PriceUnpriced
			priceNote = fmt.Sprintf(
				"this build carries no published extended-support rate for %s, so the monthly figure is "+
					"withheld rather than estimated — the support state below is unchanged by that",
				name)
		}
	default: // unsupported
		basis = types.PriceNotCost
		priceNote = "past the extension there is no surcharge left to stop, so there is no figure here — " +
			"what changes past this point is that patches have ended, which is not a number"
	}

	evidence := []string{
		snapshotNote(inv),
		fmt.Sprintf("the API server reports %s, which is minor %s on %s",
			emptyAs(inv.Meta.ServerVersion, "(unreported)"), minor, name),
		fmt.Sprintf("published window for %s %s: released %s, ordinary support ended %s%s",
			name, minor, emptyAs(window.Released, "(unpublished)"), window.StandardEnds,
			extendedClause(window.ExtendedEnds)),
		priceNote,
		fmt.Sprintf("support dates are from the reference table fetched %s; they are compared against the "+
			"snapshot's own timestamp, not against today, so re-rendering this collection cannot change the "+
			"verdict", kubeversions.AsOf()),
		"this reading is the version's SUPPORT STATE. Whether an upgrade is safe for this cluster is a " +
			"different question, and k8s.reliability's upgrade rules are where it is asked",
	}

	title := fmt.Sprintf("Kubernetes %s is past %s's ordinary support window", minor, name)
	why := "A version past ordinary support is billed at a higher per-cluster rate by EKS and AKS, and " +
		"nothing inside the cluster says so — the charge appears on an invoice nobody reads beside a " +
		"version number nobody connected to it."
	sev := types.SeverityMedium
	if status == kubeversions.StatusUnsupported {
		title = fmt.Sprintf("Kubernetes %s is past every support window %s publishes", minor, name)
		why = "Past the last published window a version receives no security patches from the provider, " +
			"and no supported upgrade path is guaranteed to remain open indefinitely."
		sev = types.SeverityHigh
	}

	return []types.Finding{{
		ID:                  findingID(r.ID(), "Cluster", "", minor),
		IDBasis:             &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: minor},
		RuleID:              r.ID(),
		RuleVersion:         r.Version(),
		Title:               title,
		Description:         fmt.Sprintf("The cluster reports Kubernetes %s. %s", minor, supportSentence(status, name, window)),
		WhyItMatters:        why,
		Evidence:            evidence,
		Severity:            sev,
		Category:            types.CategoryCost,
		DollarImpactMonthly: dollar,
		PriceBasis:          basis,

		SpendKind:         types.SpendControlPlane,
		EstimatedEffort:   types.EffortHigh,
		Confidence:        1.0,
		AffectedResources: []types.ResourceRef{{Kind: "Cluster", Name: minor}},
		Provenance:        provenance(),
	}}
}

func extendedClause(ext string) string {
	if ext == "" {
		return ", and this provider publishes no paid extension for it"
	}
	return fmt.Sprintf(", paid extension ends %s", ext)
}

// providerName is the NAME, not the table key — see kubeversions.ProviderName.
func supportSentence(s kubeversions.Status, providerName string, w kubeversions.Window) string {
	if s == kubeversions.StatusExtended {
		return fmt.Sprintf("Ordinary support from %s ended on %s; the cluster is inside the paid extension, "+
			"which ends %s.", providerName, w.StandardEnds, w.ExtendedEnds)
	}
	if w.ExtendedEnds != "" {
		return fmt.Sprintf("Ordinary support ended %s and the paid extension ended %s.", w.StandardEnds, w.ExtendedEnds)
	}
	return fmt.Sprintf("Ordinary support ended %s and %s publishes no extension for it.", w.StandardEnds, providerName)
}
