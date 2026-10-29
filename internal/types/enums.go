// Package types defines the shoalcheck audit report schema.
//
// SchemaVersion "v1" is a forever commitment. The same schema serves both
// the hand-crafted v0 demo fixtures and the production reports generated
// from real clusters in Phase 2+. Migrations are explicit (new SchemaVersion).
package types

// Severity ranks the urgency of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Valid reports whether s is a recognized severity value.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Category groups findings by the kind of risk or impact they represent.
type Category string

const (
	CategoryCost        Category = "cost"
	CategoryReliability Category = "reliability"
	CategorySecurity    Category = "security"
	CategoryConfig      Category = "config"
	CategoryCompliance  Category = "compliance"
)

// Valid reports whether c is a recognized category value.
func (c Category) Valid() bool {
	switch c {
	case CategoryCost, CategoryReliability, CategorySecurity, CategoryConfig, CategoryCompliance:
		return true
	}
	return false
}

// EffortLevel estimates the work required to apply a remediation.
type EffortLevel string

const (
	EffortLow    EffortLevel = "low"    // < 30 min, no risk
	EffortMedium EffortLevel = "medium" // < 4h, some risk
	EffortHigh   EffortLevel = "high"   // > 4h, requires planning
)

// Valid reports whether e is a recognized effort level.
func (e EffortLevel) Valid() bool {
	switch e {
	case EffortLow, EffortMedium, EffortHigh:
		return true
	}
	return false
}

// ControlStatus is the verdict for one enumerated compliance control.
// PASS/FAIL/MANUAL/NA are OBSERVATIONS, never a QSA verdict; the renderer
// reframes PASS as "No gap observed" and FAIL as "Potential gap".
type ControlStatus string

const (
	ControlStatusPass   ControlStatus = "PASS"   // evidence rule(s) ran, no finding
	ControlStatusFail   ControlStatus = "FAIL"   // >=1 finding maps to this control
	ControlStatusManual ControlStatus = "MANUAL" // in scope, not machine-evaluable
	ControlStatusNA     ControlStatus = "NA"     // out of scope for this cluster
)

func (s ControlStatus) Valid() bool {
	switch s {
	case ControlStatusPass, ControlStatusFail, ControlStatusManual, ControlStatusNA:
		return true
	}
	return false
}

// ProfileLevel is the CIS benchmark profile (L1 baseline / L2 defense-in-depth).
// Carried as metadata, never scored. Zero value = unspecified.
type ProfileLevel int

const (
	ProfileLevel1 ProfileLevel = 1
	ProfileLevel2 ProfileLevel = 2
)

func (p ProfileLevel) Valid() bool { return p == 0 || p == ProfileLevel1 || p == ProfileLevel2 }

// CapacityType records how a node's capacity is purchased, read from read-only
// node labels (zero RBAC change). The zero value "" is Valid so an omitempty-
// absent field never fails Validate — a node with no capacity signal is the
// real, legitimate CapacityUnknown state, NEVER silently defaulted to on-demand.
type CapacityType string

const (
	CapacitySpot     CapacityType = "spot"
	CapacityOnDemand CapacityType = "on-demand"
	CapacityUnknown  CapacityType = "unknown" // no capacity label IS a real state — never default to on-demand
)

// Valid reports whether c is a recognized capacity type. The zero value "" is
// Valid so omitempty-absent fields validate byte-identically against old fixtures.
func (c CapacityType) Valid() bool {
	switch c {
	case "", CapacitySpot, CapacityOnDemand, CapacityUnknown:
		return true
	}
	return false
}

// CostSource is the PROVENANCE of a cost number — the basis on which it was
// derived, NOT a measure of accuracy. The honesty rename lives here:
// CostSourceSpotCeiling means "the on-demand list price shown for this spot
// pool is an UPPER BOUND, not a fabricated lower number" (was the proposals'
// misleading "spot-adjusted"). CostSourceBilled is RESERVED for a future Layer 2
// billing-reconciliation module and is NEVER emitted by the read-only Layer 0/1
// pipeline.
type CostSource string

const (
	CostSourceListEstimate CostSource = "list-estimate" // on-demand list price (today's only mode)
	CostSourceSpotCeiling  CostSource = "spot-ceiling"  // list price for a spot pool = UPPER BOUND, real spend lower
	CostSourceBilled       CostSource = "billed"        // reconciled against the cloud bill (Layer 2 only — never emitted by P1)
	// CostSourceUnpriced — THE FOURTH STATE, and its absence was a shipped defect.
	//
	// A pool whose (provider, region, instance type) the table does not carry keeps CostMo 0, and
	// assemble stamped CostSource BEFORE the price lookup — so the price-not-found branch left
	// "list-estimate" in place and the pool travelled as {cost: 0, costSource: "list-estimate"}: the
	// same source string as a pool that WAS priced at $887.68.
	//
	// The document survived it by cross-referencing Architecture.UnpricedNodeTypes. The instrument
	// could not — its island carries the pools and never carried that list — so its Cost workspace
	// printed "$0" under the pool's own name, "9 × $0" beside it, and "Standard_D4as_v5 ·
	// list-estimate" as the basis: a list-price estimate asserted for a type nobody could price. That
	// is the fake zero this product forbids, in the one workspace whose whole subject is money.
	//
	// "unpriced" IS a cost source. It says where the number came from, which is nowhere.
	CostSourceUnpriced CostSource = "unpriced"
)

// Valid reports whether c is a recognized cost source. The zero value "" is
// Valid so omitempty-absent fields validate byte-identically against old fixtures.
func (c CostSource) Valid() bool {
	switch c {
	case "", CostSourceListEstimate, CostSourceSpotCeiling, CostSourceBilled, CostSourceUnpriced:
		return true
	}
	return false
}
