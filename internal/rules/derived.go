package rules

import (
	"sync"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// Derived is the reading's derived indexes — owner chains, pods by owner, the drain placement per node, the
// placement model — built once and shared by every rule (ENG-22). Each was built by the rule that needed it, so one
// reading built the owner index seven times and the placement model three. The inventory they are built from is not
// changed by any rule (TestRules_NoRuleChangesTheInventory), which is what makes sharing them sound.
//
// The pipeline sets Options.Derived; a rule given none, or one built over another inventory, builds its own.
type Derived struct {
	inv *collect.Inventory

	ownersOnce sync.Once
	owners     *ownerIndex

	podsOnce sync.Once
	pods     podIndex

	drainOnce sync.Once
	drain     map[string]*drainPlacement

	modelOnce sync.Once
	model     *placementModel
}

// NewDerived is the derived indexes over inv, each built on first use.
func NewDerived(inv *collect.Inventory) *Derived { return &Derived{inv: inv} }

// derived is opts.Derived when it was built over inv, else a fresh one.
func derived(inv *collect.Inventory, opts Options) *Derived {
	if d := opts.Derived; d != nil && d.inv == inv {
		return d
	}
	return NewDerived(inv)
}

func (d *Derived) ownerIndex() *ownerIndex {
	d.ownersOnce.Do(func() { d.owners = newOwnerIndex(d.inv) })
	return d.owners
}

func (d *Derived) podIndex() podIndex {
	d.podsOnce.Do(func() { d.pods = newPodIndexWith(d.inv, d.ownerIndex()) })
	return d.pods
}

func (d *Derived) drainPlacement() map[string]*drainPlacement {
	d.drainOnce.Do(func() { d.drain = buildDrainPlacementWith(d.inv, d.ownerIndex()) })
	return d.drain
}

func (d *Derived) placementModel() *placementModel {
	d.modelOnce.Do(func() { d.model = newPlacementModel(d.inv) })
	return d.model
}
