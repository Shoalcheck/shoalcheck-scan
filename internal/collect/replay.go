package collect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// replay.go — an inventory this package did not read from an API server, and an independent copy of one it did.
//
// `shoalcheck gate --with` judges a pull request's manifests by evaluating the cluster twice: as it was read, and
// with the manifests laid over a COPY of what was read. Clone is that copy. A gate run from a capture, or from
// manifests alone, has no API server to read; FromInventory is the collector for that case, so the run goes
// through the same pipeline — the same rules, analyzers, assembly and validation — rather than a second one that
// could drift from the first.

// Clone returns an independent copy of the inventory.
//
// THROUGH THE CAPTURE'S OWN ENCODING, on purpose. A capture is the one place this package already promises that
// an inventory survives a round-trip with nothing a rule reads dropped, reordered or re-dated — the two
// struct-keyed maps and the reading clock included — and internal/pipeline's replay test holds it to that. A
// hand-written deep copy would be a second promise with no test behind it, and the first field somebody added
// to Inventory without adding it there would be shared between the two halves of a comparison.
//
// The read volume travels too, though a capture file does not carry it: a copy of a reading read exactly what
// the reading read, and whatever is laid over the copy afterwards was not read from anywhere.
func (inv *Inventory) Clone() (*Inventory, error) {
	b, err := json.Marshal(inv)
	if err != nil {
		return nil, fmt.Errorf("collect: copy the inventory: %w", err)
	}
	var out Inventory
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("collect: copy the inventory: %w", err)
	}
	if inv.volume != nil {
		v := *inv.volume
		v.ByKind = append([]types.KindVolume(nil), inv.volume.ByKind...)
		out.volume = &v
	}
	return &out, nil
}

// FromInventory is a collector that reads no cluster: its Collect returns a copy of inv, as recorded — every kind
// it says was read, every kind it says was not and why, and the clock it was taken at.
//
// THE RECORD IS REPLAYED, NOT RE-DERIVED. A kind the original reading could not read stays unread here, so the
// rules' denial guards stay silent about it exactly as they were the first time; an inventory that came back
// with every kind marked read would let a rule PASS a control on a list nobody looked at.
//
// It has no connection, and says so: RESTConfig and Clientset return nil, which is what tells the pipeline there
// is no Prometheus to reach and no request to count.
func FromInventory(inv *Inventory) *Collector {
	return &Collector{replay: inv, contextName: inv.Meta.Context}
}

// replayed is Collect for a FromInventory collector.
func (c *Collector) replayed() (*Inventory, error) {
	out, err := c.replay.Clone()
	if err != nil {
		return nil, err
	}
	if c.onStep != nil {
		counts := countsOf(out)
		for _, k := range out.Meta.Collected {
			if !out.Meta.HasCollected(k) {
				continue
			}
			n := 0
			if g := counts[k]; g != nil {
				n = g()
			}
			c.onStep(k, n, "")
		}
		for _, d := range out.Meta.Denied {
			kind, cause, _ := strings.Cut(d, ":")
			c.onStep(kind, 0, CauseOf(strings.TrimSpace(cause)))
		}
	}
	return out, nil
}
