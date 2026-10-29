package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// capture.go — one reading's Inventory, written to a file and read back identically.
//
// WRITTEN BY `shoalcheck audit --capture` AND READ BY `shoalcheck gate --capture`, so a pull request can be judged in
// a pipeline that may not hold a kubeconfig: the capture stands in for the cluster, replayed through FromInventory.
//
// WHY THIS EXISTS. The product's re-derivability claim is that the same inventory yields the same findings.
// Proving that within one process is cheap and proves little: a map whose range order varies would have to
// vary twice the same way to fool it. Proving it ACROSS PROCESSES needs the inventory to survive a file, and
// until now it could not: two of its fields are maps KEYED BY A STRUCT, which encoding/json cannot marshal as
// a map key at all. Everything else on the Inventory is exported and marshals by default, so the whole of the
// work is those two keys.
//
// WHAT A CAPTURE FILE HOLDS, PLAINLY. Every object the reading collected: pod specs, RBAC role bodies, PVC
// specs, the CRs of every operator it recognised. It holds no Secret or ConfigMap VALUES, no environment
// variables and no logs, because the collector never reads them — but a capture is still the most sensitive
// artifact this product can write, more so than a report, which carries findings rather than objects.
//
// So it is written with the history store's posture and for the same reason: 0700 on the directory, 0600 on
// the file. It is a LOCAL artifact. Nothing in this product sends one anywhere, and nothing should: the
// re-derivation a CUSTOMER can perform is over the report and the published id recipe, not over a capture.
//
// THE READING CLOCK TRAVELS, and that is load-bearing. Meta.StartedAt is an ordinary field, so it round-trips
// with everything else — which is what makes a replayed inventory produce the findings the original did.
// internal/rules.readingTime and internal/analyzers.readingTime both fall back to wall-clock now when it is
// zero, so a harness that dropped it would silently re-date every window. The test asserts the captured value,
// not merely that a clock is present.

// gvrKey is the wire form of a GroupVersionResource: "<group>/<version>/<resource>", with the group empty for
// core ("v1/pods"). Chosen over GroupVersionResource.String(), which renders "cert-manager.io/v1,
// Resource=certificates" — readable, but not something to parse back.
func gvrKey(gvr schema.GroupVersionResource) string {
	return gvr.GroupVersion().String() + "/" + gvr.Resource
}

// parseGVRKey is gvrKey backwards. The resource is the last segment; everything before it is a GroupVersion,
// which apimachinery already knows how to read.
func parseGVRKey(s string) (schema.GroupVersionResource, error) {
	i := strings.LastIndexByte(s, '/')
	if i <= 0 || i == len(s)-1 {
		return schema.GroupVersionResource{}, fmt.Errorf("collect: %q is not <group>/<version>/<resource>", s)
	}
	gv, err := schema.ParseGroupVersion(s[:i])
	if err != nil {
		return schema.GroupVersionResource{}, fmt.Errorf("collect: %q: %w", s, err)
	}
	return gv.WithResource(s[i+1:]), nil
}

// MarshalJSON writes the set as a SORTED list of keys. Sorted because a set has no order and a capture file
// must not differ between two readings of one cluster for a reason as arbitrary as map iteration.
func (s GVRSet) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(s))
	for gvr := range s {
		keys = append(keys, gvrKey(gvr))
	}
	sort.Strings(keys)
	return json.Marshal(keys)
}

func (s *GVRSet) UnmarshalJSON(b []byte) error {
	var keys []string
	if err := json.Unmarshal(b, &keys); err != nil {
		return err
	}
	out := make(GVRSet, len(keys))
	for _, k := range keys {
		gvr, err := parseGVRKey(k)
		if err != nil {
			return err
		}
		out[gvr] = struct{}{}
	}
	*s = out
	return nil
}

// StackObjectMap is Inventory.StackObjects as a named type, so it can carry the same two marshalers. The map
// shape is unchanged, so every existing index and range over the field still compiles.
type StackObjectMap map[schema.GroupVersionResource][]unstructured.Unstructured

func (m StackObjectMap) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(m))
	index := make(map[string]schema.GroupVersionResource, len(m))
	for gvr := range m {
		k := gvrKey(gvr)
		keys = append(keys, k)
		index[k] = gvr
	}
	sort.Strings(keys)
	// An ordered object rather than a Go map, so the bytes are stable.
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := json.Marshal(m[index[k]])
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

func (m *StackObjectMap) UnmarshalJSON(b []byte) error {
	var raw map[string][]unstructured.Unstructured
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	out := make(StackObjectMap, len(raw))
	for k, v := range raw {
		gvr, err := parseGVRKey(k)
		if err != nil {
			return err
		}
		out[gvr] = v
	}
	*m = out
	return nil
}

// CaptureFormat names the shape of a capture file. A build reads exactly the format it writes and refuses every
// other: an inventory whose shape moved underneath it would decode with fields silently zero — a kind that reads as
// empty rather than unread — and `gate --capture` would judge a change against a cluster that never existed. Bump it
// when Inventory changes in a way an older file cannot carry.
const CaptureFormat = "shoalcheck-capture/1"

// captureFile is a capture on disk: the format and the moment first, so a reader can refuse before it decodes the
// inventory, and so a person opening the file can see what and when it is.
type captureFile struct {
	Format     string     `json:"format"`
	CapturedAt time.Time  `json:"capturedAt"`
	Context    string     `json:"context,omitempty"`
	Inventory  *Inventory `json:"inventory"`
}

// SaveCapture writes one inventory to path. The directory is created 0700 and the file written 0600, the same
// posture internal/history uses for snapshots and for the same reason: this file holds cluster internals.
func SaveCapture(path string, inv *Inventory) error {
	b, err := MarshalCapture(inv)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	// os.WriteFile keeps an existing file's mode, so a capture written over a looser file would inherit it.
	return os.Chmod(path, 0o600)
}

// MarshalCapture is the bytes of a capture file, in memory: what a caller signs, and then writes, without the file
// ever being read back from disk in between.
func MarshalCapture(inv *Inventory) ([]byte, error) {
	if inv == nil {
		return nil, fmt.Errorf("collect: nothing to capture")
	}
	b, err := json.Marshal(captureFile{Format: CaptureFormat, CapturedAt: inv.Meta.StartedAt, Context: inv.Meta.Context, Inventory: inv})
	if err != nil {
		return nil, fmt.Errorf("collect: capture: %w", err)
	}
	return b, nil
}

// LoadCapture reads one back, refusing a file that does not say it is a capture of the format this build reads.
func LoadCapture(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	inv, _, err := ParseCapture(b, path)
	return inv, err
}

// ParseCapture decodes capture bytes already in hand — the very bytes a caller has verified a signature over, so
// nothing can change between the check and the read. It returns the moment the capture records in its header,
// which must agree with the inventory's own reading clock: a header that says one time over an inventory read at
// another is two claims about one file, and neither can be trusted.
func ParseCapture(b []byte, name string) (*Inventory, time.Time, error) {
	var f captureFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, time.Time{}, fmt.Errorf("collect: read capture %s: %w", name, err)
	}
	switch {
	case f.Format == "":
		return nil, time.Time{}, fmt.Errorf("%s does not say which capture format it is: it was written by a build "+
			"from before captures carried one, or it is not a capture — take a new one with shoalcheck audit --capture", name)
	case f.Format != CaptureFormat:
		return nil, time.Time{}, fmt.Errorf("%s is capture format %q, and this build reads %q only — take a new "+
			"capture with this build (shoalcheck audit --capture)", name, f.Format, CaptureFormat)
	case f.Inventory == nil:
		return nil, time.Time{}, fmt.Errorf("%s says it is a capture and holds no inventory", name)
	case !f.CapturedAt.Equal(f.Inventory.Meta.StartedAt):
		return nil, time.Time{}, fmt.Errorf("%s says it was captured at %s over an inventory read at %s — two "+
			"claims about one file; refused", name, f.CapturedAt.UTC().Format(time.RFC3339),
			f.Inventory.Meta.StartedAt.UTC().Format(time.RFC3339))
	}
	return f.Inventory, f.CapturedAt, nil
}
