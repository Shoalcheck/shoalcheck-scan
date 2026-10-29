package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// conditional_boundaries_test.go — the half a static table cannot hold.
//
// A FAMILY boundary is true on every cluster: a PodDisruptionBudget gates voluntary eviction only, wherever
// you read it. A CONDITIONAL boundary is true of ONE READING — "three of these pods matched no endpoint entry"
// — and it is the more valuable half, because it says what this particular reading could not establish rather
// than what the rule can never establish. It is also the half that can quietly stop being emitted, since a
// table with an entry missing is visible and a conditional that stopped firing is not.

// A reading that never read EndpointSlices must say so as a boundary, not only as evidence.
func TestEndpointBoundaries_ASlicelessReadingSaysSo(t *testing.T) {
	inv := &collect.Inventory{Meta: collect.Meta{Collected: []string{"pods"}}}
	got := endpointBoundaries(inv, []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-0"}}})
	if len(got) != 1 || !strings.Contains(got[0], "EndpointSlices were not read") {
		t.Fatalf("a reading with no EndpointSlices produced %v", got)
	}
}

// NON-VACUITY IN THE OTHER DIRECTION: a reading that DID read them, and where every pod resolved, produces no
// conditional at all. A function that always returns a sentence would pass the test above and mean nothing.
func TestEndpointBoundaries_ACleanReadingProducesNone(t *testing.T) {
	inv := &collect.Inventory{Meta: collect.Meta{Collected: []string{"pods", "endpointslices"}}}
	got := endpointBoundaries(inv, nil)
	for _, line := range got {
		if strings.Contains(line, "were not read") {
			t.Errorf("a reading that read the slices still claims it did not: %q", line)
		}
	}
}

// The zone-label conditional fires on the retired key and stays silent on the current one.
func TestZoneLabelBoundaries_NameTheKeyTheReadingRestsOn(t *testing.T) {
	node := func(key, zone string) corev1.Node {
		n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n-" + zone}}
		if key != "" {
			n.Labels = map[string]string{key: zone}
		}
		return n
	}

	// Current key only: nothing to say.
	cur := &collect.Inventory{Nodes: []corev1.Node{node(collect.GAZoneLabel, "a"), node(collect.GAZoneLabel, "b")}}
	if got := zoneLabelBoundaries(cur); len(got) != 0 {
		t.Errorf("a cluster on the current zone label produced a boundary: %v", got)
	}

	// Retired key only: say which key the failure domains came from.
	old := &collect.Inventory{Nodes: []corev1.Node{node(collect.BetaZoneLabel, "a"), node(collect.BetaZoneLabel, "b")}}
	got := zoneLabelBoundaries(old)
	if len(got) != 1 || !strings.Contains(got[0], collect.BetaZoneLabel) {
		t.Fatalf("a cluster on the retired label produced %v", got)
	}
	if strings.Contains(got[0], "of the nodes") {
		t.Errorf("an all-retired cluster was described as a mixture: %q", got[0])
	}

	// A MIXTURE IS ITS OWN SENTENCE, because "some nodes carry one key and some the other" is a different and
	// worse fact than either uniform case: the failure domains are assembled from two keys a provider is not
	// required to keep in agreement.
	mix := &collect.Inventory{Nodes: []corev1.Node{node(collect.GAZoneLabel, "a"), node(collect.BetaZoneLabel, "b")}}
	m := zoneLabelBoundaries(mix)
	if len(m) != 1 || !strings.Contains(m[0], "1 of the nodes") {
		t.Fatalf("a mixed cluster produced %v", m)
	}

	// And an unlabelled cluster says nothing here — that case has a finding of its own which explains it in
	// full, and a boundary repeating it would be noise.
	none := &collect.Inventory{Nodes: []corev1.Node{node("", "a")}}
	if got := zoneLabelBoundaries(none); len(got) != 0 {
		t.Errorf("an unlabelled cluster produced a zone-key boundary: %v", got)
	}
}
