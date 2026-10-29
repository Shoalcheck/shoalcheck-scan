package collect

import "testing"

// A DENIED READ IS NOT A COLLECTED ONE, EVEN WHEN BOTH LISTS NAME IT.
//
// Meta.Collected and Meta.Denied are both appended to by the step() wrapper, and a step can plausibly land
// in both across a paginated list that failed partway. The compliance assessment reads this to decide
// whether a control may PASS at all, so "collected wins" would produce a clean bill from a refused read —
// which is the one outcome the PASS-invariant exists to prevent.
func TestMetaHasCollected_DenialWins(t *testing.T) {
	m := Meta{
		Collected: []string{"pods", "clusterroles", "roles"},
		// Denied entries are formatted "<kind>: <err>", so the prefix is what must match — not the whole
		// string, which carries an error message nobody can predict.
		Denied: []string{"clusterroles: clusterroles.rbac.authorization.k8s.io is forbidden"},
	}

	for _, tc := range []struct {
		kind string
		want bool
		why  string
	}{
		{"pods", true, "collected and not denied"},
		{"roles", true, "collected and not denied"},
		{"clusterroles", false, "denied, even though it is also in Collected"},
		{"networkpolicies", false, "never mentioned at all"},
	} {
		if got := m.HasCollected(tc.kind); got != tc.want {
			t.Errorf("HasCollected(%q) = %v, want %v — %s", tc.kind, got, tc.want, tc.why)
		}
	}

	// NON-VACUITY: an empty Meta must answer false for everything, or "false" could be the only answer the
	// function knows how to give.
	var empty Meta
	if empty.HasCollected("pods") {
		t.Error("an empty Meta claims pods were collected")
	}
	// And the prefix match must not be a substring match: a kind that merely starts the same is a different
	// kind, and `roles` is a prefix of `rolebindings`.
	m2 := Meta{Collected: []string{"rolebindings"}, Denied: []string{"roles: forbidden"}}
	if !m2.HasCollected("rolebindings") {
		t.Error("a denial of `roles` was read as a denial of `rolebindings`")
	}
}
