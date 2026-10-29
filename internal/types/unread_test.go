package types

import (
	"testing"
)

// TestUnreadKinds_ReadTheCauseBackOutOfTheNote.
//
// Every surface that renders a SAVED reading — the document, the instrument, the app, the evidence pack —
// has only the note to go on, because DeniedKinds carries names and the error text is deliberately not on
// the schema. Each of them was inventing a cause instead: "Grant the read-only role", "Refused by the API
// server", "denied by RBAC", over clusters that had never been reached.
func TestUnreadKinds_ReadTheCauseBackOutOfTheNote(t *testing.T) {
	m := Methodology{
		DeniedKinds: []string{"poddisruptionbudgets", "pods", "cr:certificates.cert-manager.io", "networkpolicies"},
		DataSources: []string{
			"Kubernetes API (server v1.31.0)",
			// Written by the only writer of this sentence, so the test cannot pass against a format
			// nothing produces. internal/collect classifies the API error into these causes; the note is
			// built and read here.
			UnreadNote([]UnreadKind{
				{Kind: "poddisruptionbudgets", Cause: "not permitted"},
				{Kind: "pods", Cause: "not reachable"},
				{Kind: "cr:certificates.cert-manager.io", Cause: "not served by this cluster"},
			}),
			// The unpriced-StorageClass note lives in the same slice and carries a customer name. A parser
			// that reads all of DataSources would take "acmebank-fast-ssd (…)" for a kind and a cause.
			"1 unpriced storage class(es) excluded from storage spend: acmebank-fast-ssd",
		},
	}
	got := map[string]string{}
	for _, kc := range m.UnreadKinds() {
		got[kc.Kind] = kc.Cause
	}
	for kind, want := range map[string]string{
		"poddisruptionbudgets":            "not permitted",
		"pods":                            "not reachable",
		"cr:certificates.cert-manager.io": "not served by this cluster",
		// IN THE NOTE'S ABSENCE, THE HONEST ANSWER — never a guess, and never the commonest cause. A reading
		// written before the note existed has no record of why, and saying "not permitted" there is the same
		// invention this whole change removes.
		"networkpolicies": "cause not recorded",
	} {
		if got[kind] != want {
			t.Errorf("%s: cause %q, want %q", kind, got[kind], want)
		}
	}
	if n := len(m.UnreadKinds()); n != 4 {
		t.Errorf("UnreadKinds returned %d entries for 4 unread kinds", n)
	}
	if len((Methodology{}).UnreadKinds()) != 0 {
		t.Error("a reading with nothing unread must yield no entries, not one empty one")
	}
}

// A REPHRASED SENTENCE MUST NOT EMPTY THE CAUSES.
//
// This is the falsifier the prose-as-schema design had no answer to. Until 2026-09-10 the causes lived
// only inside the DataSources note and were recovered with two regexes, so changing a comma, a word or a
// translation in that sentence would have dropped every cause on every saved reading to "cause not
// recorded" — a value every gate accepts. Silent, total, and invisible to the tests, because the tests
// built the note with the same writer they parsed it with.
//
// The field is authoritative now. This test proves it by writing a note the parser CANNOT read.
func TestUnreadKinds_TheFieldOutlivesTheSentence(t *testing.T) {
	m := Methodology{
		DeniedKinds: []string{"pods", "networkpolicies"},
		Unread: []UnreadKind{
			{Kind: "pods", Cause: "not reachable"},
			{Kind: "networkpolicies", Cause: "not permitted"},
		},
		DataSources: []string{
			// Deliberately NOT what UnreadNote writes: a plausible rewording of the same sentence, of the
			// kind any copy pass produces. The old parser matched "resource kind(s) could not be read: …"
			// and "kind (cause)" pairs; neither shape is here.
			"Partial collection. 2 resource kinds were refused or unreachable — pods, networkpolicies. " +
				"Nothing is claimed about them.",
		},
	}
	got := map[string]string{}
	for _, u := range m.UnreadKinds() {
		got[u.Kind] = u.Cause
	}
	if got["pods"] != "not reachable" || got["networkpolicies"] != "not permitted" {
		t.Errorf("a reworded note emptied the causes: %v — the field must be read before the prose", got)
	}

	// AND THE OLD READINGS STILL WORK. A reading saved before the field existed has the note and nothing
	// else, and must still yield its causes: the parser is a fallback, not a deletion.
	old := Methodology{
		DeniedKinds: []string{"pods"},
		DataSources: []string{UnreadNote([]UnreadKind{{Kind: "pods", Cause: "timed out"}})},
	}
	if u := old.UnreadKinds(); len(u) != 1 || u[0].Cause != "timed out" {
		t.Errorf("a reading with only the note lost its cause: %+v", u)
	}

	// AND A CAUSE THE FIELD CARRIES THAT THIS BUILD DOES NOT DEFINE IS NOT TRUSTED. A file is an input:
	// a value outside the closed set came from somewhere this project has not audited.
	bogus := Methodology{
		DeniedKinds: []string{"pods"},
		Unread:      []UnreadKind{{Kind: "pods", Cause: "because the moon"}},
	}
	if u := bogus.UnreadKinds(); len(u) != 1 || u[0].Cause != CauseNotRecorded {
		t.Errorf("an unrecognised cause was passed through from the file: %+v", u)
	}
}
