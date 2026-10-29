package redact

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// harvest_coverage_test.go — A HARVEST NOTHING EXERCISES IS A HARVEST NOTHING GUARDS.
//
// M-59 refused reflection-driven harvesting and the refusal stands: the 27 add() call sites do not only
// decide WHETHER to harvest a value, each chooses the token's KIND, and reflection cannot tell a count from
// a name — M-37 was a WRONG harvest, not a forgotten one. Re-measured 2026-09-11 and both halves still
// hold: removing add("region", …) fails TestReport_NoCustomerIdentifierSurvivesAnywhere, and adding a new
// identifier-bearing string field to types.ClusterInfo fails
// TestRedact_EveryStringFieldOnTheSchemaIsClassified.
//
// WHAT NEITHER OF THEM MEASURES IS THE COVERAGE OF THE HARVEST ITSELF.
//
// The structural gate is blind to a missing harvest by construction: it plants ONE value everywhere, so a
// field whose add() is gone is still replaced as long as any other field registered the same string. Its own
// comment explains why one value is right — a per-path value is in no registry and would survive a field
// that IS correctly rebuilt — so that blindness is deliberate and not a defect.
//
// Which leaves the whole weight of the harvest on the HAND-BUILT sentinel fixture, and only for the kinds it
// happens to carry a distinct string for. Nothing said which kinds those were. A new add("pvc", …) whose
// value never appears in buildSentinelReport is registered, is never exercised, and deleting it again would
// fail nothing — the "fixture that cannot produce the state" shape, applied to a security boundary.
//
// So this measures it: every kind the harvest can mint must actually appear as a token in the redacted
// sentinel document, and the denominator is printed.

// harvestKinds reads the kinds out of redact.go rather than restating them, so a new add() widens the
// requirement in the same commit that adds it. A list restated here would be one more thing to remember.
func harvestKinds(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("redact.go")
	if err != nil {
		t.Fatalf("read redact.go: %v", err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`\badd\("([a-z]+)"`).FindAllStringSubmatch(string(src), -1) {
		seen[m[1]] = true
	}
	// The cluster's own name is minted without going through add() — it is registered directly, because it
	// is the one identifier that must never be skipped by add()'s "default"/"cluster" guard.
	seen["cluster"] = true
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) < 8 {
		t.Fatalf("only %d harvest kind(s) parsed from redact.go: %v — the scan is not reading the file and "+
			"every assertion below would pass over an almost empty set", len(out), out)
	}
	return out
}

func TestRedact_EveryHarvestKindIsExercisedByTheSentinel(t *testing.T) {
	kinds := harvestKinds(t)

	out := Report(buildSentinelReport())
	if out == nil {
		t.Fatal("Report returned nil")
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(blob)

	// A token is "<kind>-<6 hex>". Counting them per kind says which harvests this fixture actually reached.
	found := map[string]int{}
	for _, m := range regexp.MustCompile(`\b([a-z]+)-[0-9a-f]{6}\b`).FindAllStringSubmatch(text, -1) {
		found[m[1]]++
	}

	var missing []string
	for _, k := range kinds {
		if found[k] == 0 {
			missing = append(missing, k)
		}
	}
	for _, k := range missing {
		t.Errorf("the harvest can mint %q tokens and the sentinel document contains none.\n"+
			"  Nothing exercises that add(), so deleting it would fail no test — and --redact is the mode an\n"+
			"  operator uses to share a reading OUTSIDE their organisation. Give buildSentinelReport a value\n"+
			"  for that field, distinct from every other, or remove the harvest.", k)
	}

	var covered []string
	for _, k := range kinds {
		if found[k] > 0 {
			covered = append(covered, k+"×"+itoa(found[k]))
		}
	}
	t.Logf("%d harvest kind(s) in redact.go, %d exercised by the sentinel: %s",
		len(kinds), len(kinds)-len(missing), strings.Join(covered, " "))
}

// AND EACH HARVEST MUST BE INDEPENDENTLY FALSIFIABLE.
//
// A harvested value that only ever appears INSIDE a longer harvested value is unguarded: the replacer works
// longest-first, so the longer one is substituted at every occurrence and removing the shorter harvest
// changes nothing a test can see. The sentinel fixture's region constant already carries this reasoning in a
// comment — "NOT a substring of the node name above ... asserting that string would have been satisfied by
// the node-name replacement and proved nothing about the region field" — and a comment is not a check.
//
// THE FIRST VERSION OF THIS TEST WAS WRONG AND IT IS WORTH RECORDING WHY. It reported any harvested value
// that is a substring of another of a different kind, and fired on `region sa-east-1 inside zone sa-east-1a`
// — which is not a defect: the region ALSO appears on its own in Cluster.Region, so deleting its harvest
// does fail, measured. Nesting is not the property. Occurring ONLY while nested is.
func TestRedact_EveryHarvestIsIndependentlyFalsifiable(t *testing.T) {
	ar := buildSentinelReport()
	ids := gatherIdentifiers(ar)
	if len(ids) < 10 {
		t.Fatalf("the sentinel fixture yields %d harvested identifier(s); this assertion needs the fixture "+
			"to be cluster-shaped to mean anything", len(ids))
	}
	raw, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal the unredacted fixture: %v", err)
	}
	doc := string(raw)

	longer := func(v string) []string {
		var out []string
		for other := range ids {
			if other != v && len(other) > len(v) && strings.Contains(other, v) {
				out = append(out, other)
			}
		}
		return out
	}

	var unguarded []string
	for v := range ids {
		wrappers := longer(v)
		if len(wrappers) == 0 {
			continue
		}
		// Does v occur anywhere in the fixture NOT inside one of its wrappers?
		alone := false
		for at := 0; ; {
			i := strings.Index(doc[at:], v)
			if i < 0 {
				break
			}
			pos := at + i
			nested := false
			for _, w := range wrappers {
				off := strings.Index(w, v)
				lo := pos - off
				if lo >= 0 && lo+len(w) <= len(doc) && doc[lo:lo+len(w)] == w {
					nested = true
					break
				}
			}
			if !nested {
				alone = true
				break
			}
			at = pos + 1
		}
		if !alone {
			unguarded = append(unguarded, v+" (only ever inside "+strings.Join(wrappers, ", ")+")")
		}
	}
	sort.Strings(unguarded)
	for _, u := range unguarded {
		t.Errorf("the sentinel fixture harvests %s.\n"+
			"  The replacer works longest-first, so the longer value is substituted at every occurrence and\n"+
			"  deleting this harvest would change nothing any test can see. Give the fixture one place where\n"+
			"  this value stands on its own, the way Cluster.Region does for the region.", u)
	}
	t.Logf("%d harvested value(s); every one occurs somewhere no longer harvested value covers", len(ids))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
