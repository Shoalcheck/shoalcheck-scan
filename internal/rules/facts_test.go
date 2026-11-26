package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// EVERY KEY IS REGISTERED, TYPED, CLASSIFIED AND WRITTEN (M-172). A key with no redaction class could carry a name
// into a shared document; a key with no meaning is a number nobody can read; a key nothing writes is a promise.
func TestFacts_EveryKeyIsRegisteredTypedAndClassified(t *testing.T) {
	var src strings.Builder
	files, _ := filepath.Glob("*.go")
	// The analyzers write facts too (ENG-20c): a key only they write is still a key written.
	more, _ := filepath.Glob(filepath.Join("..", "analyzers", "*.go"))
	files = append(files, more...)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	written := map[string]bool{}
	for _, m := range regexp.MustCompile(`NewFact\("([a-z0-9.-]+)"`).FindAllStringSubmatch(src.String(), -1) {
		written[m[1]] = true
	}
	// A key built from a prefix and a closed set ("scaledown.blocker."+reason) is written for every registered key
	// under the prefix.
	for _, m := range regexp.MustCompile(`NewFact\("([a-z0-9.-]+\.)"\s*\+`).FindAllStringSubmatch(src.String(), -1) {
		for _, k := range types.SortedFactKeys() {
			if strings.HasPrefix(k, m[1]) {
				written[k] = true
			}
		}
	}
	for _, k := range types.SortedFactKeys() {
		d := types.FactKeys[k]
		if d.Type != types.FactNumber && d.Type != types.FactString && d.Type != types.FactBool {
			t.Errorf("%s: type %q", k, d.Type)
		}
		if d.Class != types.FactSafe && d.Class != types.FactIdentifier && d.Class != types.FactText {
			t.Errorf("%s: no redaction class", k)
		}
		if strings.TrimSpace(d.Means) == "" {
			t.Errorf("%s: no meaning", k)
		}
		if !d.Deprecated && !written[k] {
			t.Errorf("%s is registered and no rule writes it", k)
		}
	}
	for k := range written {
		if strings.HasSuffix(k, ".") {
			continue // a prefix, checked above against the keys it covers
		}
		if _, ok := types.FactKeys[k]; !ok {
			t.Errorf("a rule writes %s, which is not registered", k)
		}
	}
	if len(written) < 20 {
		t.Fatalf("only %d keys written; the source scan is not reading the rules", len(written))
	}
}

// THE PILOTS' SENTENCES ARE THEIR FACTS (M-172). Over the sample reading, every pilot finding's figures are read
// back from its facts and found in the sentence that states them — the aggregate line of zone loss re-rendered
// whole, the rightsizing price line's counts and dollar, the LoadBalancer's base price, the grant's binding count.
func TestFacts_PilotEvidenceIsRenderedFromFacts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "sample-audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(raw, &ar); err != nil {
		t.Fatal(err)
	}
	checked := map[string]int{}
	for _, f := range ar.Findings {
		ev := strings.Join(f.Evidence, "\n")
		switch f.RuleID {
		case "k8s.reliability.zone-loss-feasibility":
			if types.FactNum(f.Facts, "zone.pods.moving") > 0 {
				checked[f.RuleID]++
				if !strings.Contains(ev, zoneAggregateLine(f.Facts)) {
					t.Errorf("%s: the aggregate line is not its facts' rendering:\n%s", f.ID, zoneAggregateLine(f.Facts))
				}
			}
		case "k8s.cost.overprovisioned-resources":
			checked[f.RuleID]++
			want := fmt.Sprintf("priced %d of %d replicas", int(types.FactNum(f.Facts, "rightsizing.replicas.priced")), int(types.FactNum(f.Facts, "rightsizing.replicas")))
			bound := types.FactNum(f.Facts, "rightsizing.usd.cpu")
			if types.FactStr(f.Facts, "rightsizing.bound") == "memory" {
				bound = types.FactNum(f.Facts, "rightsizing.usd.memory")
			}
			if !strings.Contains(ev, want) || !strings.Contains(ev, fmt.Sprintf("-bound up to $%.2f/mo", bound)) {
				t.Errorf("%s: the price line does not carry its facts (%s, $%.2f):\n%s", f.ID, want, bound, ev)
			}
		case "k8s.cost.idle-loadbalancer":
			if v, ok := types.FactValue(f.Facts, "lb.usd"); ok {
				checked[f.RuleID]++
				if !strings.Contains(ev, fmt.Sprintf("about $%.2f/mo", v.(float64))) {
					t.Errorf("%s: the price line does not carry lb.usd", f.ID)
				}
			}
		case "k8s.rbac.dangerous-grant":
			checked[f.RuleID]++
			if n := int(types.FactNum(f.Facts, "rbac.bindings")); !strings.Contains(f.Description, nWord(n, "binding", "bindings")+" name subjects") ||
				!strings.HasSuffix(f.Description, "The grant reaches "+types.FactStr(f.Facts, "rbac.reach")+".") {
				t.Errorf("%s: the description does not carry its facts: %s", f.ID, f.Description)
			}
		}
	}
	for _, r := range []string{"k8s.cost.overprovisioned-resources", "k8s.cost.idle-loadbalancer", "k8s.rbac.dangerous-grant"} {
		if checked[r] == 0 {
			t.Errorf("no %s finding with facts in the sample: the check measured nothing for it", r)
		}
	}
	t.Logf("checked against their facts: %v", checked)
}
