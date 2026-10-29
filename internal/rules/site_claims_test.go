package rules

import (
	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"

	"os"
	"regexp"
	"strconv"
	"testing"
)

// THE FIGURES ON THE LANDING PAGE ARE READ OFF THIS TREE, OR THEY GO STALE IN PUBLIC.
//
// site/index.html said "85 rules" while the registry held 87 — measured 2026-09-10, two rules after the
// number was written. Nothing checked it: `site-copy` enforces the vocabulary and `no-placeholders` enforces
// that nothing says REPLACE-ME, and neither of them can know what the registry counts.
//
// It is the same shape as a stale golden fixture, on the one page a stranger reads first, and the fix is the
// same: derive the number rather than remember it. This test does not render the page — it reads the figure
// out of the markup and compares it to len(All()), so a rule added without touching the site fails here with
// both numbers named.
//
// WHY NOT JUST GENERATE THE PAGE. The landing is hand-written prose and should stay that way; what it must
// not do is state a number this repository can contradict. A test is the smaller instrument.
func TestSiteFiguresMatchTheTree(t *testing.T) {
	b, err := os.ReadFile("../../site/index.html")
	if err != nil {
		t.Skipf("no landing page in this tree: %v", err)
	}
	src := string(b)

	// <b>102</b><span>rules in every reading, …
	//
	// THE NUMBER A READING SHOWS. The page said 87 — the rule registry — while every reading says "102 rules run",
	// because a reading's rule set is the rules AND the stack analyzers (pipeline.RuleSetStamp). A visitor who
	// opened the sample from the page read two different counts for one thing.
	m := regexp.MustCompile(`<b>(\d+)</b><span>rules in every reading,`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("the landing page states no rule count, or the figure's markup changed — this test is now " +
			"blind and would pass on any number at all")
	}
	stated, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("rule figure %q is not a number", m[1])
	}
	if got := len(All()) + len(analyzers.All()); stated != got {
		t.Errorf("the landing page says %d rules and a reading runs %d: the page a stranger reads first "+
			"is making a claim this tree contradicts", stated, got)
	}
}

// THE RESOURCE COUNT, ON BOTH PAGES THAT STATE IT.
//
// "47 resource types read, with get and list" is on the landing and twice more on the read-only page, and it
// is the number `shoalcheck audit --show-permissions` prints from collect.CollectedResources(). A kind added to
// the collector moves it, and three pieces of hand-written prose would keep the old one.
func TestSiteResourceCountMatchesTheCollector(t *testing.T) {
	want := len(collect.CollectedResources())
	if want == 0 {
		t.Fatal("the collector declares no resources, so this test would pin nothing")
	}
	// A FLOOR PER PAGE, because "every occurrence I found was right" passes when an occurrence goes missing.
	// Measured 2026-09-10 with the tags stripped: one occurrence per page carries the number adjacent to
	// the phrase. A grep counted two, because it counts LINES and both pages mention the phrase twice —
	// which is why the floor is measured through the same expression the check uses rather than by eye.
	pages := map[string]int{"../../site/index.html": 1, "../../site/read-only.html": 1}
	for page, floor := range pages {
		b, err := os.ReadFile(page)
		if err != nil {
			t.Skipf("no %s in this tree: %v", page, err)
		}
		// TAGS OFF FIRST. The figure's markup is `<b>47</b><span>resource types read…`, so a pattern that
		// wants the number adjacent to the phrase sees only the meta description's copy of the claim — and
		// the floor below would then be measuring one occurrence while the page makes two.
		text := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(string(b), "")
		found := regexp.MustCompile(`(\d+)\s*resource types`).FindAllStringSubmatch(text, -1)
		if len(found) < floor {
			t.Errorf("%s states the resource-type count %d time(s) and stated it %d when this floor was "+
				"measured: a phrasing change removes an occurrence from this scan without removing the "+
				"claim from the page", page, len(found), floor)
			continue
		}
		for _, m := range found {
			stated, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			if stated != want {
				t.Errorf("%s says %d resource types and the collector reads %d", page, stated, want)
			}
		}
	}
}

// THE READ-ONLY PAGE NAMES EVERY WAY THE BINARY REACHES PAST YOUR CLUSTER, AND SAYS WHICH ONE IS LIVE.
//
// It said "One outbound address is compiled into the binary, for signed reference-data bundles", and the tree
// contradicted it twice: the reference-data source has been empty by default since assay.sh turned out to be
// somebody else's domain, and the updater became the one destination a default build does carry. A page whose
// whole job is to be checkable stated the one thing about egress the code had stopped doing. Each fetcher
// must be named by its source file, and the reference-data one must be described as having no address while
// the build leaves bundleSource empty.
func TestReadOnlyPage_NamesEveryOutboundFetcher(t *testing.T) {
	b, err := os.ReadFile("../../site/read-only.html")
	if err != nil {
		t.Skipf("no read-only page in this tree: %v", err)
	}
	page := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(string(b), "")
	page = regexp.MustCompile(`\s+`).ReplaceAllString(page, " ")

	upd, err := os.ReadFile("../../internal/selfupdate/fetch.go")
	if err != nil {
		t.Fatalf("the updater's fetcher is gone; this test is stale: %v", err)
	}
	if !regexp.MustCompile(`"https://`).Match(upd) {
		t.Error("internal/selfupdate/fetch.go carries no https destination; it is not an outbound fetcher any more")
	}
	ref, err := os.ReadFile("../../internal/refdata/fetch.go")
	if err != nil {
		t.Fatalf("the reference-data fetcher is gone; this test is stale: %v", err)
	}
	for _, f := range []string{"internal/selfupdate/fetch.go", "internal/refdata/fetch.go"} {
		if !regexp.MustCompile(regexp.QuoteMeta(f)).MatchString(page) {
			t.Errorf("site/read-only.html never names %s — the page tells a reader what can leave the machine", f)
		}
	}
	if regexp.MustCompile(`(?m)^var bundleSource = ""$`).Match(ref) &&
		!regexp.MustCompile(`(?i)reference-data[^.]*\bno address\b`).MatchString(page) {
		t.Error("bundleSource is empty in this tree, so a build fetches no reference data, and the page never says " +
			"the reference-data fetcher has no address")
	}
	// AND THE SECURITY POLICY, which made the same claim in the same words to the people most likely to test it.
	sec, err := os.ReadFile("../../SECURITY.md")
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	stale := regexp.MustCompile(`(?i)\bone outbound address is compiled\b`)
	for name, text := range map[string]string{"site/read-only.html": page, "SECURITY.md": regexp.MustCompile(`\s+`).ReplaceAllString(string(sec), " ")} {
		if stale.MatchString(text) {
			t.Errorf("%s still says one outbound address is compiled in, for reference data", name)
		}
	}
}
