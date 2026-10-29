package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// EVERY LINK THE SITE OFFERS GOES SOMEWHERE, AND ITS LABEL IS WHAT IS THERE.
//
// Two links on site/read-only.html — the topbar and the footer — were labelled "Pricing" and pointed at
// /#pricing. No page defines that anchor. The site's own copy says: "no pricing — the last because it is a
// decision that has not been taken, and quoting a number before it is taken is how a placeholder becomes a
// promise." A nav label IS a promise, and that one promised a number the product deliberately refuses to
// invent, then delivered a scroll to nowhere.
//
// The gate is link integrity, which catches the whole class rather than that one label: every same-site
// fragment a page links to resolves to an id defined on the page it points at.
func TestSite_EveryInternalAnchorResolves(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "site")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read site/: %v", err)
	}
	// The rendered readings are the product's own output, not pages written here: their anchors are the
	// renderer's business and internal/report gates them. A link INTO one may carry the instrument's view
	// state ("#v=…", read by viewApply), which is not an id and is not this test's to resolve.
	skip := map[string]bool{"sample-report.html": true, "sample-compare.html": true, "sample-fleet.html": true}

	page := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".html" || skip[e.Name()] {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		page[e.Name()] = string(b)
	}
	if len(page) < 2 {
		t.Fatalf("found %d authored page(s) in site/; this assertion needs the pages it is about", len(page))
	}

	idRe := regexp.MustCompile(`\sid="([^"]+)"`)
	ids := map[string]map[string]bool{}
	for name, body := range page {
		ids[name] = map[string]bool{}
		for _, m := range idRe.FindAllStringSubmatch(body, -1) {
			ids[name][m[1]] = true
		}
	}

	hrefRe := regexp.MustCompile(`href="([^"]*#[^"]+)"`)
	// The text of the <a> that carries the href, so a failure can quote the label a reader saw.
	labelOf := func(body, href string) string {
		i := strings.Index(body, `href="`+href+`"`)
		if i < 0 {
			return ""
		}
		rest := body[i:]
		j := strings.Index(rest, "</a>")
		if j < 0 {
			return ""
		}
		txt := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(rest[:j], " ")
		return strings.Join(strings.Fields(txt), " ")
	}

	var problems []string
	for name, body := range page {
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			href := m[1]
			target, frag := name, strings.TrimPrefix(href, "#")
			if !strings.HasPrefix(href, "#") {
				path, f, _ := strings.Cut(href, "#")
				frag = f
				switch {
				case path == "/" || path == "":
					target = "index.html"
				case strings.HasPrefix(path, "http"):
					continue // another site's anchors are not ours to check
				default:
					target = strings.TrimPrefix(path, "/")
					if !strings.HasSuffix(target, ".html") {
						target += ".html"
					}
				}
			}
			if skip[target] {
				continue
			}
			if _, known := page[target]; !known {
				problems = append(problems, name+": "+href+" points at a page site/ does not have")
				continue
			}
			if !ids[target][frag] {
				problems = append(problems, name+`: "`+labelOf(body, href)+`" links to `+href+
					" and "+target+" defines no such id — a nav label is a promise, and a dead one delivers a scroll to nowhere")
			}
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// repoRoot walks up to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
