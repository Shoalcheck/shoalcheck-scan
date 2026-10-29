package pipeline

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE TWO HALVES OF AN OPEN-CORE REPOSITORY HAVE TO SAY THE SAME THING ABOUT THE SAME CODE.
//
// Measured 7 September and recorded in the completion register: no LICENSE, no COPYING, no NOTICE, and not
// one copyright header anywhere — while `scripts/oss-tree.sh` generated an Apache-2.0 LICENSE into the
// published OSS tree. So the open half shipped under a licence the parent repository never declared, and
// the licence it shipped was a **placeholder whose own text said it was a placeholder**, because the
// `LICENSE-APACHE` it looked for did not exist and the script warned and carried on.
//
// This test holds three things that a reader of either half depends on:
//
//  1. both licence texts exist, and the Apache one is the real one — not a note about getting it later;
//  2. the parent LICENSE's package list agrees with `OSS_INTERNAL` in the generator, which is what the
//     build actually enforces. A prose list beside an authoritative array drifts silently, and the
//     direction of the drift decides whether somebody is told a proprietary package is Apache-2.0;
//  3. the parent LICENSE does not claim to be open source, because `oss-tree.sh` used to fall back to
//     copying it onto the OSS module.
//
// It lives in internal/pipeline because that package is in the OSS half: if the licence files are wrong,
// the failure surfaces in the half whose licence is being asserted.
func TestOSSTree_TheLicenceFilesSayTheSameThing(t *testing.T) {
	apache, err := os.ReadFile("../../LICENSE-APACHE")
	if err != nil {
		t.Fatalf("no LICENSE-APACHE: %v — the OSS module is Apache-2.0 and scripts/oss-tree.sh copies "+
			"this file as its LICENSE, so without it the published module carries no real licence", err)
	}
	// The real text, not a placeholder or a link to one. These three lines only appear in the licence itself.
	for _, want := range []string{
		"Apache License",
		"Version 2.0, January 2004",
		"http://www.apache.org/licenses/",
		"TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
		"APPENDIX: How to apply the Apache License to your work",
	} {
		if !strings.Contains(string(apache), want) {
			t.Errorf("LICENSE-APACHE does not contain %q, so it is not the Apache-2.0 text", want)
		}
	}
	if strings.Contains(strings.ToLower(string(apache)), "placeholder") {
		t.Error("LICENSE-APACHE calls itself a placeholder: a generated module carrying that text makes a " +
			"legal statement nobody made, and it survives into every mirror of the module")
	}

	parent, err := os.ReadFile("../../LICENSE")
	if err != nil {
		t.Fatalf("no LICENSE in the repository root: %v — the closed half then declares nothing at all "+
			"while the open half ships a licence", err)
	}
	if _, err := os.ReadFile("../../NOTICE"); err != nil {
		t.Errorf("no NOTICE: %v — Apache-2.0 §4(d) carries it with every redistribution of the OSS module, "+
			"and scripts/oss-tree.sh copies it beside the LICENSE", err)
	}

	// The closed half has its own file, and its scope is the COMPLEMENT of the open list rather than a
	// second enumeration. It used to say it "governs only the report renderer", which stopped being true
	// the moment anything was built beside internal/report — and by 8 September that was the triage store,
	// the tracker, the scheduler, the exporters and four binaries.
	prop, err := os.ReadFile("../../LICENSE-PROPRIETARY")
	if err != nil {
		t.Fatalf("no LICENSE-PROPRIETARY: %v — the root LICENSE and the README both point at it", err)
	}
	// PROSE WRAPS, so these phrases are matched against a whitespace-collapsed copy. The first version
	// compared against the raw bytes and the phrase it wanted spanned a line break, so a file that said
	// exactly the right thing failed the check.
	flat := regexp.MustCompile(`\s+`).ReplaceAllString(string(prop), " ")
	if strings.Contains(flat, "governs only the report renderer") {
		t.Error("LICENSE-PROPRIETARY still claims to cover only internal/report, so every proprietary " +
			"package built since is covered by nothing")
	}
	if !strings.Contains(flat, "NOT in the Apache-2.0 subset") {
		t.Error("LICENSE-PROPRIETARY does not define its scope as the complement of the open list, so a " +
			"package added tomorrow is covered only if somebody remembers to add a line for it")
	}

	// ONE LIST, ONE PLACE. Four files stated the split and all four named seven packages while the build
	// published twenty — stale in the same direction, which is what a duplicated list does. The root
	// LICENSE holds the list; nothing else may enumerate the open half, because a second copy is a second
	// thing to forget.
	for _, other := range []struct{ path, name string }{
		{"../../NOTICE", "NOTICE"},
		{"../../LICENSE-PROPRIETARY", "LICENSE-PROPRIETARY"},
	} {
		b, err := os.ReadFile(other.path)
		if err != nil {
			continue
		}
		var found []string
		for _, pkg := range []string{"internal/collect", "internal/rules", "internal/types",
			"internal/prom", "internal/analyzers", "internal/verdict", "internal/headline"} {
			if strings.Contains(string(b), pkg) {
				found = append(found, pkg)
			}
		}
		if len(found) > 1 {
			t.Errorf("%s enumerates the open half (%v): the list lives in LICENSE alone, and a second "+
				"copy is what let four files disagree about the same code", other.name, found)
		}
	}

	// THE LIST HAS ONE OWNER. `OSS_INTERNAL` is what the generator uses and what the standalone build
	// proves; the LICENSE's list is prose beside it. This test is the only thing keeping them equal.
	script, err := os.ReadFile("../../scripts/oss-tree.sh")
	if err != nil {
		t.Fatalf("read oss-tree.sh: %v", err)
	}
	m := regexp.MustCompile(`(?m)^OSS_INTERNAL=\(([^)]*)\)`).FindSubmatch(script)
	if m == nil {
		t.Fatal("OSS_INTERNAL not found in scripts/oss-tree.sh, so there is nothing to compare the " +
			"LICENSE's package list against")
	}
	pkgs := strings.Fields(string(m[1]))
	if len(pkgs) < 10 {
		t.Fatalf("OSS_INTERNAL has %d entries, which is too few for this comparison to mean anything",
			len(pkgs))
	}
	for _, pkg := range pkgs {
		if !strings.Contains(string(parent), "internal/"+pkg) {
			t.Errorf("internal/%s is in OSS_INTERNAL but not in the LICENSE's Apache-2.0 list: the build "+
				"publishes it under Apache-2.0 while the licence file leaves it under proprietary terms",
				pkg)
		}
	}
	// And the other direction: a package named as Apache-2.0 that the generator does not publish is a
	// promise the build does not keep.
	listed := regexp.MustCompile(`internal/([a-z]+)`).FindAllStringSubmatch(string(parent), -1)
	inOSS := map[string]bool{}
	for _, p := range pkgs {
		inOSS[p] = true
	}
	// THE SLICE'S BOTH ENDS ARE ASSERTED. The first version of this ended the Apache section at a phrase
	// the file no longer contained, so the slice ran past it into the sentence naming the PROPRIETARY
	// packages and reported internal/billing as wrongly licensed. A boundary that silently fails to match
	// makes the region under test the whole document — the same defect as a markup strip whose closing
	// token never arrives.
	const openMark, closeMark = "THE APACHE-2.0 SUBSET", "Everything not on that list is proprietary"
	i, j := strings.Index(string(parent), openMark), strings.Index(string(parent), closeMark)
	if i < 0 || j < 0 || j <= i {
		t.Fatalf("the LICENSE's Apache section is not delimited by %q … %q (found at %d and %d), so this "+
			"check would read the whole file as the open list", openMark, closeMark, i, j)
	}
	apacheSection := string(parent)[i:j]
	for _, l := range listed {
		if strings.Contains(apacheSection, "internal/"+l[1]) && !inOSS[l[1]] {
			t.Errorf("the LICENSE lists internal/%s as Apache-2.0 and OSS_INTERNAL does not publish it, "+
				"so the licence grants rights over code the open module never contains", l[1])
		}
	}
}

// THE KREW MANIFEST AND THE RELEASE DESCRIBE THE SAME PLATFORMS.
//
// `deploy/krew/shoalcheck.yaml` declares one platform block per os/arch with its own digest placeholder, and
// `.goreleaser.yaml` decides which os/arch pairs are actually built. Nothing connected them: the manifest's
// header claimed "the URIs and digests below are filled by the release job" and **no release job ever
// substituted one** — it carried krew-release-bot's template variables and that bot was never wired up, so
// the file was a draft that could not be rendered, describing a step that did not exist.
// `scripts/krew-manifest.sh` renders it now, and this holds the two files' platform lists equal.
//
// The failure this prevents is specific and lands on a stranger: krew resolves a plugin by matching the
// user's os/arch against these selectors. A platform in the manifest that the release does not build gives
// that user a 404 at install time, and a platform the release builds that the manifest omits makes the
// plugin silently unavailable to them — "no matching platform", on a tool that shipped for their machine.
func TestKrew_ManifestAndReleaseAgreeOnPlatforms(t *testing.T) {
	man, err := os.ReadFile("../../deploy/krew/shoalcheck.yaml")
	if err != nil {
		t.Skipf("no krew manifest (%v)", err)
	}
	rel, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatalf("read .goreleaser.yaml: %v", err)
	}

	// The manifest's platforms, from its selector labels — os and arch are adjacent in each block.
	manifest := map[string]bool{}
	blocks := regexp.MustCompile(`(?s)os:\s*(\w+)\s+arch:\s*(\w+)`).FindAllStringSubmatch(string(man), -1)
	for _, b := range blocks {
		manifest[b[1]+"/"+b[2]] = true
	}
	if len(manifest) == 0 {
		t.Fatal("no os/arch selectors parsed from the krew manifest, so this comparison is about nothing")
	}

	// The release's goos × goarch. One list each, so the product is what gets built.
	list := func(key string) []string {
		m := regexp.MustCompile(`(?s)\n\s*` + key + `:\s*\n((?:\s*-\s*\w+\s*\n)+)`).FindStringSubmatch(string(rel))
		if m == nil {
			return nil
		}
		var out []string
		for _, l := range regexp.MustCompile(`-\s*(\w+)`).FindAllStringSubmatch(m[1], -1) {
			out = append(out, l[1])
		}
		return out
	}
	oses, arches := list("goos"), list("goarch")
	if len(oses) == 0 || len(arches) == 0 {
		t.Fatalf("could not read goos/goarch from .goreleaser.yaml (got %v × %v)", oses, arches)
	}
	built := map[string]bool{}
	for _, o := range oses {
		for _, a := range arches {
			built[o+"/"+a] = true
		}
	}

	for p := range manifest {
		if !built[p] {
			t.Errorf("the krew manifest offers %s and the release does not build it: krew would resolve "+
				"that selector and hand the user a 404 at install time", p)
		}
	}
	for p := range built {
		if !manifest[p] {
			t.Errorf("the release builds %s and the krew manifest has no block for it: the plugin is "+
				"silently unavailable on a machine the binary was built for", p)
		}
	}

	// And every platform block carries a digest placeholder the renderer knows how to fill.
	for p := range manifest {
		os_, arch := p[:strings.Index(p, "/")], p[strings.Index(p, "/")+1:]
		if !strings.Contains(string(man), "Sha256_"+os_+"_"+arch) {
			t.Errorf("the %s block has no Sha256_%s_%s placeholder, so scripts/krew-manifest.sh leaves it "+
				"unrendered and krew's own validation rejects the submission", p, os_, arch)
		}
	}
}

// THE CI EXAMPLES WE HAND PEOPLE HAVE TO WORK, AND HAVE TO VERIFY WHAT THEY DOWNLOAD.
//
// `docs/ci/github-actions.yml` and `docs/ci/gitlab-ci.yml` are copy-paste artifacts: the register calls the
// CI verb "the dashboard the team already reads", and the first thing a stranger does with these files is
// paste them into a pipeline that touches a production cluster. Two defects lived in both:
//
//  1. `releases/latest/download/shoalcheck_${VERSION}_linux_amd64.tar.gz` — "whatever is latest" combined with a
//     version-stamped filename. That URL resolves only while latest happens to BE that version, and
//     `/releases/latest` skips prereleases entirely, so with only a prerelease published it 404s outright.
//     Verified against the live API on 2026-09-09: the source repository's `releases/latest` → 404.
//  2. The tarball was piped straight into `/usr/local/bin` with nothing verified — while every release
//     publishes a `checksums.txt` and a keyless cosign signature over it. An example that ignores both
//     teaches the opposite of what this product argues for on every other surface.
//
// A gate rather than a fix, because both are the kind of line somebody restores while "simplifying" an
// example, and neither fails anything here — it fails in a stranger's pipeline.
func TestCIExamples_PinTheTagAndVerifyTheDownload(t *testing.T) {
	files, err := filepath.Glob("../../docs/ci/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no CI examples found under docs/ci (%v), so this check is about nothing", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("read %s: %v", f, err)
			continue
		}
		name := filepath.Base(f)
		// Comments explaining the old defect are allowed; a live line is not. A live line is one that is
		// not preceded on its own line by a `#`.
		for i, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(line, "releases/latest/download") {
				t.Errorf("%s:%d fetches from releases/latest/download — `latest` skips prereleases and "+
					"cannot be combined with a version-stamped filename", name, i+1)
			}
		}
		// And the download is verified. sha256sum -c is the floor; cosign is offered as the stronger form.
		if !strings.Contains(string(b), "checksums.txt") {
			t.Errorf("%s downloads a release archive and never fetches checksums.txt", name)
		}
		if !strings.Contains(string(b), "sha256sum -c") {
			t.Errorf("%s never verifies the archive it puts on PATH: a binary that is not the one that "+
				"was signed has no business reading a production cluster", name)
		}
		// The pinned form, so the example is a pipeline somebody can trust not to change under them.
		if !strings.Contains(string(b), "releases/download/v$") {
			t.Errorf("%s does not fetch from a pinned tag (releases/download/v<version>/…)", name)
		}
	}
}

// NO WAIT IN THE BROWSER HARNESS IS UNBOUNDED.
//
// `make ci` sat for 28 minutes, twice, at 0.26 seconds of CPU with no Chrome alive. Three separate
// unbounded waits, in three files, each of which alone was enough to hang the run:
//
//   - scripts/lib/cdp.mjs        the socket's open, and EVERY send()
//   - scripts/browser-check.mjs  the socket's open (its send() already had a deadline)
//   - scripts/browser-corpus.mjs the wait on each child's exit — the outermost one, so even a child that
//     failed correctly could not be reported if it never exited
//
// A gate that reports nothing is indistinguishable from a gate that is still working, which is the most
// expensive failure shape available to a gate: it costs the session rather than the run. The trigger both
// times was another Chrome driving the same binary — an environment condition the harness cannot prevent,
// so it stops pretending it can.
//
// This is a TEXTUAL check over the harness, which is the right shape for it: the property is "every wait
// has a deadline", and a runtime test would have to hang to prove a hang.
func TestBrowserHarness_EveryWaitHasADeadline(t *testing.T) {
	for _, f := range []string{
		"../../scripts/lib/cdp.mjs",
		"../../scripts/browser-check.mjs",
		"../../scripts/browser-corpus.mjs",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("read %s: %v", f, err)
			continue
		}
		src, name := string(b), filepath.Base(f)

		// `ws.onopen = res` assigned bare — with no setTimeout in the same promise — is the socket wait
		// that hung. The fixed form clears a timer inside the handler, so the marker is the assignment
		// without a nearby clearTimeout.
		for _, bad := range []string{
			"await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });",
			"await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });",
		} {
			if strings.Contains(src, bad) {
				t.Errorf("%s waits on the CDP socket with no deadline: a Chrome that reports an endpoint "+
					"and then stops answering leaves the process alive with nothing printed", name)
			}
		}

		// Every file that opens a socket must name a timeout for it.
		if strings.Contains(src, "new WebSocket(") && !strings.Contains(src, "did not open within") {
			t.Errorf("%s opens a CDP socket and never states a timeout for it", name)
		}

		// THE CORPUS DELIBERATELY HAS NO PER-CHILD DEADLINE, and that is the conclusion of three attempts
		// at one. 240s total failed 8 of 22; 600s total failed 2 of 22 on an idle machine; 120s of silence
		// failed 5 of 22, and four of those had already printed "every check passed" before being killed.
		// Measured after: run alone, that document prints its verdict at 55.6s and exits 0.1s later — so
		// there was no lingering child to guard against, and the guard was inventing failures in a gate
		// whose whole job is to be believed.
		//
		// The hang the deadline was for lives a layer down and is bounded there: a child that cannot drive
		// a browser fails and EXITS, which is what the corpus loop waits on. Guarding it twice, from
		// outside, where the outer guard cannot tell working from stuck, added only false reports.
		// THE LINGER GUARD KEYS ON THE VERDICT, NOT ON ANY LINE THE CHILD PRINTS.
		//
		// browser-corpus kills a child that has printed its verdict and has not exited — a leaked handle,
		// not a slow document, which is why it is allowed to exist beside the paragraph that removed the
		// per-child deadline. Its first version tested for the substring `browser-check: `, which the child
		// ALSO writes at startup as its Chrome banner: the timer started a second into every run and killed
		// each document ten seconds later, mid-checks, while the summary line still read "ok" because the
		// banner is what the summary regex picked up too. Measured: three documents that take 111s ran in
		// 24s and reported every check passed.
		//
		// A guard that shortens the work and reports success is the defect this project exists to refuse.
		// THE RETRY IS FOR A HARNESS FAILURE AND NEVER FOR A CHECK FAILURE.
		//
		// A child that printed "N check(s) failed" measured the document; running it again would hide a real
		// failure, which is the one thing a gate must not do. A child that printed no verdict measured
		// nothing. The predicate that tells those apart is the same anchored verdict match the linger guard
		// uses, and a retry keyed on anything looser would re-run genuine failures until one of them passed.
		if name == "browser-corpus.mjs" {
			if strings.Contains(src, "r = await run(files[i]);") &&
				!strings.Contains(src, "if (!verdictIn(r.out)) {") {
				t.Error("browser-corpus retries a document without checking that the first attempt produced " +
					"no verdict: a retry that cannot tell a dead browser from a failed check re-runs real " +
					"failures until one of them passes")
			}
			if strings.Contains(src, "!/browser-check: /.test(out)") {
				t.Error("browser-corpus starts its linger timer on any `browser-check: ` line, and the child " +
					"prints one at startup — so the guard fires mid-checks and the run is truncated with a " +
					"passing summary")
			}
			if !strings.Contains(src, "every check passed|") {
				t.Error("browser-corpus's linger trigger does not name the verdict lines: the guard has to " +
					"start only once the checks have reported, or it is a stopwatch on the work itself")
			}
		}
		if name == "browser-corpus.mjs" {
			for _, gone := range []string{"PER_DOC_TIMEOUT_MS", "SILENCE_TIMEOUT_MS"} {
				if strings.Contains(src, gone) {
					t.Errorf("browser-corpus.mjs has %s again. An outer per-child deadline cannot "+
						"distinguish a slow document from a stuck one — three of them failed 8, then 2, "+
						"then 5 documents of 22 that each pass alone", gone)
				}
			}
			// And the reasoning has to travel with the absence, or the next person adds a fourth.
			if !strings.Contains(src, "NO PER-CHILD DEADLINE HERE") {
				t.Error("browser-corpus.mjs does not record why it has no per-child deadline; without " +
					"that note the next reader sees an unbounded wait and adds one back")
			}

			// THE REAPER TAKES DIRECTORIES, NOT JUST PROCESSES. It killed leaked browsers and left their
			// user-data-dirs behind, one per killed run, forever — 267 of them were in the temp directory
			// when this was written, while cdp.mjs's own comment claimed this runner reaped "profiles".
			// Leaked browsers are what made the corpus slow enough for three successive deadlines to fire
			// on documents that were merely slow, so this is the root of that whole chase.
			if !strings.Contains(src, "pkill") {
				t.Error("browser-corpus.mjs does not reap leaked browsers; enough of them and this gate " +
					"slows to a crawl for reasons that have nothing to do with the checks")
			}
			// THE CALL, NOT THE IDENTIFIER. Checking for "rmSync" was satisfied by the import line, so
			// gutting the call itself left this green — the second time today a gate asserted that a
			// string exists in a file rather than that a behaviour exists.
			if !strings.Contains(src, "rmSync(path, { recursive: true, force: true })") {
				t.Error("browser-corpus.mjs imports rmSync and never removes a profile directory with it: " +
					"it reaps leaked browsers and leaves their user-data-dirs, which accumulate one per " +
					"killed run without limit")
			}
			if !strings.Contains(src, "hourAgo") {
				t.Error("the profile reaper has no age gate, so it could delete a directory belonging to a " +
					"harness that is running right now")
			}
			if !strings.Contains(src, `/^shoalcheck-(cdp|browser-check)-/`) {
				t.Error("the profile reaper is not scoped to this project's own prefixes — anything " +
					"broader could reach a directory that is not ours to delete")
			}
		}

		// And every send()/command path names one too.
		if strings.Contains(src, "const send = (method") &&
			!strings.Contains(src, "did not answer within") && !strings.Contains(src, "got no reply within") {
			t.Errorf("%s issues CDP commands with no per-command deadline", name)
		}
	}
}

// EVERY MAKEFILE RULE IS DECLARED PHONY, AND TWELVE WERE NOT — including four of the gates `make ci` runs.
//
// The failure this prevents is silent and total. If a file or directory in the repository root shares a
// target's name, make considers the target up to date and runs **nothing**: `make app-check` prints
// "app-check is up to date", exits 0, and `make ci` goes green having verified nothing. That is the same
// shape as every other defect removed this session — a gate that reports success without doing its work —
// except this one needs no bug to trigger, just a filename.
//
// The twelve were `app-check`, `browser-check`, `browser-corpus`, `browser-required`, `gofmt`,
// `transport-gate`, `mcp`, `mac-dmg` and the four kind-mesh targets. None of them produces a file of its
// own name, so all of them are phony and the rule is universal rather than a list to maintain.
func TestMakefile_EveryRuleIsPhony(t *testing.T) {
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	mk := string(b)

	rules := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^([a-z][a-z0-9-]*):`).FindAllStringSubmatch(mk, -1) {
		rules[m[1]] = true
	}
	if len(rules) < 20 {
		t.Fatalf("only %d rules parsed from the Makefile; its shape changed and this test is now blind",
			len(rules))
	}

	phony := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\.PHONY:(.*)$`).FindAllStringSubmatch(mk, -1) {
		for _, name := range strings.Fields(m[1]) {
			phony[name] = true
		}
	}
	if len(phony) == 0 {
		t.Fatal("no .PHONY declarations found at all")
	}

	for r := range rules {
		if !phony[r] {
			t.Errorf("the rule %q is not declared .PHONY: a file or directory of that name in the "+
				"repository root makes `make %s` a silent no-op that exits 0", r, r)
		}
	}
	// And nothing is declared phony that is not a rule — a name that drifted out of the Makefile and
	// stayed in the list is a target somebody thinks exists.
	for p := range phony {
		if !rules[p] {
			t.Errorf(".PHONY names %q and there is no such rule: the target was renamed or removed and "+
				"the declaration outlived it", p)
		}
	}
}
