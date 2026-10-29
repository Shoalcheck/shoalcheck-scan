package refdata_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/refdata"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// SPEC §10 test 3 — TestDataVersions_EveryDatasetIsStamped, the registry half.
//
// The registry is what makes "every report names the data version it used, per dataset" checkable rather
// than aspirational. Its exact count is asserted, so a dataset added without being stamped fails the build
// instead of passing quietly — the same shape as the app-surface spec's TestUIVocabulary_ResolvesEverySection.
func TestDatasets_TheRegistryIsClosedAndCounted(t *testing.T) {
	names := refdata.Datasets()
	if len(names) == 0 {
		t.Fatal("the registry is empty, so every assertion about stamping every dataset is vacuous")
	}
	// PRICING FIRST (brief §2 Q4), API-REMOVALS SECOND — the second dataset landed 2026-08-30 with Upgrade
	// Preflight, on exactly the shape this test anticipated. KUBEVERSIONS THIRD, 2026-08-31, and this
	// number moved in the same change as its leg in Stamp — which is the whole point: a fourth dataset
	// added without a stamp must fail the build rather than ship unstamped.
	if got, want := len(names), 3; got != want {
		t.Errorf("registry holds %d dataset(s) %v, want %d. A dataset added here without a DataVersions "+
			"stamp would ship unstamped; raise this number in the same change as the stamp.", got, names, want)
	}
	want := map[string]bool{"pricing": true, "api-removals": true, "kubeversions": true}
	for _, n := range names {
		if !want[n] {
			t.Errorf("registry holds unexpected dataset %q", n)
		}
		delete(want, n)
	}
	for n := range want {
		t.Errorf("registry is missing dataset %q", n)
	}
	// Sorted, so two readings of the same registry list it the same way.
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Errorf("registry is not sorted: %v", names)
		}
	}
}

// THE SOURCE VOCABULARY IS CLOSED. A report that could print any string as a provenance would let a future
// leg invent one, and the comparison gate keys on Version while a surface prints Source — both need to know
// the set.
func TestSources_AreAClosedSet(t *testing.T) {
	for _, s := range []refdata.Source{refdata.SourceEmbedded, refdata.SourceCache, refdata.SourceBundle, refdata.SourceLive} {
		if !s.Valid() {
			t.Errorf("%q is in the constant list and reports itself invalid", s)
		}
		if s == "" {
			t.Error("a source constant is empty")
		}
	}
	for _, bad := range []refdata.Source{"", "guessed", "Embedded", "EMBEDDED"} {
		if refdata.Source(bad).Valid() {
			t.Errorf("%q is accepted as a source", bad)
		}
	}
}

// SPEC §10 test 11 — TestBundle_RefusesWhatItCannotVerify. Four cases, keys generated in the test and
// injected per license.go:94-97.
//
// Non-vacuity: the valid case must CHANGE THE LOADED VERSION. A loader that never loads anything would
// otherwise pass all four refusals.
func TestBundle_RefusesWhatItCannotVerify(t *testing.T) {
	pub, priv := mustKeypair(t)
	other, otherPriv := mustKeypair(t)
	_ = other

	payload := mustPayload(t, "pricing", fixtureVersion)

	t.Run("a valid signature loads and the version changes", func(t *testing.T) {
		signed := refdata.Sign(payload, priv)
		b, err := refdata.VerifyBundle(signed, pub)
		if err != nil {
			t.Fatalf("a bundle we signed was refused: %v", err)
		}
		v, ok := b.Datasets["pricing"]
		if !ok {
			t.Fatal("the verified bundle carries no pricing dataset")
		}
		// 9999-12 IS DELIBERATE AND IS NOT A DATE. The fixture used "2026-08" until 2026-08-31, when a
		// pricing refresh moved the embedded stamp to that same month and this assertion quietly stopped
		// distinguishing anything. A month that the embedded data can never reach makes the test
		// non-vacuous permanently, instead of until the next refresh happens to collide again.
		//
		// NON-VACUITY: the version must be the bundle's, not the embedded one. A loader that returns the
		// embedded snapshot regardless would pass every refusal case above.
		if v.Version != fixtureVersion {
			t.Errorf("loaded version %q, want %s — the loader is not reading the bundle", v.Version, fixtureVersion)
		}
		if v.Version == refdata.EmbeddedVersion("pricing") {
			t.Errorf("the loaded version equals the embedded one (%q), so this test cannot tell a load from a "+
				"fallback — change the fixture's version", v.Version)
		}
	})

	t.Run("a flipped payload byte refuses", func(t *testing.T) {
		signed := refdata.Sign(payload, priv)
		// Flip a byte inside the PAYLOAD, not the signature: the point is that the content is what is
		// signed over, so tampering with the data must be caught even though the signature is intact.
		tampered := flipPayloadByte(t, signed)
		if _, err := refdata.VerifyBundle(tampered, pub); err == nil {
			t.Fatal("a bundle with a modified payload verified")
		} else if !strings.Contains(err.Error(), refdata.ErrBundleSignature.Error()) {
			t.Errorf("tampering reported as %v, want a signature error", err)
		}
	})

	t.Run("a valid signature by a different key refuses", func(t *testing.T) {
		signed := refdata.Sign(payload, otherPriv)
		if _, err := refdata.VerifyBundle(signed, pub); err == nil {
			t.Fatal("a bundle signed by an unrelated key verified")
		}
	})

	t.Run("an unsigned bundle refuses", func(t *testing.T) {
		if _, err := refdata.VerifyBundle(payload, pub); err == nil {
			t.Fatal("an unsigned payload verified")
		}
	})

	t.Run("no key at all refuses", func(t *testing.T) {
		signed := refdata.Sign(payload, priv)
		if _, err := refdata.VerifyBundle(signed, nil); err == nil {
			t.Fatal("a bundle verified against no key")
		}
	})
}

// THE TWO KEYPAIRS ARE SEPARATE, AND THIS IS THE TEST THAT MAKES IT REAL (brief §2 Q5).
//
// license.go:49-56 says the embedded licence key is the dev/founder key and must rotate before any
// customer-facing release. Sharing it would mean rotating the licence invalidates every published bundle,
// and a bundle-key compromise costs the licence channel.
//
// TWO KEYS THAT ARE NOMINALLY SEPARATE AND INTERCHANGEABLY ACCEPTED ARE ONE KEY. So: a bundle signed with
// the licence key must be REFUSED by the bundle verifier.
func TestBundle_ALicenceKeyCannotSignABundle(t *testing.T) {
	bundlePub, bundlePriv := mustKeypair(t)
	licencePub, licencePriv := mustKeypair(t)

	payload := mustPayload(t, "pricing", fixtureVersion)

	// Signed with the LICENCE key, verified against the BUNDLE key.
	if _, err := refdata.VerifyBundle(refdata.Sign(payload, licencePriv), bundlePub); err == nil {
		t.Error("a bundle signed with the licence key was accepted by the bundle verifier — the two keys are " +
			"one key, and rotating the licence would invalidate every published bundle")
	}
	// And the converse, so the test cannot pass because the verifier refuses everything.
	if _, err := refdata.VerifyBundle(refdata.Sign(payload, bundlePriv), bundlePub); err != nil {
		t.Errorf("the bundle key cannot sign a bundle either: %v", err)
	}
	// The keys really are different, or the assertion above proves nothing.
	if string(bundlePub) == string(licencePub) {
		t.Fatal("the test generated the same key twice")
	}
}

// SPEC §10 test 12 AND §8 point 1 — ONE CONSTRAINED DOOR, AND EVERY OTHER FILE HAS NONE.
//
// Half one of this epic asserted that this package ships no network code at all, which was true and was the
// reason it needed no transport-gate change. Half two adds fetch.go and makes that claim false — so the
// property is RE-SCOPED RATHER THAN DELETED, into the stronger one §8 asks for: exactly one file in this
// package can reach the network, and the verify-and-load half still cannot.
//
// That matters because `--bundle` is the air-gapped path. If verification, cache reading or bundle parsing
// could dial, "works with no network at all" would be a claim about what a call happens to do rather than
// about what the code can do.
//
// Detected by the IMPORT and not by a text scan: fetch.go's own comments discuss http.Client in order to
// explain why it does not use one, and a grep for the words would fail on the rationale — which is how a
// gate teaches the next person to delete the rationale.
func TestBundle_OnlyOneFileInThisPackageCanReachTheNetwork(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no Go files found in this package (%v), so this scan measured nothing", err)
	}
	var networked []string
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scanned++
		src := string(b)
		// The import block only: a mention inside a comment is prose, and an import is capability.
		imports := src
		if i := strings.Index(src, "\n)"); i > 0 {
			imports = src[:i]
		}
		for _, imp := range []string{`"net/http"`, `"net"`, `"net/url"`} {
			if strings.Contains(imports, imp) {
				networked = append(networked, f+" imports "+imp)
			}
		}
	}
	sort.Strings(networked)

	if len(networked) != 1 || !strings.HasPrefix(networked[0], "fetch.go ") {
		t.Errorf("network capability in this package is %v; want exactly [fetch.go imports \"net/http\"].\n"+
			"One constrained door is §8's first property, and the verify-and-load half must stay air-gapped by "+
			"construction rather than by habit.", networked)
	}
	if scanned < 2 {
		t.Fatalf("only %d non-test file(s) scanned", scanned)
	}
	t.Logf("%d non-test file(s), %d with network capability", scanned, len(networked))
}

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func mustPayload(t *testing.T, dataset, version string) []byte {
	t.Helper()
	b, err := json.Marshal(refdata.Bundle{
		FormatVersion: 1,
		Datasets: map[string]refdata.DatasetStamp{
			dataset: {Version: version, Payload: json.RawMessage(`{"note":"a dated snapshot of public sources"}`)},
		},
	})
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return b
}

// flipPayloadByte changes one byte of the signed envelope's PAYLOAD, leaving the signature intact. Done
// here rather than behind a production helper: a package that exports a tampering function for its own tests
// has widened its API for a test's convenience, and the envelope is a documented JSON shape precisely so a
// test can manipulate it without one.
// fixtureVersion is the ONE place the test bundle's version is written.
//
// It was a literal in two places — the payload builder and the tamper below — until 2026-08-31, when
// the payload moved and the tamper kept searching for a string that was no longer there. The tamper
// then changed nothing and the case reported that honestly, but only because it happened to check.
// One constant removes the drift rather than relying on the check catching it next time.
const fixtureVersion = "9999-12"

func flipPayloadByte(t *testing.T, signed []byte) []byte {
	t.Helper()
	var env refdata.Envelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatalf("the signed envelope is not the documented JSON shape: %v", err)
	}
	if len(env.Payload) == 0 {
		t.Fatal("the envelope carries no payload")
	}
	// A CONTENT change that keeps the payload valid JSON, which is the strongest form of this test: an
	// attacker edits the version or a price, not the braces. A bit-flip at a random offset usually breaks
	// JSON syntax, and a payload that fails to parse would be refused for the wrong reason — proving the
	// unmarshaller works rather than the signature.
	tampered := bytes.Replace(env.Payload,
		[]byte(`"`+fixtureVersion+`"`), []byte(`"9999-11"`), 1)
	if bytes.Equal(tampered, env.Payload) {
		t.Fatal("the tamper changed nothing, so this case would pass against an unverified loader")
	}
	env.Payload = tampered
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}

// THE TWO SOURCE VOCABULARIES MUST AGREE.
//
// internal/types is a leaf — every package depends on it and it depends on nothing — so it cannot import the
// constants here and carries its own copy in DataSourceValid. That is the same shape Severity and Category
// already use, and it has the same failure mode: two lists that drift. This is the assertion that stops them,
// in the package that owns the authority.
func TestSources_TypesAgreesWithTheAuthority(t *testing.T) {
	all := []refdata.Source{refdata.SourceEmbedded, refdata.SourceCache, refdata.SourceBundle, refdata.SourceLive}
	for _, s := range all {
		if !types.DataSourceValid(string(s)) {
			t.Errorf("refdata knows the source %q and types.DataSourceValid rejects it — a report stamped with "+
				"it would fail its own validity check", s)
		}
	}
	// And nothing types accepts may be unknown here, which is the direction that matters more: types is what
	// a report is validated against, so a value it blesses and this package does not is a value that ships.
	for _, s := range []string{"embedded", "cache", "bundle", "live"} {
		if !refdata.Source(s).Valid() {
			t.Errorf("types.DataSourceValid accepts %q and refdata.Source does not", s)
		}
	}
	// NON-VACUITY: both must reject something, or two functions returning true always would agree perfectly.
	if types.DataSourceValid("guessed") || refdata.Source("guessed").Valid() {
		t.Error("one of the two accepts an invented source")
	}
	if len(all) == 0 {
		t.Fatal("no sources to compare")
	}
}
