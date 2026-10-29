package refdata_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/refdata"
	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
)

// SPEC §8 — DOWNLOAD-ONLY MUST BE A PROPERTY OF THE CODE, NOT A CONVENTION.
//
// Point 2 is the line between the two: "a POST with a payload is not merely un-written, it is not writable
// through the only door. A gate that greps for http.MethodPost proves a convention; a signature that has no
// io.Reader parameter proves a property."
//
// This test reads the constructor's SIGNATURE out of the source. It is the only way to assert the absence of a
// parameter, and the absence is the property.
func TestFetch_TheOnlyDoorAdmitsNoBodyAndNoMethod(t *testing.T) {
	b, err := os.ReadFile("fetch.go")
	if err != nil {
		t.Fatalf("read fetch.go: %v", err)
	}
	src := string(b)

	// THE PARAMETER LIST ONLY. The first version of this scan read the whole signature line and fired on
	// `[]byte` in the RETURN type — a fetcher must of course return bytes. The property is about what can be
	// handed IN, so the assertion has to be about the parameters and nothing else.
	params, ok := paramList(src, "func (f *Fetcher) Get")
	if !ok {
		t.Fatal("Fetcher.Get is not declared, so this test measured nothing")
	}
	for _, forbidden := range []string{"io.Reader", "[]byte", "body", "method", "http.Request", "io.Writer"} {
		if strings.Contains(params, forbidden) {
			t.Errorf("Fetcher.Get takes %q:\n  (%s)\n\nA request body must not be expressible through the only "+
				"door. That is what makes download-only a property rather than a habit.", forbidden, params)
		}
	}
	// NON-VACUITY: the parameter list must be the real one, or an empty string satisfies every assertion.
	if !strings.Contains(params, "SourceURL") {
		t.Errorf("the extracted parameter list does not mention SourceURL, so the extraction is wrong: (%s)", params)
	}

	// And no other verb must be reachable. A second request function would be a second door, and the property
	// is about there being one.
	//
	// COMMENTS STRIPPED FIRST. The file's own rationale explains why a grep for http.MethodPost proves only a
	// convention — and the first version of this scan fired on that sentence. A gate that fails on the
	// reasoning teaches the next person to delete the reasoning.
	code := stripGoComments(src)
	for _, forbidden := range []string{"MethodPost", "MethodPut", "MethodPatch", "MethodDelete", `"POST"`, `"PUT"`} {
		if strings.Contains(code, forbidden) {
			t.Errorf("fetch.go's code names %q — this file issues GETs and nothing else", forbidden)
		}
	}
	if !strings.Contains(code, "http.MethodGet") {
		t.Error("fetch.go's code never names http.MethodGet, so it is unclear what it does issue")
	}
	if len(code) < 500 {
		t.Fatalf("comment stripping left %d bytes, so the scan above measured almost nothing", len(code))
	}
}

// paramList returns the text between the parentheses of a function declaration, matching nesting so a
// parameter of a function type does not truncate it.
func paramList(src, decl string) (string, bool) {
	i := strings.Index(src, decl)
	if i < 0 {
		return "", false
	}
	open := strings.Index(src[i+len(decl):], "(")
	if open < 0 {
		return "", false
	}
	start := i + len(decl) + open + 1
	depth := 1
	for j := start; j < len(src); j++ {
		switch src[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return src[start:j], true
			}
		}
	}
	return "", false
}

// stripGoComments removes // and /* */ comments. Crude — it does not understand string literals holding a
// slash pair — and that is acceptable here: the failure mode is stripping slightly too much from a scan whose
// non-vacuity guard checks how much is left.
func stripGoComments(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); {
		if strings.HasPrefix(src[i:], "//") {
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				break
			}
			i += j
			continue
		}
		if strings.HasPrefix(src[i:], "/*") {
			j := strings.Index(src[i:], "*/")
			if j < 0 {
				break
			}
			i += j + 2
			continue
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String()
}

// THE URL COMES FROM A COMPILED-IN LIST, AND A CALLER CANNOT SUPPLY ONE (§8 point 5).
//
// This is the property that matters most: a request that could carry a cluster UID in a query string is
// outside the reach of the other four. Expressed in the type system — Get takes a SourceURL, and the only
// values of that type are package constants.
//
// AND WHEN THE BUILD COMPILES IN NONE, the property under test moves rather than disappearing. A default
// build publishes nowhere — the address that used to be a constant here named a domain this project does not
// own (see refdata.bundleSource) — so "a caller cannot supply a URL" is then held by the REFUSAL: Refresh
// with an empty source must say there is nothing to fetch, not issue a request to "". An empty list with no
// second assertion would be this suite's own version of a gate passing over an empty set.
func TestFetch_ACallerCannotSupplyAURL(t *testing.T) {
	srcs := refdata.Sources()
	if len(srcs) == 0 {
		err := refdata.Refresh(context.Background(), refdata.RefreshOptions{
			Fetcher:  refdata.NewFetcher(trace.New(nil)),
			Source:   "",
			CacheDir: t.TempDir(),
		})
		if err == nil {
			t.Fatal("this build compiles in no source AND Refresh accepted an empty one, so nothing " +
				"stands between the operator and a request to a URL that came from somewhere else")
		}
		if !strings.Contains(err.Error(), "nothing to fetch") {
			t.Errorf("the refusal does not say why there is no URL: %v", err)
		}
		t.Logf("no compiled-in source; the refusal was measured instead: %v", err)
		return
	}
	for _, s := range srcs {
		u := string(s)
		if !strings.HasPrefix(u, "https://") {
			t.Errorf("source %q is not https", u)
		}
		// NO CUSTOMER IDENTIFIER CAN BE ON THE WIRE. A compiled-in URL cannot carry one, and a query string
		// is where one would hide.
		if strings.Contains(u, "?") {
			t.Errorf("source %q carries a query string, which is where a cluster UID would hide", u)
		}
		for _, forbidden := range []string{"%s", "%v", "{", "+"} {
			if strings.Contains(u, forbidden) {
				t.Errorf("source %q is a template, so something is interpolated into it: %q", u, forbidden)
			}
		}
	}
}

// A FETCH IS RECORDED, COUNTED AS EXTERNAL, AND WRITES NOTHING (§8 points 3 and 4).
//
// Both halves of point 4: Tally.Write is 0 AND Total is greater than zero. A zero Write on a zero Total proves
// only that nothing happened.
func TestFetch_IsRecordedAsExternalAndWritesNothing(t *testing.T) {
	pub, priv := mustKeypair(t)
	payload := mustPayload(t, "pricing", "2026-08")
	signed := refdata.Sign(payload, priv)

	var served int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		if r.Method != http.MethodGet {
			t.Errorf("the fetcher issued a %s", r.Method)
		}
		if r.ContentLength > 0 {
			t.Errorf("the fetcher sent a body of %d bytes", r.ContentLength)
		}
		_, _ = w.Write(signed)
	}))
	defer srv.Close()

	rec := trace.New(nil)
	f := refdata.NewFetcher(rec)
	got, err := f.Get(context.Background(), refdata.SourceURL(srv.URL))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if served != 1 {
		t.Errorf("the server handled %d request(s), want 1", served)
	}
	if _, err := refdata.VerifyBundle(got, pub); err != nil {
		t.Errorf("what came back does not verify: %v", err)
	}

	tal := rec.Tally()
	if tal.Total == 0 {
		t.Fatal("the recorder saw nothing, so every assertion below is vacuous")
	}
	if tal.Write != 0 {
		t.Errorf("Tally.Write = %d — a reference-data GET reached the Kubernetes object-write claim", tal.Write)
	}
	if tal.External != 1 {
		t.Errorf("Tally.External = %d, want 1 — the fetch must be counted on its own line", tal.External)
	}
	if tal.Read != 0 {
		t.Errorf("Tally.Read = %d — a public-data GET is not a cluster read, and the read-only claim is about "+
			"the cluster", tal.Read)
	}
	// The host is recorded so an operator can check what was contacted; the path is not.
	hosts := rec.ExternalHosts()
	if len(hosts) != 1 {
		t.Errorf("ExternalHosts = %v, want one entry", hosts)
	}
}

// A REFRESH VERIFIES BEFORE IT WRITES A CACHE. A server that returns something we did not sign must leave the
// cache untouched — otherwise the next audit reads unsigned data and the signature was theatre.
func TestFetch_ARefreshDoesNotCacheWhatItCannotVerify(t *testing.T) {
	pub, _ := mustKeypair(t)
	_, otherPriv := mustKeypair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(refdata.Sign(mustPayload(t, "pricing", "2026-08"), otherPriv))
	}))
	defer srv.Close()

	dir := t.TempDir()
	rec := trace.New(nil)
	err := refdata.Refresh(context.Background(), refdata.RefreshOptions{
		Fetcher:   refdata.NewFetcher(rec),
		Source:    refdata.SourceURL(srv.URL),
		CacheDir:  dir,
		PublicKey: pub,
	})
	if err == nil {
		t.Fatal("a bundle signed by an unrelated key was accepted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("the cache holds %d file(s) after a refused refresh: the previous data must stay in place", len(entries))
	}

	// NON-VACUITY: the same flow with the RIGHT key must write a cache, or "nothing written" is true because
	// Refresh never writes.
	pub2, priv2 := mustKeypair(t)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(refdata.Sign(mustPayload(t, "pricing", "2026-08"), priv2))
	}))
	defer srv2.Close()
	dir2 := t.TempDir()
	if err := refdata.Refresh(context.Background(), refdata.RefreshOptions{
		Fetcher:   refdata.NewFetcher(trace.New(nil)),
		Source:    refdata.SourceURL(srv2.URL),
		CacheDir:  dir2,
		PublicKey: pub2,
	}); err != nil {
		t.Fatalf("a correctly signed bundle was refused: %v", err)
	}
	if entries, _ := os.ReadDir(dir2); len(entries) == 0 {
		t.Error("a verified refresh wrote no cache, so the refusal above proves nothing")
	}
}

// THE CACHE IS READ BACK, VERIFIED AGAIN, AND ITS VERSION REACHES A CALLER.
//
// Verified AGAIN on read, not trusted because it was verified on write: a cache file is on the operator's disk
// where anything can edit it, and "we checked it once" is the reasoning the history store's loadSnapshot had
// before it started validating.
func TestCache_IsVerifiedOnReadNotOnlyOnWrite(t *testing.T) {
	pub, priv := mustKeypair(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.bundle")
	if err := os.WriteFile(path, refdata.Sign(mustPayload(t, "pricing", "2026-08"), priv), 0o600); err != nil {
		t.Fatalf("seed the cache: %v", err)
	}

	b, err := refdata.LoadCache(dir, pub)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if b.Datasets["pricing"].Version != "2026-08" {
		t.Errorf("cached version = %q, want 2026-08", b.Datasets["pricing"].Version)
	}

	// Hand-edit it, the way a customer verifying our re-derivation claim would.
	raw, _ := os.ReadFile(path)
	var env refdata.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Payload = json.RawMessage(strings.Replace(string(env.Payload), `"2026-08"`, `"2027-01"`, 1))
	edited, _ := json.Marshal(env)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if _, err := refdata.LoadCache(dir, pub); err == nil {
		t.Error("a hand-edited cache file loaded — it was trusted because it had been verified once")
	}
	// An empty cache dir is not an error: it is the ordinary state before any refresh.
	if _, err := refdata.LoadCache(t.TempDir(), pub); err != nil {
		t.Errorf("an empty cache directory reported an error: %v", err)
	}
}

var _ = ed25519.PublicKeySize
