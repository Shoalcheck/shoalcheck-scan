package refdata

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
)

// fetch.go — THE ONLY DOOR, AND IT OPENS ONE WAY.
//
// This is the first code in this repository that issues an HTTP request to a host that is not the customer's.
// Everything about its shape is chosen so that download-only is a PROPERTY rather than a convention somebody
// observed while writing it:
//
//	No body is expressible. Get's signature has no io.Reader, no []byte, no method parameter. A POST with a
//	payload is not merely un-written — it is not writable through the only door. A gate that greps for
//	http.MethodPost proves a convention; a signature with no body parameter proves a property.
//
//	A caller cannot supply a URL. Get takes a SourceURL, and every value of that type is a package constant
//	pointing at a credential-free public source. §8's fifth property — "no customer identifier can be on the
//	wire" — is the one the other four cannot reach, because a request carrying a cluster UID in a query string
//	satisfies all of them. A compiled-in constant cannot carry one.
//
//	It constructs no transport. The RoundTripper comes from trace.Recorder.Wrap, which is what makes the
//	request countable — and it is why `make transport-gate` needs no change for this file: it builds no
//	http.Client and no http.Transport, exactly as internal/tracker's postJSON does not, for the same reason.
//
//	It is a RoundTripper and not an http.Client. A Client follows redirects by default, so a 301 with a
//	Location on another host would make this binary contact a host nobody configured — the precise property
//	the gate exists to prove. A bare RoundTripper follows nothing, so a redirect surfaces as a status code
//	this code refuses.
//
// WHAT IT FETCHES IS A SIGNED BUNDLE, not a vendor API response. That follows from P3: verify before load,
// refuse rather than fall back. A vendor's price API answers with unsigned JSON, so caching it would put
// unsigned reference data on disk and the signature would be theatre for the `--bundle` path alone. The
// vendor APIs are read by scripts/update-pricing.py at PUBLISH time, and what crosses the wire here is the
// artifact we signed.
//
// NEVER DURING AN AUDIT. Nothing on the audit path reaches this file; `shoalcheck update` is the only caller.

// SourceURL is a credential-free public source of reference data. Its values are the package constants below
// and nothing else — a type rather than a string so a caller cannot pass a URL of their own.
//
// Tests construct one directly, which is the same latitude every other type in this repo gives them; what the
// type prevents is a PRODUCTION caller assembling a URL from cluster data, because nothing in internal/ or
// cmd/ has a reason to name this type at all except the update command.
type SourceURL string

// bundleSource is where THIS BUILD publishes its signed bundles, injected with
//
//	-ldflags "-X shoalcheck/internal/refdata.bundleSource=https://…/latest.bundle"
//
// EMPTY BY DEFAULT, AND THAT IS A CORRECTION RATHER THAN A GAP. It used to be a compiled-in constant naming
// `data.assay.sh`, described in this file as "where the vendor publishes the current signed bundle" — and
// **assay.sh is not this project's domain.** Measured 2026-09-11: it 308s to www.assay.sh, which serves a
// live product called "Assay — Agentic Code Reviews", with its own pricing and sign-in; `data.assay.sh`
// answers 404 from that party's Vercel deployment.
//
// So a release build carrying a bundle-verification key would have issued a GET to a third party's server
// from the operator's machine. The signature check would have refused whatever came back — the order in
// Refresh is not negotiable — but refusing the payload is not the whole harm: the request itself puts this
// product's users in somebody else's logs, from a tool whose argument is that it contacts nothing you did
// not ask it to.
//
// A build with no source REFUSES rather than fetching, which is the same shape as a build with no
// verification key. Choosing the address is a decision for whoever owns the domain, and an empty string
// invents nothing.
var bundleSource = ""

// SourceBundleLatest is this build's published bundle source, and false when it names none.
func SourceBundleLatest() (SourceURL, bool) {
	if bundleSource == "" {
		return "", false
	}
	return SourceURL(bundleSource), true
}

// Sources returns every compiled-in source, sorted. EMPTY IS A REAL ANSWER: this build publishes nowhere.
func Sources() []SourceURL {
	src, ok := SourceBundleLatest()
	if !ok {
		return nil
	}
	out := []SourceURL{src}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// maxBundleBytes caps what a fetch will read. A signed bundle of price tables is measured in hundreds of
// kilobytes; anything larger is a proxy's error page or a hostile response, and there is no reason to hold it
// in memory to find out.
const maxBundleBytes = 32 << 20

// Fetcher issues GETs to the compiled-in sources, through the session-trace recorder.
type Fetcher struct {
	rt http.RoundTripper
}

// NewFetcher wires a fetcher to a recorder. A nil recorder is refused at the point of use rather than
// silently unwrapped: an unrecorded non-cluster request is the one thing the trace exists to prevent, and
// falling back to a bare transport would produce exactly that with no error.
func NewFetcher(rec *trace.Recorder) *Fetcher {
	if rec == nil {
		return &Fetcher{}
	}
	// http.DefaultTransport as the base, named by the recorder's own wrapper when the caller passes nil —
	// this file constructs neither a client nor a transport.
	return &Fetcher{rt: rec.Wrap(trace.TargetPublicData)(nil)}
}

// Get retrieves one source. NO BODY, NO METHOD, NO CALLER-SUPPLIED URL — see the file comment; the absence of
// those three parameters is the property this whole file exists to hold.
func (f *Fetcher) Get(ctx context.Context, src SourceURL) ([]byte, error) {
	if f == nil || f.rt == nil {
		return nil, fmt.Errorf("refusing to fetch without a session-trace recorder: an unrecorded request to a " +
			"host that is not the cluster is the one thing this product's trace exists to make impossible")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, string(src), nil)
	if err != nil {
		return nil, fmt.Errorf("build the request for %s: %w", src, err)
	}
	resp, err := f.rt.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", src, err)
	}
	defer resp.Body.Close()

	// A REDIRECT IS A REFUSAL, not something to follow. A bare RoundTripper does not follow one, and a 301
	// with a Location on another host is precisely the case that would make this binary contact a host nobody
	// configured.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("fetch %s: refusing a %d redirect; a reference-data source is a compiled-in "+
			"constant and following one would contact a host nobody configured", src, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", src, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", src, err)
	}
	if len(body) > maxBundleBytes {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", src, maxBundleBytes)
	}
	return body, nil
}

// ── the cache ────────────────────────────────────────────────────────────────────────────────────

// cacheFile is the one name a cached bundle has. One file rather than one per version: the cache is "the
// current reference data", and a directory accumulating versions would make "which one is live" a question
// nobody can answer from the filesystem.
const cacheFile = "pricing.bundle"

// RefreshOptions is what a refresh needs. Every field is required; there is no useful default for any of them
// and a zero value that half-worked would be worse than one that refuses.
type RefreshOptions struct {
	Fetcher   *Fetcher
	Source    SourceURL
	CacheDir  string
	PublicKey ed25519.PublicKey
}

// Refresh fetches a bundle, VERIFIES IT, and only then writes the cache.
//
// THE ORDER IS THE POINT. A refresh that wrote first and verified after would leave unsigned data on disk for
// the next audit to read, and "we will check it later" is how a signature becomes decoration. A refused
// refresh leaves the previous cache exactly where it was — not "falls back to embedded", which is
// indistinguishable from success to the operator.
func Refresh(ctx context.Context, opts RefreshOptions) error {
	if opts.CacheDir == "" {
		return fmt.Errorf("refusing to refresh without a cache directory")
	}
	// AN EMPTY SOURCE IS A REFUSAL, not a request to "". http.NewRequest would reject it anyway, with a URL
	// parse error that says nothing about why there is no URL — and this build genuinely has none to name.
	if opts.Source == "" {
		return fmt.Errorf("this build names no published bundle source, so there is nothing to fetch; " +
			"pass a bundle carried in by hand instead")
	}
	raw, err := opts.Fetcher.Get(ctx, opts.Source)
	if err != nil {
		return err
	}
	if _, err := VerifyBundle(raw, opts.PublicKey); err != nil {
		return fmt.Errorf("refusing what %s served: %w", opts.Source, err)
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return fmt.Errorf("create the cache directory: %w", err)
	}
	// Written to a temp file and renamed, so an interrupted write cannot leave a truncated bundle that the
	// next read would refuse — turning a network blip into a broken cache.
	tmp := filepath.Join(opts.CacheDir, cacheFile+".partial")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write the cache: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(opts.CacheDir, cacheFile)); err != nil {
		return fmt.Errorf("install the cache: %w", err)
	}
	return nil
}

// LoadCache reads the cached bundle and VERIFIES IT AGAIN.
//
// Verified again on read, not trusted because it was verified on write. A cache file sits on the operator's
// disk where anything can edit it, and "we checked it once" is exactly the reasoning internal/history's
// loadSnapshot carried before it started validating — accurate on the day it was written, false the moment the
// file outlives it.
//
// AN ABSENT CACHE IS NOT AN ERROR. It is the ordinary state before any refresh, and the embedded snapshot is
// the correct answer there. A nil bundle with a nil error says "nothing cached" without making every caller
// spell an errors.Is.
func LoadCache(dir string, pub ed25519.PublicKey) (*Bundle, error) {
	if dir == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, cacheFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the cached bundle: %w", err)
	}
	b, err := VerifyBundle(raw, pub)
	if err != nil {
		return nil, fmt.Errorf("the cached bundle no longer verifies: %w", err)
	}
	return b, nil
}
