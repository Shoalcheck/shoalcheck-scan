// Package refdata is the reference-data channel: data that ages on a public schedule — prices, Kubernetes
// EOL dates, provider deprecations, control text — and can be refreshed without a new binary.
//
// THREE CHANNELS, AND THE SENTENCE THAT KEEPS THEM APART. Logic ships in the binary and is never downloaded,
// interpreted or configurable, because downloadable logic is a remote-code-execution surface and would end
// the property that dishonesty fails the build — the honesty guards live in Go and are enforced by `make ci`,
// not by a data file. Cluster data never leaves the machine. Reference data is the only one of the three that
// is a public, customer-independent fact, and it is the only one this package handles.
//
// THIS PACKAGE SHIPS NO NETWORK CODE. That is deliberate and it is enforced by a test
// (TestBundle_ThisPackageShipsNoNetworkCode). The epic was split so the honesty-critical half — the signed
// bundle format, verification, the version stamp and the sixth comparison gate — lands with no HTTP client at
// all and therefore needs no change to `make transport-gate`. The fetcher is a separate change that cannot
// regress a gate which by then exists and is tested.
//
// WHAT SIGNING DOES AND DOES NOT PROVE. ed25519 proves a bundle is the one we published. It says nothing
// about whether the price inside it is right — the same admission cmd/shoalcheck-app/license.go:10-15 already
// makes about licences. A bundle is a dated snapshot of public sources, named in the report with its date and
// its source, exactly as the embedded table is.
package refdata

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/apiremoval"
	"github.com/Shoalcheck/shoalcheck-scan/internal/kubeversions"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Source is where a dataset's bytes came from. A CLOSED SET: a report prints it and the comparison gate
// reasons beside it, so a future leg inventing a provenance string would make both unfalsifiable.
type Source string

const (
	// SourceEmbedded is the compiled-in snapshot — the offline, deterministic, air-gapped default. It is
	// what makes the tool autonomous; fetching is a convenience on top of it, and if the fallback ever stops
	// being correct, a fetch is not a mitigation.
	SourceEmbedded Source = "embedded"
	// SourceCache is a previously-fetched dataset on disk, within its TTL.
	SourceCache Source = "cache"
	// SourceBundle is a signed bundle the operator supplied — `shoalcheck update --bundle`. No network involved.
	SourceBundle Source = "bundle"
	// SourceLive is a fetch from a credential-free public source. Half two.
	SourceLive Source = "live"
)

func (s Source) Valid() bool {
	switch s {
	case SourceEmbedded, SourceCache, SourceBundle, SourceLive:
		return true
	}
	return false
}

// Datasets returns every registered dataset name, sorted.
//
// PRICING ONLY, FIRST. Its staleness test already exists, its sources are documented and spot-checked in
// scripts/update-pricing.py, and its comparison defect is live rather than hypothetical — a refreshed table
// makes a report announce a dollar delta on an unchanged cluster. Epic 4's Kubernetes API-removal table is
// the second dataset, on the shape this establishes.
//
// Sorted so two readings of the same registry list it identically, and counted by a test so a dataset added
// without a DataVersions stamp fails the build instead of shipping unstamped.
func Datasets() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// dataset is what the registry knows about one reference dataset without loading anything.
type dataset struct {
	// embeddedVersion reports the compiled-in snapshot's own stamp. A function rather than a constant so a
	// dataset's stamp stays in the package that owns the table, instead of being copied here where it would
	// drift.
	embeddedVersion func() string
}

var registry = map[string]dataset{
	"pricing": {embeddedVersion: pricing.AsOf},
	// THE SECOND DATASET, and it lands on the shape the first one established rather than beside it. Its
	// staleness matters differently from pricing's: a stale price table makes a figure less current, and a
	// stale removal schedule makes a rule silently miss a removal that has since been announced — which is
	// why k8s.upgrade.deprecated-api-served declares it with Presence:true and pricing is declared without.
	"api-removals": {embeddedVersion: apiremoval.AsOf},
	// THE THIRD DATASET, and its staleness fails a third way. A stale price makes a figure a few percent
	// wrong and says so through its own stamp. A stale removal schedule makes a rule miss a removal that
	// has since been announced. A stale SUPPORT WINDOW makes a version that crossed its end-of-support
	// inside the staleness window produce no finding at all — and an absent finding carries no stamp for
	// a reader to distrust. Same shape, three different consequences, which is why each dataset gets its
	// own generator and its own cadence.
	"kubeversions": {embeddedVersion: kubeversions.AsOf},
}

// EmbeddedVersion is a dataset's compiled-in stamp, or "" for a name the registry does not hold.
func EmbeddedVersion(name string) string {
	d, ok := registry[name]
	if !ok {
		return ""
	}
	return d.embeddedVersion()
}

// ── the bundle ───────────────────────────────────────────────────────────────────────────────────

// Bundle is a set of dated reference datasets. It is the payload a signature is taken over, never the thing
// that carries the signature — see Envelope.
type Bundle struct {
	// FormatVersion is the envelope-and-bundle shape, not the data's date. A bundle from a future format is
	// refused rather than parsed optimistically: half-understanding a signed artifact is worse than refusing
	// it, because the operator cannot tell the difference from success.
	FormatVersion int `json:"formatVersion"`
	// Datasets maps a registry name to its stamp and payload.
	Datasets map[string]DatasetStamp `json:"datasets"`
}

// DatasetStamp is one dataset inside a bundle.
type DatasetStamp struct {
	// Version is the dataset's own date stamp, e.g. "2026-08". It is what the sixth comparison gate compares;
	// Source is deliberately not compared, because the same table read from the embedded snapshot on Monday
	// and from a bundle on Friday is the same table.
	Version string `json:"version"`
	// Payload is the dataset's own bytes, parsed by whoever owns that dataset. This package verifies and
	// routes; it does not interpret. A package that both verified signatures and parsed price tables would
	// make a parser bug a trust-boundary bug.
	Payload json.RawMessage `json:"payload"`
}

// Envelope is the signed wrapper: a payload and a detached signature over exactly those bytes.
//
// A DOCUMENTED JSON SHAPE ON PURPOSE. The licence format nests base64 inside base64 because a licence key is
// pasted into a text field by a human; a bundle is a file, and a shape a test can construct and tamper with
// directly is worth more than compactness — it is how the tampering case gets tested without the package
// exporting a tampering helper.
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

// Typed errors, so a caller distinguishes "this is not a bundle" from "this bundle is not ours". The
// difference matters at the command line: one is a wrong file, the other is a supply-chain question.
var (
	ErrBundleMalformed = errors.New("not a signed reference-data bundle")
	ErrBundleSignature = errors.New("bundle signature does not verify")
	ErrBundleNoKey     = errors.New("no bundle verification key")
	ErrBundleFormat    = errors.New("unsupported bundle format version")
)

// FormatVersion is the only bundle shape this binary understands.
const FormatVersion = 1

// Sign wraps payload in an Envelope signed by priv. Exported because a publisher — and the tests — must be
// able to mint bundles with the documented encoding, the same reason EncodeLicense is exported.
func Sign(payload []byte, priv ed25519.PrivateKey) []byte {
	env := Envelope{Payload: json.RawMessage(append([]byte(nil), payload...)), Signature: ed25519.Sign(priv, payload)}
	out, err := json.Marshal(env)
	if err != nil {
		// Marshalling a struct of a RawMessage and a []byte cannot fail; returning an error here would add a
		// branch every caller must handle for a case that does not exist.
		panic("refdata: marshalling a signed envelope: " + err.Error())
	}
	return out
}

// VerifyBundle verifies signed against pub and returns the bundle it carries.
//
// VERIFY BEFORE LOAD, AND REFUSE RATHER THAN FALL BACK. Not a single dataset byte is interpreted until the
// signature checks out, and a bad signature is a typed error with the previous data left in place — because
// "fall back to embedded and carry on" is indistinguishable from a successful update to the operator.
//
// The public key is a PARAMETER, never a package global read inside the verifier, so the verifier is testable
// with an injected key and keys can rotate without code edits (cmd/shoalcheck-app/license.go:94-97). It is also
// what lets TestBundle_ALicenceKeyCannotSignABundle prove the two keypairs are actually two.
func VerifyBundle(signed []byte, pub ed25519.PublicKey) (*Bundle, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrBundleNoKey
	}
	var env Envelope
	if err := json.Unmarshal(signed, &env); err != nil {
		return nil, fmt.Errorf("%w: envelope json: %v", ErrBundleMalformed, err)
	}
	if len(env.Payload) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrBundleMalformed)
	}
	if len(env.Signature) != ed25519.SignatureSize {
		// An unsigned file lands here: it parses as JSON, carries no signature, and is refused as malformed
		// rather than as a signature failure — the operator handed us the wrong file, not a tampered one.
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrBundleMalformed, len(env.Signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, env.Payload, env.Signature) {
		return nil, ErrBundleSignature
	}

	var b Bundle
	if err := json.Unmarshal(env.Payload, &b); err != nil {
		return nil, fmt.Errorf("%w: bundle json: %v", ErrBundleMalformed, err)
	}
	if b.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("%w: bundle says %d, this binary understands %d",
			ErrBundleFormat, b.FormatVersion, FormatVersion)
	}
	if len(b.Datasets) == 0 {
		return nil, fmt.Errorf("%w: no datasets", ErrBundleMalformed)
	}
	for name, ds := range b.Datasets {
		if ds.Version == "" {
			return nil, fmt.Errorf("%w: dataset %q carries no version", ErrBundleMalformed, name)
		}
	}
	return &b, nil
}

// ── the stamp ────────────────────────────────────────────────────────────────────────────────────

// Stamp is the DataVersions map for one run: every registered dataset, with the version and source this run
// actually read.
//
// ONE PLACE THAT ITERATES THE REGISTRY, so "every dataset is stamped" is a property of this function rather
// than a habit of every caller. A dataset added to the registry without a leg here produces an empty stamp,
// which TestDataVersions_EveryDatasetIsStamped fails on — the failure is at the registry, where the omission
// is, and not three layers away in a report.
//
// The pricing provider is passed rather than resolved here, because the run already chose one and asking a
// second time could answer differently — which is how a report ends up naming a table it did not price from.
func Stamp(pp pricing.PriceProvider) map[string]types.DataVersion {
	out := make(map[string]types.DataVersion, len(registry))
	for name := range registry {
		switch name {
		case "pricing":
			if pp == nil {
				pp = pricing.Embedded()
			}
			version, source := pp.AsOf()
			out[name] = types.DataVersion{Version: version, Source: source}
		case "kubeversions":
			// Embedded-only for the same reason api-removals is: no provider indirection, no bundle entry,
			// no cache. When a bundle carries it, this leg changes in the edit that adds the entry.
			out[name] = types.DataVersion{Version: kubeversions.AsOf(), Source: string(SourceEmbedded)}
		case "api-removals":
			// Embedded is not a default here, it is the only leg that exists: this table has no provider
			// indirection, no bundle entry and no cache, so naming any other source would be a guess. When a
			// bundle carries it, this leg changes in the same edit that adds the entry.
			out[name] = types.DataVersion{Version: apiremoval.AsOf(), Source: string(SourceEmbedded)}
		default:
			// Deliberately empty rather than guessed. A dataset in the registry with no leg here is a bug in
			// this function, and an empty stamp is what makes the test say so; inventing "embedded" would
			// make a report name a table nothing read.
			out[name] = types.DataVersion{}
		}
	}
	return out
}
