package pricing

// PriceConfig controls hybrid resolution. The zero value is the offline,
// deterministic, air-gapped default: embedded tables, no network, no new trust
// boundary. Live fetch is strictly opt-in (RefreshLive, from --refresh-pricing)
// and hits ONLY credential-free public HTTP APIs — NEVER the IAM-gated
// aws-pricing Query API, NEVER internal/billing.
type PriceConfig struct {
	RefreshLive bool   // --refresh-pricing: allow public-API live fetch (default OFF)
	CacheDir    string // ~/.shoalcheck/pricing; "" disables the disk cache
	GCPAPIKey   string // SHOALCHECK_GCP_API_KEY; absent ⇒ GCP silently falls back to embedded + note

	// CachedBundle is a VERIFIED reference-data bundle's pricing payload, or nil.
	//
	// ALREADY VERIFIED WHEN IT GETS HERE, and that is why it is bytes rather than a path. internal/refdata
	// owns the signature and the cache file; this package owns the table format. A pricing package that read a
	// path would be a pricing package that could load an unverified file, and the trust boundary would live in
	// two places.
	CachedBundle []byte
}

// Resolve returns the PriceProvider per cfg, discarding resolution notes.
func Resolve(cfg PriceConfig) PriceProvider {
	p, _ := ResolveWithNotes(cfg)
	return p
}

// ResolveWithNotes returns the PriceProvider AND human notes the caller stamps
// into Methodology (e.g. the GCP-fallback note). Resolution order:
//
//  1. disk cache (cfg.CacheDir, fresh within TTL) — source "cache".
//  2. live public APIs, ONLY when cfg.RefreshLive — source "live". GCP without
//     GCPAPIKey is the weak leg: it falls back to embedded with a surfaced note.
//  3. embedded snapshot (tables_gen.go) — source "embedded", the offline default.
//
// In this phase the cache and live legs are not yet implemented (no network code
// shipped), so every path returns Embedded(); the notes contract is what later
// tasks/PRs build the fetcher behind. This keeps the default deterministic and
// the open-core boundary intact.
func ResolveWithNotes(cfg PriceConfig) (PriceProvider, []string) {
	var notes []string
	if cfg.RefreshLive && cfg.GCPAPIKey == "" {
		notes = append(notes, "GCP live pricing requires SHOALCHECK_GCP_API_KEY (absent) — using embedded GCP tables")
	}
	// ---- leg 1: the disk cache, as a verified bundle ----
	//
	// Preferred over the embedded snapshot when present, because an operator who ran `shoalcheck update` asked for
	// this table. A PARSE FAILURE IS SURFACED, NOT SWALLOWED: the embedded table stays in place and a note
	// says the cache was unusable, because an operator who saw the update succeed and gets unchanged figures
	// has been told nothing.
	if len(cfg.CachedBundle) > 0 {
		p, err := FromBundle(cfg.CachedBundle, "cache")
		if err == nil {
			return p, notes
		}
		notes = append(notes, "the cached reference-data bundle could not be read by this binary, so the "+
			"embedded price table was used instead: "+err.Error())
	}

	// ---- leg 2: live fetch ----
	//
	// Deliberately absent, and absent by design rather than by omission. A refresh is never a side effect of
	// an audit: `shoalcheck update` fetches, verifies and writes the cache, and this resolver reads what it wrote.
	// A live leg here would be a fetch inside an audit, which is the one thing the channel's rules forbid
	// outright.

	// ---- leg 3: the embedded snapshot ----
	//
	// The offline, deterministic, air-gapped default. The tool is autonomous because THIS produces a correct,
	// stamped report with no network at all — fetching is a convenience on top of it.
	return Embedded(), notes
}
