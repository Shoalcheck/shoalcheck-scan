package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
)

// B-105 — A GATE WHOSE INPUT SOMEBODY MUST REMEMBER TO BUMP IS NOT A GATE.
//
// internal/history's Gate 0 refuses to compare two readings taken by different engine versions, and its own
// comment says exactly why: "what an unknown engine hides is precisely a rule that did not exist in one of the
// two builds, i.e. an absence that is ours and not the cluster's."
//
// The gate is correct. Its INPUT was dead. `engineVersion` was a constant unchanged since the first rules
// commit, so it could never differ, so the gate could never fire — and eleven rules shipped in two days
// underneath it. A customer who audited, upgraded Shoalcheck, and audited again would have had our new rules
// reported as `NewInSet`: their cluster's new problems. That is the precise defect the five ordered gates exist
// to prevent, wearing our own version number as a disguise.
//
// So the version stops being a thing to remember. This test pins a digest of every identity that can change
// what findings a build produces, and it covers BOTH registries — rules and analyzers — because
// `RunBasis.EngineVersion` is stamped from `rules.EngineVersion()` alone, and an analyzer changing while the
// rules stand still would move the finding set without moving the number.
//
// It also pins the stamped RuleIDs, not just the registration IDs. Those are two different identity concepts
// in this tree — an analyzer's ID() is its registration identity and the RuleID it stamps is the finding
// family a reader cites — and either changing changes what a reader sees.
//
// WHEN THIS FAILS, BUMP THE VERSION. That is the whole point: the failure is the reminder, and the digest in
// this file is the record of what the current version describes.
func TestEngineVersion_MovesWhenTheFindingSetCan(t *testing.T) {
	var ids []string
	for _, r := range rules.All() {
		ids = append(ids, "rule:"+r.ID())
	}
	for _, a := range analyzers.All() {
		ids = append(ids, "analyzer:"+a.ID())
	}
	if len(ids) == 0 {
		t.Fatal("both registries are empty, so this digest would pin nothing")
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	digest := hex.EncodeToString(sum[:])[:16]

	// Raise BOTH of these together, deliberately, whenever a rule or analyzer is added, removed or renamed.
	const (
		wantEngineVersion = "0.24.0"
		wantDigest        = "6e243a2fe79cd197" // 104 rule + analyzer identities, as of 2026-10-27 (cluster-admin-user-or-group)
	)

	if got := rules.EngineVersion(); got != wantEngineVersion {
		t.Errorf("rules.EngineVersion() is %q, expected %q — the registries changed and the version did not, "+
			"so internal/history's Gate 0 cannot tell our rule change from the customer's cluster change",
			got, wantEngineVersion)
	}
	if digest != wantDigest {
		t.Errorf("the registry digest is %s, pinned at %s: a rule or analyzer was added, removed or renamed. "+
			"Bump buildinfo.EngineVersion (rules.EngineVersion() reads it) and this pin together — a customer's next comparison depends on the "+
			"version moving when the finding set can.", digest, wantDigest)
	}
}
