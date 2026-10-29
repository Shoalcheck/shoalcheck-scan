package rules

import "github.com/Shoalcheck/shoalcheck-scan/internal/boundaries"

// boundaries.go — the claim-boundary lookup, as internal/rules exposes it.
//
// The table itself lives in internal/boundaries, which imports nothing: internal/rules imports
// internal/collect and therefore client-go, and cmd/shoalcheck-mcp may not. See that package's own comment for
// why a table of sentences ended up needing its own home.
//
// This wrapper exists so the gates can walk the registry and the table together, and so a caller inside the
// rules package asks the question in the obvious place.

// ClaimBoundariesFor returns every family boundary that applies to a rule, sorted and de-duplicated. An empty
// result is a defect, not a state: TestEveryRuleCarriesABoundary fails on one.
func ClaimBoundariesFor(ruleID string) []string { return boundaries.For(ruleID) }
