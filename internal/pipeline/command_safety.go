package pipeline

import (
	"fmt"
	"io"

	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// attachCommandSafety classifies every finding's RemediationCommand.
//
// WHY IT IS HERE. rules.SafeRemediationCommand is the single definition of which kubectl verbs this product
// will put a copy button on, and internal/report may not import internal/rules — the renderer consumes an
// assembled report (depcheck rule 1). So the verdict is computed on this side and carried on the finding,
// the same shape as Basis, PriceBasis, Requests and Pillar.
//
// It had ONE production caller before this — internal/tracker, for the ticket payload. The report's copy
// button consulted nothing, so a `kubectl delete --force` shipped behind the same one-click affordance as a
// `kubectl get`. Latent rather than live: measured on a real cluster, 21 commands and 0 rejected. Latent is
// how it survived two reports.
//
// A REJECTION IS LOGGED, not swallowed. The rejection is usually a RULE's fault — a rule that generated a
// destructive command — and that is worth someone seeing rather than silently downgrading the affordance.
func attachCommandSafety(ar *types.AuditReport, log io.Writer) {
	if ar == nil {
		return
	}
	for i := range ar.Findings {
		cmd := ar.Findings[i].RemediationCommand
		if cmd == "" {
			// No command, no verdict. Leaving it unclassified is honest: there is nothing to classify, and
			// the template renders no command block at all.
			ar.Findings[i].CommandSafety = types.CommandUnclassified
			continue
		}
		safe, reason := rules.SafeRemediationCommand(cmd)
		if safe {
			ar.Findings[i].CommandSafety = types.CommandOneClick
			continue
		}
		ar.Findings[i].CommandSafety = types.CommandByHand
		if log != nil {
			fmt.Fprintf(log, "remediation command for %s (%s) is presented for manual review rather than "+
				"one click: %s\n", ar.Findings[i].ID, ar.Findings[i].RuleID, reason)
		}
	}
}
