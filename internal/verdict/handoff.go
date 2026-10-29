package verdict

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A handoff is the exact text an operator runs to apply one finding's remediation. It is not
// something this process does.
//
// THAT DISTINCTION IS THE WHOLE DESIGN. Shoalcheck reads; it has never issued a mutating request and the
// session trace exists to prove it. A closed loop is only worth having if it does not cost that:
// the tool produces text, a person reads it, a person runs it, and the next audit is an independent
// reading that reports whatever it finds. Nothing here executes anything, and nothing here promises
// what the next reading will say.
//
// WHY THE SET IS SMALL. Only SafeNow findings get a handoff, and SafeNow is narrow on purpose —
// safety.go's additiveYAMLMarkers is two entries long, LimitRange and ResourceQuota, because almost
// nothing in Kubernetes is restart-free. Resources, probes, security contexts and images all live in
// the pod template, so editing them rolls every pod; scaling adds pods; a PodDisruptionBudget
// changes drain behaviour. What is left are namespace-scoped objects that constrain future pods
// without disturbing running ones. The flagship rightsizing fix is deliberately NOT in this set.
type Handoff struct {
	FindingID string
	RuleID    string

	// Targets is what the manifest touches, named explicitly so a namespaced object cannot land
	// wherever the operator's current context happens to point.
	Targets []types.ResourceRef

	// YAML and Command are the rule's own text, verbatim. Regenerating either would mean the
	// operator applies something other than what the rule was written and tested against.
	YAML    string
	Command string

	// Class travels with the handoff. A UI that cannot tell an additive change from a reviewed one
	// will present them the same way, and the difference is the whole point.
	Class SafetyClass
	// Disruption says what applying this DOES, in words, and is empty only for an additive change.
	// It comes from the evidence that decided the class — a pod-template edit, a reachability
	// change, a replica change are three different sentences — never from boilerplate.
	Disruption string

	// Staged marks a remediation whose own text documents a LATER step, and StagedNote says so in
	// words. Proven necessary on the live testbed: the PSA rule sets warn and audit and documents
	// "then set enforce=baseline", so applying it exactly as handed over left the finding standing —
	// correctly, with the evidence updated to "enforce=<unset>, warn=baseline, audit=baseline". Every
	// part of that was right and the operator was still owed a sentence, because handing over the
	// first half of a two-part change without saying which half invites the reasonable conclusion
	// that the re-audit failed.
	Staged     bool
	StagedNote string

	Summary string
	Caveat  string
	Steps   []Step
}

// Step is one command the operator runs, with the reason it comes before the next one.
type Step struct {
	Label   string
	Command string
	Why     string
}

var (
	// ErrNotSafeNow — the finding's remediation restarts something, changes reachability, or is a
	// hedged suggestion rather than a change.
	ErrNotSafeNow = errors.New("only a safe-now finding gets a handoff")
	// ErrNoRemediation — the rule ships no manifest and no command, so there is nothing to hand over.
	ErrNoRemediation = errors.New("the rule ships no remediation to apply")
	// ErrNoTarget — the finding names no resource. A manifest with nowhere to go is how somebody
	// applies it to the wrong namespace.
	ErrNoTarget = errors.New("the finding names no resource to apply against")
)

// BuildHandoff assembles the handoff for one finding, or refuses with a reason.
//
// The refusals are separate errors rather than one, because "no handoff" and "no handoff because the
// rule ships no manifest" send the reader to different places.
// kubeContext is the context the audit actually ran against. It is threaded in rather than left as a
// placeholder because a copied command with "<your-context>" in it fails, and a copied command with
// NO context flag runs against whatever the operator's current context happens to be — which is the
// mistake most worth preventing in a fleet, where the last context used is rarely the one meant.
func BuildHandoff(f types.Finding, class SafetyClass, kubeContext string) (Handoff, error) {
	// Manual is refused: there is nothing mechanical to hand over, either because the rule ships no
	// change or because its own text asks the operator to work something out first.
	//
	// NeedsReview is NOT refused any more, and the reason is worth stating. The loop began restricted
	// to SafeNow, and SafeNow occurs on no real cluster: the only rule emitting an additive kind
	// ships a manifest that honestly calls itself a starting point. A feature that cannot happen is
	// worth less than one that tells the truth about a change, so a reviewed change gets a handoff
	// too — and pays for it by naming its disruption before anything else.
	if class == Manual {
		return Handoff{}, fmt.Errorf("%w: this one is %s", ErrNotSafeNow, class)
	}
	if class != SafeNow && class != NeedsReview {
		return Handoff{}, fmt.Errorf("%w: this one is %s", ErrNotSafeNow, class)
	}
	if strings.TrimSpace(f.RemediationYAML) == "" && strings.TrimSpace(f.RemediationCommand) == "" {
		return Handoff{}, ErrNoRemediation
	}
	if len(f.AffectedResources) == 0 {
		return Handoff{}, ErrNoTarget
	}

	h := Handoff{
		FindingID: f.ID,
		RuleID:    f.RuleID,
		Class:     class,
		Targets:   f.AffectedResources,
		YAML:      f.RemediationYAML,
		Command:   f.RemediationCommand,
	}

	where := targetPhrase(f.AffectedResources)
	if class == NeedsReview {
		// The disruption LEADS. A reviewed change described as "apply the manifest" with the
		// consequence further down is a change somebody applies without reading the consequence.
		_, reason := ClassifyReason(f)
		if reason == "" {
			reason = "what applying this does was not established, so treat it as disruptive."
		}
		h.Disruption = reason
		h.Summary = fmt.Sprintf("Before anything else: %s Then, against %s — check it parses, apply it, "+
			"read back what the cluster holds.", upperFirstRune(reason), where)
	} else {
		h.Summary = fmt.Sprintf("Apply the manifest this rule ships, against %s. Three commands: check it "+
			"parses, apply it, read back what the cluster now holds. Nothing running is disturbed.", where)
	}

	// The caveat is not decoration. An operator handed a cluster change is owed the limits of what
	// was checked, and the limits are real: this text was validated by decoding it against the
	// Kubernetes scheme, not by admitting it to their cluster, and their cluster has admission
	// controllers, quotas and policies this audit never saw.
	h.Caveat = "Checked by decoding the manifest against the Kubernetes API scheme — not against your " +
		"cluster's admission controllers, quotas or policies, which this read-only audit cannot see. " +
		"The dry run below is where those answer. Shoalcheck does not apply anything, and the next audit is " +
		"an independent reading: it reports what it finds rather than confirming what you did."

	if note := stagedNote(f); note != "" {
		h.Staged, h.StagedNote = true, note
	}

	ctxFlag := "--context <the-context-you-audited>"
	if kubeContext != "" {
		ctxFlag = "--context " + shellQuote(kubeContext)
	}

	if strings.TrimSpace(f.RemediationYAML) != "" {
		body := strings.TrimRight(f.RemediationYAML, "\n")
		delim := heredocDelim(body)
		h.Steps = append(h.Steps, Step{
			Label:   "Check it parses against your cluster",
			Command: fmt.Sprintf("kubectl %s apply --dry-run=server -f - <<'%s'\n%s\n%s", ctxFlag, delim, body, delim),
			Why:     "A server dry run runs your admission controllers and persists nothing, so this is where a policy or a quota objects — before anything changes.",
		})
		h.Steps = append(h.Steps, Step{
			Label:   "Apply it",
			Command: fmt.Sprintf("kubectl %s apply -f - <<'%s'\n%s\n%s", ctxFlag, delim, body, delim),
			Why:     "The same text, once the dry run came back clean. You are running this, not Shoalcheck.",
		})
	} else {
		cmd := pinContext(f.RemediationCommand, kubeContext)
		h.Steps = append(h.Steps, Step{
			Label:   "Check the command with a dry run",
			Command: addFlag(cmd, "--dry-run=server"),
			Why:     "A server dry run runs your admission controllers and persists nothing, so this is where a policy or a quota objects — before anything changes.",
		})
		h.Steps = append(h.Steps, Step{
			Label:   "Run it",
			Command: cmd,
			Why:     "The rule's own command, with the audited context pinned. You are running this, not Shoalcheck.",
		})
	}

	h.Steps = append(h.Steps, Step{
		Label:   "Read back what the cluster now holds",
		Command: readBackCommand(ctxFlag, f.AffectedResources, f.RemediationCommand),
		Why:     "A read, so you see the object rather than taking the apply's word for it. Then re-audit: the next reading is independent and reports whatever it finds.",
	})
	return h, nil
}

// shellQuote makes a context name safe to paste. EKS context names are ARNs — they carry colons and
// slashes — and an AKS clusterUser entry carries underscores; none of that needs quoting, but a name
// with a space would silently split into two arguments.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\"'\\$`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// laterStepMarkers are how a rule documents that its remediation is one move of several. They are
// read from the remediation's own text, not guessed from the rule id, so a rule that stops being
// staged stops being described as staged without anybody remembering to update a list.
var laterStepMarkers = []string{"then set", "then add", "then apply", "then switch", "then raise",
	"first, then", "breakage first", "once that", "after that", "as a second step", "then enable"}

// stagedNote returns the sentence for a remediation that documents a later step, or "".
func stagedNote(f types.Finding) string {
	hay := strings.ToLower(f.RemediationYAML + " " + f.RemediationCommand)
	for _, m := range laterStepMarkers {
		if strings.Contains(hay, m) {
			return "This is the FIRST of more than one step — the remediation's own text describes what comes " +
				"after it. Applying only this will leave the finding in the next reading, and that is the " +
				"reading being correct rather than the change failing."
		}
	}
	return ""
}

// upperFirstRune capitalises a reason so it reads as a sentence where the summary places it.
func upperFirstRune(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 32
	}
	return string(r)
}

// targetPhrase names the resources in a form an operator recognises: "namespace payments", or
// "Deployment payments/api-gateway".
func targetPhrase(refs []types.ResourceRef) string {
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		switch {
		case strings.EqualFold(r.Kind, "Namespace"):
			parts = append(parts, "namespace "+r.Name)
		case r.Namespace != "":
			parts = append(parts, fmt.Sprintf("%s %s/%s", r.Kind, r.Namespace, r.Name))
		default:
			parts = append(parts, fmt.Sprintf("%s %s", r.Kind, r.Name))
		}
		if len(parts) == 3 && len(refs) > 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(refs)-3))
			break
		}
	}
	return strings.Join(parts, ", ")
}

// heredocDelim picks a delimiter that does not appear as a standalone line in the body.
//
// The delimiter is always QUOTED at the call site — <<'DELIM' — which is what stops the shell
// expanding a manifest that contains $(...) or backticks; without that a remediation annotation
// would execute on the operator's machine with their credentials. This function handles the other
// half: a manifest carrying the delimiter on a line of its own ends the heredoc early, and
// everything after it is handed to the shell as commands. Rare, and the failure is bad enough that
// picking a name the body does not contain costs nothing.
func heredocDelim(body string) string {
	candidate := "SHOALCHECK_MANIFEST"
	for n := 0; n < 100; n++ {
		d := candidate
		if n > 0 {
			d = fmt.Sprintf("%s_%d", candidate, n)
		}
		clash := false
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == d {
				clash = true
				break
			}
		}
		if !clash {
			return d
		}
	}
	return candidate + "_X"
}

// addFlag appends a flag to a command WITHOUT putting it inside a trailing shell comment.
//
// Rules document their commands inline — the PSA rule's is followed by "# surface breakage first,
// then set enforce=baseline" — and appending to the end of that string puts the flag after the "#",
// where the shell ignores it. The step labelled "check it parses" then applied the change it claimed
// to check. Nothing about the rendered text looked wrong.
func addFlag(cmd, flag string) string {
	if strings.Contains(cmd, flag) {
		return cmd
	}
	if i := strings.Index(cmd, "#"); i >= 0 {
		head := strings.TrimRight(cmd[:i], " \t")
		return head + " " + flag + "   " + cmd[i:]
	}
	return cmd + " " + flag
}

// pinContext inserts --context into a kubectl invocation that does not already carry one, so a
// pasted command cannot land in whatever cluster happens to be current. Every kubectl stage of a
// pipeline is pinned, because the second one runs against the same ambient context as the first.
func pinContext(cmd, kubeContext string) string {
	if kubeContext == "" || strings.Contains(cmd, "--context") {
		return cmd
	}
	flag := "--context " + shellQuote(kubeContext)
	stages := strings.Split(cmd, "|")
	for i, st := range stages {
		// A comment is left alone: "kubectl" inside prose is not an invocation.
		code := st
		var comment string
		if j := strings.Index(st, "#"); j >= 0 {
			code, comment = st[:j], st[j:]
		}
		if k := strings.Index(code, "kubectl"); k >= 0 {
			code = code[:k+len("kubectl")] + " " + flag + code[k+len("kubectl"):]
		}
		stages[i] = code + comment
	}
	return strings.Join(stages, "|")
}

// readBackCommand is a GET, always. The confirmation step must not be another mutating verb.
//
// It reads what the change TOUCHED, which the target ref alone does not tell you: a Namespace target
// can mean a LimitRange was added or that labels were set, and confirming a label change by listing
// LimitRanges tells the operator nothing about whether the labels landed.
func readBackCommand(ctxFlag string, refs []types.ResourceRef, cmd string) string {
	r := refs[0]
	ns := r.Namespace
	if strings.EqualFold(r.Kind, "Namespace") {
		ns = r.Name
		if strings.Contains(cmd, " label ") || strings.Contains(cmd, " annotate ") {
			what := "labels"
			if strings.Contains(cmd, " annotate ") {
				what = "annotations"
			}
			return fmt.Sprintf("kubectl %s get namespace %s -o jsonpath='{.metadata.%s}' | tr ',' '\\n'",
				ctxFlag, ns, what)
		}
		return fmt.Sprintf("kubectl %s -n %s get limitrange,resourcequota -o yaml", ctxFlag, ns)
	}
	if ns == "" {
		return fmt.Sprintf("kubectl %s get %s %s -o yaml", ctxFlag, strings.ToLower(r.Kind), r.Name)
	}
	return fmt.Sprintf("kubectl %s -n %s get %s %s -o yaml", ctxFlag, ns, strings.ToLower(r.Kind), r.Name)
}
