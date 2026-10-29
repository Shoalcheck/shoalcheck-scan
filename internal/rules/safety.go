package rules

import (
	"fmt"
	"strings"
)

// safeVerbs are the kubectl verbs we're willing to put a one-click copy button
// on: read-only inspection plus in-place, reversible edits. `edit` is
// interactive (it opens $EDITOR and the user confirms the change), so it's
// safe-ish — never a silent destructive action.
var safeVerbs = map[string]bool{
	"get":      true,
	"describe": true,
	"patch":    true,
	"apply":    true,
	"scale":    true,
	"annotate": true,
	"label":    true,
	"set":      true,
	"rollout":  true,
	"explain":  true,
	"top":      true,
	"edit":     true,
}

// destructiveVerbs are verbs that delete data, evict workloads, change node
// scheduling, or open a shell — they must be presented as commented/manual
// documentation, never as a one-click command.
var destructiveVerbs = map[string]bool{
	"delete":   true,
	"drain":    true,
	"cordon":   true,
	"uncordon": true,
	"exec":     true,
	"cp":       true,
	"replace":  true, // notably `replace --force`; we treat all replace as manual
	"taint":    true,
}

// SafeRemediationCommand reports whether a remediation command string is
// limited to read/patch verbs we're willing to put a copy button on.
// Destructive verbs (delete, drain, cordon, exec) require the command to be
// presented as commented/manual, never one-click.
//
// Rules:
//   - A line whose first non-space character is '#' is documentation (a
//     comment / manual caveat) and is always safe.
//   - Blank lines are ignored.
//   - For each remaining (executable) line, the first recognized kubectl verb
//     must be in safeVerbs. Any destructive verb makes the whole command unsafe.
//   - A command that isn't a kubectl invocation we recognize is treated
//     conservatively as unsafe (we can't vouch for it) — except pure comments.
func SafeRemediationCommand(cmd string) (safe bool, reason string) {
	saw := false
	for _, raw := range strings.Split(cmd, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Documentation line — safe by construction, regardless of any
			// destructive verb it describes for manual execution.
			saw = true
			continue
		}
		saw = true
		if ok, reason := safeLine(line); !ok {
			return false, reason
		}
	}
	if !saw {
		// No executable or comment content at all — nothing to copy-button.
		return false, "empty command"
	}
	return true, ""
}

// safeLine classifies a single executable (non-comment, non-blank) line.
func safeLine(line string) (safe bool, reason string) {
	verb := firstKubectlVerb(line)
	if verb == "" {
		return false, fmt.Sprintf("unrecognized command (not a kubectl verb we allowlist): %q", line)
	}
	if destructiveVerbs[verb] {
		return false, fmt.Sprintf("destructive verb %q must be commented/manual, not one-click: %q", verb, line)
	}
	if !safeVerbs[verb] {
		return false, fmt.Sprintf("verb %q is not on the safe allowlist: %q", verb, line)
	}
	return true, ""
}

// firstKubectlVerb returns the kubectl subcommand verb on a line, or "" if the
// line isn't a kubectl invocation we can classify. It walks tokens after the
// `kubectl` binary, skipping global flags and their values (e.g. `-n app`,
// `--namespace=app`), and returns the first bare word — the verb.
//
// Only the leading command of the line is inspected; a pipe (`| grep ...`) or
// shell continuation after a safe verb doesn't change the classification (the
// destructive surface is the kubectl verb itself).
func firstKubectlVerb(line string) string {
	fields := strings.Fields(line)
	i := 0
	// Find the `kubectl` token (allow a leading path like /usr/bin/kubectl).
	for ; i < len(fields); i++ {
		base := fields[i]
		if slash := strings.LastIndex(base, "/"); slash >= 0 {
			base = base[slash+1:]
		}
		if base == "kubectl" {
			i++
			break
		}
		// A token before kubectl that isn't an env assignment (FOO=bar) means
		// this isn't a leading kubectl command.
		if !strings.Contains(base, "=") {
			return ""
		}
	}
	if i >= len(fields) {
		return ""
	}
	// Skip global flags and their values until we hit the verb.
	for ; i < len(fields); i++ {
		tok := fields[i]
		if strings.HasPrefix(tok, "-") {
			// `--flag=value` carries its own value; `-n` / `--namespace` take
			// the next token. Conservatively, single-token short flags that are
			// known to take a value consume the next token.
			if strings.Contains(tok, "=") {
				continue
			}
			if flagTakesValue(tok) {
				i++ // also skip the value
			}
			continue
		}
		return tok // first non-flag token after kubectl = the verb
	}
	return ""
}

// flagTakesValue reports whether a kubectl global flag consumes the next token
// as its value (so the verb scanner can skip past it).
func flagTakesValue(flag string) bool {
	switch flag {
	case "-n", "--namespace", "--context", "--cluster", "--kubeconfig",
		"--user", "--as", "--as-group", "--token", "--server", "-s":
		return true
	}
	return false
}
