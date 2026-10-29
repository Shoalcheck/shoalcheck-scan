package types

// CommandSafety is whether a finding's RemediationCommand may be offered behind a one-click copy button.
//
// WHY IT IS ON THE SCHEMA AND NOT COMPUTED BY THE RENDERER. rules.SafeRemediationCommand is the single
// definition of which kubectl verbs this product is willing to put a copy button on, and internal/report may
// not import internal/rules — the renderer consumes an assembled report and does not run rules (depcheck
// rule 1). Duplicating the classifier in the renderer would make it the second copy of a safety policy,
// which is the failure internal/lexicon exists to end. So the verdict is computed once in internal/pipeline
// and carried here, the same way Basis, PriceBasis, Requests and Pillar are.
//
// THE ZERO VALUE FAILS SAFE. An unclassified command gets no button, so an assembly path that forgets to
// classify loses an affordance rather than gaining an unvetted one.
type CommandSafety string

const (
	// CommandUnclassified is the zero value: nothing has judged this command. Rendered as by-hand.
	CommandUnclassified CommandSafety = ""
	// CommandOneClick means every executable line is a verb on the safe allowlist.
	CommandOneClick CommandSafety = "one-click"
	// CommandByHand means at least one line was rejected — a destructive verb, or a command the classifier
	// does not recognise and therefore cannot vouch for. The command is still SHOWN: the operator needs to
	// know what the fix is, and hiding it would trade one bad affordance for a worse omission.
	CommandByHand CommandSafety = "by-hand"
)

// OneClick reports whether a copy button may be rendered. Written as a method so every surface asks the same
// question and the zero value cannot be read as permission by accident.
func (c CommandSafety) OneClick() bool { return c == CommandOneClick }
