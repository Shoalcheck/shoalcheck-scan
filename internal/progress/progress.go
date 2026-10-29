// Package progress is the FROZEN event contract for the Glass-Box Audit live
// stream (design: docs/superpowers/specs/2026-07-03-glass-box-audit-design.md).
//
// The audit pipeline emits an ordered stream of these events at the REAL engine
// moment each fact becomes known — collection counts as list calls return,
// findings as rules fire, node prices when pricing actually runs, the map when
// it is built. The desktop app records them into a journal the theater UI
// consumes. The CLI passes no sink, so CLI behaviour is byte-identical.
//
// HONESTY CONTRACT (enforced by tests in later phases, stated here so emitters
// obey it from day one):
//   - Timestamps are stamped at Emit — never synthesized, never delayed. The UI
//     may smooth *rendering* but the journal carries true engine timing.
//   - Collected.Count is the actual list-result length; a denied kind emits
//     Unread, never a zero Collected.
//   - NodePriced is emitted for EVERY node pool: Priced=false means the SKU is
//     not in the pricing table — the UI renders "unpriced", never "$0", and it
//     never ticks the savings counter.
//   - MapBuilt.Tier is always one of observed|partial|declared; declared edges
//     carry no numbers; an ingress-only cluster stays declared.
//
// IMPORT BOUNDARY: progress imports only types (Apache-2.0). internal/pipeline
// imports it, so scripts/oss-tree.sh lists `progress` in OSS_INTERNAL.
package progress

import (
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Kind is the discriminator; exactly one payload pointer on Event is non-nil,
// selected by Kind.
type Kind string

const (
	KindCollected   Kind = "collected"
	KindUnread      Kind = "unread"
	KindNodeSeen    Kind = "node_seen"
	KindPromConnect Kind = "prom_connect"
	KindUsage       Kind = "usage"
	KindPricing     Kind = "pricing"
	KindNodePriced  Kind = "node_priced"
	KindFinding     Kind = "finding"
	KindMapBuilt    Kind = "map_built"
	KindVerdict     Kind = "verdict"
	KindComparison  Kind = "comparison"
	KindReportReady Kind = "report_ready"
	KindRunDone     Kind = "run_done"
	KindRunError    Kind = "run_error"
	KindLine        Kind = "line"
)

// Event is one journal entry. It is JSON-serialized to the UI as-is.
type Event struct {
	T    time.Time `json:"t"`
	Kind Kind      `json:"kind"`

	Collected   *Collected   `json:"collected,omitempty"`
	Unread      *Unread      `json:"unread,omitempty"`
	NodeSeen    *NodeSeen    `json:"nodeSeen,omitempty"`
	PromConnect *PromConnect `json:"promConnect,omitempty"`
	Usage       *Usage       `json:"usage,omitempty"`
	Pricing     *Pricing     `json:"pricing,omitempty"`
	NodePriced  *NodePriced  `json:"nodePriced,omitempty"`
	Finding     *FindingEvt  `json:"finding,omitempty"`
	MapBuilt    *MapBuilt    `json:"mapBuilt,omitempty"`
	Verdict     *Verdict     `json:"verdict,omitempty"`
	Comparison  *Comparison  `json:"comparison,omitempty"`
	ReportReady *ReportReady `json:"reportReady,omitempty"`
	RunDone     *RunDone     `json:"runDone,omitempty"`
	RunError    *RunError    `json:"runError,omitempty"`
	Line        *Line        `json:"line,omitempty"`
}

// Collected — a resource kind finished listing; Count is the real item count.
type Collected struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// Unread — a resource kind could not be listed; rendered as an amber row, never as a zero count.
//
// IT WAS CALLED Denied, and its comment said "typically RBAC". That guess is where the defect started: a
// list fails for six reasons, and every surface that read this event chose a permission word for all of
// them. Cause carries internal/collect.CauseOf's answer — "not permitted", "not reachable", "timed out",
// "not served by this cluster", "cause not recorded", "could not be read" — and is empty only on a stream
// written before the field existed, which a surface must render as an unexplained absence rather than as
// any particular cause.
type Unread struct {
	Kind  string `json:"kind"`
	Cause string `json:"cause,omitempty"`
}

// NodeSeen — a node pool observed at COLLECTION time (Act 1), before any pricing.
// Spec is render-ready, e.g. "4 vCPU · 16 GiB". No dollars here by design.
type NodeSeen struct {
	InstanceType string `json:"instanceType"`
	Spec         string `json:"spec"`
	Count        int    `json:"count"`
}

// PromConnect — the usage/telemetry connection resolved. Method is the disclosed
// connect mode ("service-proxy" | "port-forward" | "url"); Source names the
// backend flavour when known.
type PromConnect struct {
	Source string `json:"source"`
	Method string `json:"method"`
}

// Usage — the usage layer that powers rightsizing. Quality is the data-window
// quality label ("high"|"medium"|"low"); it is NEVER rendered as a finding's
// confidence (which means problem-certainty under the honesty policy).
type Usage struct {
	Source      string `json:"source"`
	Window      string `json:"window"`
	Aggregation string `json:"aggregation"` // e.g. "p95"
	Series      int    `json:"series"`
	Quality     string `json:"quality"`
}

// Pricing — the pricing step ran; N of M nodes had a price in the table.
type Pricing struct {
	Provider    string `json:"provider"`
	Region      string `json:"region"`
	PricedNodes int    `json:"pricedNodes"`
	TotalNodes  int    `json:"totalNodes"`
}

// NodePriced — a node pool's price (Act 2). Priced=false ⇒ SKU not in the table:
// render "unpriced", never "$0", never tick the counter. CapacityType is
// "on-demand"|"spot"|"unknown"; a spot CostMo is an UPPER BOUND.
type NodePriced struct {
	InstanceType string  `json:"instanceType"`
	Count        int     `json:"count"`
	Priced       bool    `json:"priced"`
	CostMo       float64 `json:"costMo"`
	CapacityType string  `json:"capacityType"`
}

// UsagePoint is one point of a rightsizing sparkline. Optional: absent ⇒ the UI
// draws no sparkline (honest — it never invents a series).
type UsagePoint struct {
	T     time.Time `json:"t"`
	Value float64   `json:"value"`
}

// FindingEvt carries a full finding plus an OPTIONAL usage series for a
// rightsizing sparkline. The dollar counter ticks from Finding.DollarImpactMonthly.
type FindingEvt struct {
	Finding     *types.Finding `json:"finding"`
	UsageSeries []UsagePoint   `json:"usageSeries,omitempty"`
}

// MapBuilt — the service map was built. Tier is observed|partial|declared. The
// graph BODY is fetched separately (GET /api/run/map); this event carries only
// the summary the pinned tier pill needs. Note carries an honest empty-observed
// message ("mesh present, no traffic in window") when there are 0 observed edges.
type MapBuilt struct {
	Tier               string `json:"tier"`
	Source             string `json:"source"`
	Window             string `json:"window"`
	Note               string `json:"note,omitempty"`
	NamespacesObserved int    `json:"namespacesObserved"`
	NamespacesTotal    int    `json:"namespacesTotal"`
	Edges              int    `json:"edges"`
	EdgeCap            int    `json:"edgeCap"` // 0 = uncapped
}

// Verdict — the judgment layer's opinion, emitted once after every finding has been
// streamed. ADDITIVE to the frozen contract: a consumer that does not know this kind ignores
// it and loses nothing, because every leader it names was already streamed as its own
// KindFinding event.
//
// It is deliberately a separate event rather than a reordering of the finding stream. The
// stream is a record of what was found, in the order it was found; re-sorting it once the
// opinion forms would make the cards visibly jump on a long run and would blur "here is what
// we saw" into "here is what we think". Two claims, two places.
type Verdict struct {
	// Cluster is the reading this opinion is about. A fleet emits one verdict per cluster, and with nothing to tell
	// them apart the window drew the last one as the whole fleet's — one cluster's podium, unnamed, reconciling to
	// its own findings beside a fleet total twice the size.
	Cluster string        `json:"cluster,omitempty"`
	Leaders []VerdictItem `json:"leaders"`

	// StartHere is the safest place to begin, which is frequently NOT Leaders[0]: on a real
	// cluster the most important findings often have no mechanical remediation at all. Nil
	// when nothing is safe to apply — an honest absence, never a promoted unsafe item.
	StartHere *VerdictItem `json:"startHere,omitempty"`

	// MostSevere is the reading's most severe finding when no leader is as severe — nil when the podium holds
	// it. The podium is ranked in bands, and a finding whose own text says it may not apply is ranked after
	// everything that certainly does, so three cards can leave out a reading's only critical. A podium that does
	// says which, so the most serious thing in a reading is never one a reader has to go looking for.
	MostSevere *VerdictItem `json:"mostSevere,omitempty"`

	RestCount   int     `json:"restCount"`
	RestDollars float64 `json:"restDollars"`

	// TotalDollars is every finding's impact, uncollapsed. It must equal the run's headline;
	// it travels here so the UI can show the reconciliation rather than assert it.
	TotalDollars float64 `json:"totalDollars"`

	// DollarsPriced says whether TotalDollars may be printed as a figure at all, and it travels for
	// exactly the reason the report's own flag does: a zero means three different things and the number
	// alone cannot say which. A live reading of a cluster the price table does not cover showed the app
	// printing "$0/mo identified" and "94 findings and $0/mo across all findings" — while the reading's
	// one cost finding carried priceBasis "unpriced" and the document beside it said "unpriced — excluded
	// from the total above".
	//
	// False when the total is zero AND some cost finding failed to price: the zero is then an absence of
	// knowledge, not an absence of savings. True when the total is non-zero (it came from findings that
	// priced) or when nothing failed — where zero is the honest answer.
	DollarsPriced bool `json:"dollarsPriced"`
}

// VerdictItem is one ranked finding, flattened for the UI. Score is deliberately absent: an
// invented number on screen invites an argument about the number instead of the finding.
type VerdictItem struct {
	FindingID string `json:"findingId"`
	RuleID    string `json:"ruleId"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Safety    string `json:"safety"` // safe-now | needs-review | manual
	Rationale string `json:"rationale"`
	// Band is the band the finding was ranked in, by its reader-facing name ("critical", "true now",
	// "conditional"): under band-first ranking a medium can lead a high, and the band is why.
	Band          string  `json:"band,omitempty"`
	DollarMonthly float64 `json:"dollarMonthly"`
	CollapsedFrom int     `json:"collapsedFrom"`

	// Resources, Effort and Summary are a row's facts in the finding's own terms, for a reader who acts on the
	// list rather than reads about it: how many objects it names, the rule's own estimate of the work (low,
	// medium, high), and the first sentence of why it matters, cut to 120 characters. The band prose stays in
	// Rationale.
	Resources int    `json:"resources,omitempty"`
	Effort    string `json:"effort,omitempty"`
	Summary   string `json:"summary,omitempty"`

	// Handoff is the text an operator would run to apply this one, or nil when there is nothing
	// mechanical to hand over. It travels with the item because a judgment layer that says "these
	// three, in this order" and then makes the reader go and work out how is only half an opinion.
	Handoff *HandoffView `json:"handoff,omitempty"`
}

// HandoffView is a verdict.Handoff flattened for the wire.
//
// Disruption is empty only for an additive change. It is carried separately from Summary — rather
// than folded into it — so a UI cannot render the instruction without the consequence: the two are
// one statement, and a layout that can show the first without the second will eventually do so.
type HandoffView struct {
	Class      string `json:"class"`
	Disruption string `json:"disruption,omitempty"`
	Summary    string `json:"summary"`
	Caveat     string `json:"caveat"`
	// StagedNote is non-empty when the remediation's own text documents a later step. Applying only
	// what is handed over will leave the finding in the next reading, and a reader who was not told
	// that will read a correct re-audit as a failed one.
	StagedNote string        `json:"stagedNote,omitempty"`
	Steps      []HandoffStep `json:"steps"`
}

// HandoffStep is one command the operator runs, with the reason it comes before the next.
type HandoffStep struct {
	Label   string `json:"label"`
	Command string `json:"command"`
	Why     string `json:"why"`
}

// Comparison — this run measured against the most recent earlier reading of the same cluster.
//
// The event carries the REFUSAL as a first-class state rather than as absent numbers. A run with no
// earlier reading and a run whose earlier reading turned out incomparable are different things, and
// both are different again from a run that compared and found nothing moved. A UI handed only counts
// would render all three as a row of zeroes, which reads as "nothing changed" — the one claim none of
// them supports.
// Closed is one finding present in the earlier reading and confirmed absent from this one.
//
// NAMED FOR WHAT IT IS. Shoalcheck reads two states minutes apart, so it cannot know why a finding is
// absent: the object may have been deleted, an autoscaler may have acted, a rule may not have run,
// or someone else may have changed something in the same minute. "Closed" means closed out of the
// set, not repaired — and DollarWas is an estimate that LEFT the total, not money anybody saved.
type Closed struct {
	ID       string `json:"id"`
	RuleID   string `json:"ruleId"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// DollarWas is what this finding contributed to the EARLIER reading's estimate.
	DollarWas float64 `json:"dollarWas"`
}

type Comparison struct {
	// Cluster names the cluster this comparison is OF, on a fleet run, where every cluster is compared with its
	// own previous kept reading and the window shows one line per cluster. Empty for a single reading.
	Cluster string `json:"cluster,omitempty"`
	// Comparable is false when the two readings may not be compared at all. Reason then says why, in
	// words the UI prints verbatim rather than paraphrasing.
	Comparable bool   `json:"comparable"`
	Reason     string `json:"reason,omitempty"`

	// PreviousAt is the earlier reading this one is measured against. Zero when there was none, which
	// is the baseline case and not a failure.
	PreviousAt time.Time `json:"previousAt,omitempty"`
	// HasPrevious separates "no earlier reading exists" from "an earlier reading exists but cannot be
	// compared". Without it a zero PreviousAt would have to carry both meanings.
	HasPrevious bool `json:"hasPrevious"`

	NewCount      int `json:"newCount"`
	NoLongerCount int `json:"noLongerCount"`
	// NotEvaluatedCount is how many findings the comparison declined to classify because something they
	// rest on was not readable in one of the two runs. It travels beside the other counts because a UI
	// showing them without it is telling half a truth.
	NotEvaluatedCount int `json:"notEvaluatedCount"`
	// StillPresent counts findings matched in both readings, whatever moved within them.
	StillPresent int `json:"stillPresent"`

	// NoLonger names the findings behind NoLongerCount, so a UI can point at the one the operator
	// acted on instead of printing a number and leaving them to guess.
	//
	// It is a BOUNDED sample: NoLongerCount is the truth and this is what fits on a screen, with
	// NoLongerOmitted saying how many are not listed. A list silently shorter than its own count is
	// the defect this pair exists to prevent.
	NoLonger        []Closed `json:"noLonger,omitempty"`
	NoLongerOmitted int      `json:"noLongerOmitted,omitempty"`

	// PricingCoverageChanged marks that the two readings could price a different set of node types, so a
	// dollar movement between them mixes a changed cluster with a changed price table. The theater shows
	// no money on the comparison line when this is set.
	PricingCoverageChanged bool `json:"pricingCoverageChanged,omitempty"`

	// FirstUnevaluatedReason is one example of what was missing, so the UI can be specific in one line
	// instead of sending the reader to the report.
	FirstUnevaluatedReason string `json:"firstUnevaluatedReason,omitempty"`
}

// The session trace deliberately does NOT travel on this event stream.
//
// P0 froze a ReadIssued event here with a comment saying its emitter would land in P3. The emitter turned
// out to be a typed recorder (internal/trace) with its own cursor endpoint, and keeping the event as well
// would have kept its defects: a free-form verb string with no validation, no status field, and a journal
// that routed every entry into a list the UI labelled "reads recorded" — so a recorder emitting a create
// would have been counted and displayed as a read. One typed representation, or the weaker one becomes the
// one something renders.

// ReportReady — the HTML report was rendered to Path (served at /report/<base>).
type ReportReady struct {
	// Path is the basename the local viewer serves, under a scratch directory.
	Path string `json:"path"`
	// DurablePath is the absolute path the document will still be at tomorrow, and it is the one a UI
	// states to the operator. The two are separate because the served copy is scratch: telling somebody
	// their audit is at `/report/report-20260828-...html` gives them a URL that dies with the process,
	// which is not the same as giving them their document. Empty when the caller has only the one path.
	DurablePath string `json:"durablePath,omitempty"`
}

// RunDone — terminal success event. Requests/ObjectWrites/Streams are the session-trace
// tallies (0 until P3's recorder lands); SavingsUSD MUST equal the report
// headline (reconciliation, enforced by a P3 test).
type RunDone struct {
	Requests int `json:"requests"`
	// ObjectWrites counts create/update/patch/delete against an object. It must be zero for every audit,
	// and the UI renders the read-only claim FROM this number rather than asserting it in a string.
	//
	// It replaces a field called Mutating, which could not be rendered honestly: the opt-in port-forward
	// issues `create pods/portforward`, so a run could legitimately have a non-zero "mutating" count while
	// writing nothing — and the sentence built from that field said "no create/update/patch/delete".
	ObjectWrites int `json:"objectWrites"`
	// Streams counts opt-in proxied streams. Neither a read nor an object write; reported on its own line.
	Streams    int           `json:"streams"`
	SavingsUSD float64       `json:"savingsUsd"`
	Clusters   int           `json:"clusters"`
	Duration   time.Duration `json:"duration"`
	// FreeLine, when set, is the sentence that replaces "the reading is written": this run was the free line,
	// or past its licence's cap, and nothing from it was written or kept.
	FreeLine string `json:"freeLine,omitempty"`
	// Fingerprint and Shop are what a free result's "unlock this reading" needs: the read cluster's
	// licence.ClusterFingerprint, and whether this build names a shop to send it to. Shop is false in every
	// build until the project owns one, and then no unlock is offered.
	Fingerprint string `json:"fingerprint,omitempty"`
	Shop        bool   `json:"shop,omitempty"`
	// Free is the reading's free line — internal/freeline's projection, the one the free CLI prints — set with
	// FreeLine, so a free window names the same five most serious kinds the command line does.
	Free *FreeReading `json:"free,omitempty"`
	// MoneyBasis is what SavingsUSD rests on, in the reading's opening's own words ("prometheus over 7d · list
	// price · upper bound if consolidated"), so the figure is never printed without it. Empty for a fleet.
	MoneyBasis string `json:"moneyBasis,omitempty"`
	// Notes are what the run's own log knows that its reader must: the document is written and something around it
	// was not — the reading could not be kept in the history, the document says something the copy policy does not
	// allow. The log said so and no screen did, so the window announced "The reading is written" over a reading that
	// the next one would not be compared with.
	Notes []string `json:"notes,omitempty"`
}

// FreeReading is the free line of one reading: how many findings and kinds, and the most serious kinds by a name
// that identifies no object.
type FreeReading struct {
	Total int        `json:"total"`
	Kinds int        `json:"kinds"`
	Top   []FreeKind `json:"top"`
}

// FreeKind is one kind of problem on the free line: its subject-free name, its worst severity, how many findings
// are at that severity, and how many more of the kind are lower.
type FreeKind struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Count    int    `json:"n"`
	Lower    int    `json:"lower"`
}

// RunError — terminal (or per-stage) failure. Stage is e.g. "collect"|"usage"|
// "render"; a Stage:"usage" error flips the Prometheus chip amber rather than
// aborting the run.
type RunError struct {
	Stage string `json:"stage"`
	Msg   string `json:"msg"`
}

// Line — which reading this run is, decided before it reads anything: the full reading, or the free line and
// why. It is the first event of a run.
//
// A SURFACE CANNOT LEARN THIS FROM THE LICENCE ON THE MACHINE. A valid key does not cover every cluster: a key
// bound to another one, or a plan whose cluster cap is full, reads THIS cluster on the free line. The window
// decided from the key alone, so a refused run was drawn as a full one — the podium, the map — around a stream
// the engine had already stripped. The run says which line it is on, once, before the first finding.
type Line struct {
	// Full is true when the licence covers a full reading of this cluster at this moment.
	Full bool `json:"full"`
	// Why is the licence's own sentence when a licensed copy reads this cluster on the free line — the binding,
	// or the cap, with the day a slot frees. Empty on a full reading and on a copy with no licence at all.
	Why string `json:"why,omitempty"`
}

// Func is a nil-safe event sink. The pipeline holds one; nil discards everything
// (the CLI path). All the typed constructors below funnel through Emit, which
// stamps the timestamp — so emitters never set Event.T themselves.
type Func func(Event)

// Emit stamps the wall-clock and delivers the event. Nil-safe.
func (f Func) Emit(e Event) {
	if f == nil {
		return
	}
	e.T = time.Now()
	f(e)
}

func (f Func) Collected(kind string, count int) {
	f.Emit(Event{Kind: KindCollected, Collected: &Collected{Kind: kind, Count: count}})
}

// Unread reports a resource kind whose list did not come back, WITH the reason — one of the causes
// internal/collect.CauseOf returns. The cause is never the API error text: that text carries the server's
// address and the caller's identity.
//
// It was Denied(kind) with no cause, and the two live surfaces reading it each invented one.
func (f Func) Unread(kind, cause string) {
	f.Emit(Event{Kind: KindUnread, Unread: &Unread{Kind: kind, Cause: cause}})
}
func (f Func) NodeSeen(instanceType, spec string, count int) {
	f.Emit(Event{Kind: KindNodeSeen, NodeSeen: &NodeSeen{InstanceType: instanceType, Spec: spec, Count: count}})
}
func (f Func) PromConnect(source, method string) {
	f.Emit(Event{Kind: KindPromConnect, PromConnect: &PromConnect{Source: source, Method: method}})
}
func (f Func) UsageResolved(u Usage) {
	f.Emit(Event{Kind: KindUsage, Usage: &u})
}
func (f Func) PricingRan(p Pricing) {
	f.Emit(Event{Kind: KindPricing, Pricing: &p})
}
func (f Func) NodePriced(n NodePriced) {
	f.Emit(Event{Kind: KindNodePriced, NodePriced: &n})
}
func (f Func) FindingFound(fe FindingEvt) {
	f.Emit(Event{Kind: KindFinding, Finding: &fe})
}
func (f Func) MapReady(m MapBuilt) {
	f.Emit(Event{Kind: KindMapBuilt, MapBuilt: &m})
}
func (f Func) VerdictReady(v Verdict) {
	f.Emit(Event{Kind: KindVerdict, Verdict: &v})
}

// Compared emits the comparison against the previous reading. Emitted on EVERY run, including the
// first: the UI has to be able to say "this is the baseline" rather than leave the slot empty, because
// an empty slot is indistinguishable from a failure to compare.
func (f Func) Compared(c Comparison) {
	f.Emit(Event{T: time.Now(), Kind: KindComparison, Comparison: &c})
}

func (f Func) Report(path, durablePath string) {
	f.Emit(Event{Kind: KindReportReady, ReportReady: &ReportReady{Path: path, DurablePath: durablePath}})
}
func (f Func) Done(d RunDone) {
	f.Emit(Event{Kind: KindRunDone, RunDone: &d})
}

// OnLine emits which line this run reads on. See Line.
func (f Func) OnLine(l Line) {
	f.Emit(Event{Kind: KindLine, Line: &l})
}
func (f Func) Error(stage, msg string) {
	f.Emit(Event{Kind: KindRunError, RunError: &RunError{Stage: stage, Msg: msg}})
}
