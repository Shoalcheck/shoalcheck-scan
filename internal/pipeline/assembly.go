package pipeline

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/headline"
	"github.com/Shoalcheck/shoalcheck-scan/internal/progress"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// assembly.go — what happens to a reading between the last rule and validation, as a declared graph (ENG-24, A1).
//
// WHY A GRAPH. A comment holds an order only for as long as the next person reads it, and a stage run too early states
// something false (a headline selected before the trace says "this reading recorded no session trace" over a recorder
// holding requests), so the order is not held by comments.
//
// Each stage names the keys it reads and the keys it writes. The order is derived from those declarations;
// declaration order only breaks ties. orderStages refuses a key that nothing provides, a key with two providers
// and a cycle. TestAssembly_OrderIsDerivedNotListed runs the assembly with the declarations reversed, which flips
// every tie, and requires the same bytes: a stage that reads something it did not declare fails there.
//
// A KEY IS A PART OF THE READING, not a function. "findings.pillar" is the pillar field on every finding,
// "methodology.sources.1" is the second sentence appended to Methodology.DataSources. The appends to one slice are
// chained through numbered keys because their order is the order a reader sees them in.

// assembly is what the stages share: the reading, the report under construction and the run's sinks.
type assembly struct {
	ctx          context.Context
	rd           *reading
	opts         Options
	inv          *collect.Inventory
	prog         progress.Func
	log          io.Writer
	ar           *types.AuditReport
	ropts        rules.Options
	um           *prom.UsageMethodology
	res          usageResult
	dataSrc      string
	promC        *prom.Client
	promConnNote string
}

// stage is one step of the assembly.
type stage struct {
	name     string
	needs    []string
	provides []string
	run      func(*assembly)
}

// keyReport is what every stage may read without declaring it: the report BuildReport returned, with its findings
// in report order.
const keyReport = "report"

// assemblyStages is the declaration. Its order is a tie-break, never a dependency.
var assemblyStages = []stage{
	{name: "pricing events", needs: []string{keyReport}, provides: []string{"events.pricing"}, run: func(a *assembly) {
		// The summary chip ("N of M priced") then one node_priced per pool. An unpriced pool (SKU not in the table)
		// streams Priced=false so the UI renders "unpriced", never "$0", never ticks.
		emitPricing(a.prog, a.ar)
	}},
	{name: "price basis", needs: []string{keyReport}, provides: []string{"findings.price-basis"}, run: func(a *assembly) {
		// Every finding gets a price basis before anything reads its dollar figure, because a zero in
		// DollarImpactMonthly means three different things and every reader downstream had to guess.
		classifyPriceBasis(a.ar.Findings)
	}},
	{name: "pillar", needs: []string{keyReport}, provides: []string{"findings.pillar"}, run: func(a *assembly) {
		// Which of the two headline claims each finding belongs to. The renderer may not import internal/rules, so
		// the declaration travels on the finding — see pillar.go.
		attachPillar(a.ar.Findings)
	}},
	{name: "claim boundaries", needs: []string{keyReport}, provides: []string{"findings.boundaries"}, run: func(a *assembly) {
		// What each finding does NOT establish. A conditional boundary is appended by a rule at Evaluate time and this
		// merges the family ones in after it.
		attachClaimBoundaries(a.ar.Findings)
	}},
	{name: "owner", needs: []string{keyReport}, provides: []string{"findings.owner"}, run: func(a *assembly) {
		// Who owns each finding, when the operator has told us which namespace label says so.
		attachOwner(a.ar.Findings, a.inv.Namespaces, a.opts.OwnerLabel)
	}},
	{name: "command safety", needs: []string{keyReport}, provides: []string{"findings.command-safety", "log.command-safety"},
		run: func(a *assembly) {
			// Whether each remediation command may be offered behind a one-click copy button. rules.SafeRemediationCommand
			// is the single definition of which verbs get a button. See command_safety.go.
			attachCommandSafety(a.ar, a.log)
		}},
	{name: "diagram tables", needs: []string{"findings.price-basis"}, provides: []string{"tables"}, run: func(a *assembly) {
		// The diagram tables, from the same inventory and the final findings (ENG-35, ENG-36, ENG-38).
		a.ar.Placement, a.ar.Images, a.ar.NodeVerdicts, a.ar.RBACGraph, a.ar.Capacity = rules.BuildTables(a.inv, a.ar.Findings, a.ropts)
	}},
	{name: "finding events",
		needs: []string{"events.pricing", "findings.price-basis", "findings.pillar", "findings.boundaries", "findings.owner",
			"findings.command-safety"},
		provides: []string{"events.findings"},
		run: func(a *assembly) {
			// Streamed from the FINAL, report-order findings so the running dollar counter sums to exactly the report
			// headline (validate.go enforces headline == Σ DollarImpactMonthly). One event per finding.
			for i := range a.ar.Findings {
				a.prog.FindingFound(progress.FindingEvt{Finding: &a.ar.Findings[i]})
			}
		}},
	{name: "verdict event", needs: []string{"events.findings"}, provides: []string{"events.verdict"}, run: func(a *assembly) {
		// The opinion, once — after every finding is counted, because a podium formed halfway through the stream
		// would be a guess. It is an additional event, not a reordering of the stream above.
		emitVerdict(a.prog, a.ar, a.inv.Meta.Context)
	}},
	{name: "compliance", needs: []string{keyReport}, provides: []string{"compliance"}, run: func(a *assembly) {
		// Derived here, not in collect.BuildReport: internal/rules imports internal/collect for Inventory, so collect
		// cannot import rules without a cycle. These are OBSERVATIONS mapped to controls, never an audit verdict.
		a.ar.Compliance = rules.BuildCompliance(a.ar.Findings)
		// COVERAGE IS PASSED, NOT ASSUMED. A control PASSes only when its evidence rule ran; a rule whose inputs were
		// refused returns nothing, which is indistinguishable from "found nothing" unless the assessment is told what
		// the collector actually managed to read.
		a.ar.ComplianceAssessment = rules.BuildComplianceAssessmentWithCoverage(a.ar.Findings, a.inv.Meta.HasCollected)
	}},
	{name: "usage source sentence", needs: []string{keyReport}, provides: []string{"methodology.sources.1"}, run: func(a *assembly) {
		if a.dataSrc != "" {
			a.ar.Methodology.DataSources = append(a.ar.Methodology.DataSources, a.dataSrc)
		}
	}},
	{name: "unmodelled controllers", needs: []string{"methodology.sources.1"},
		provides: []string{"methodology.sources.2", "methodology.unmodelled"}, run: func(a *assembly) {
			// What the rules do not model is said, counted, beside what they read (ENG-12).
			if u := rules.UnmodelledControllers(a.inv, a.ropts); len(u) > 0 {
				a.ar.Methodology.Unmodelled = u
				a.ar.Methodology.DataSources = append(a.ar.Methodology.DataSources, rules.UnmodelledSentence(u))
			}
		}},
	{name: "usage methodology", needs: []string{keyReport}, provides: []string{"methodology.usage"}, run: func(a *assembly) {
		a.ar.Methodology.UsageMethodology = withheldCaveat(a.um, rules.RightsizingWithheld(a.inv, a.ropts))
	}},
	{name: "run basis", needs: []string{"findings.owner"}, provides: []string{"run-basis"}, run: func(a *assembly) {
		// The settings only this layer knows. The comparison guard reads these to decide whether two readings are
		// comparable at all.
		ar := a.ar
		if ar.Methodology.RunBasis == nil {
			ar.Methodology.RunBasis = &types.RunBasis{}
		}
		ar.Methodology.RunBasis.IncludeSystem = a.opts.IncludeSystem
		// "12 of 134 findings have an owner" is the honest form; four team names with no denominator would let a
		// reader assume the rest were covered.
		if a.opts.OwnerLabel != "" {
			ar.Methodology.RunBasis.OwnerLabel = a.opts.OwnerLabel
			ar.Methodology.RunBasis.OwnerResolved, ar.Methodology.RunBasis.OwnerOwnable = ownerCoverage(ar.Findings)
		}
		ar.Methodology.RunBasis.EngineVersion = rules.EngineVersion()
		ar.Methodology.RunBasis.RuleSet = RuleSetStamp()
		if a.um != nil {
			ar.Methodology.RunBasis.UsageSource = a.um.Source
			// The tier travels with the source, always — including when it is "unproven", which is the case a reader
			// most needs to see.
			if a.res.provenance.Tier != "" {
				ar.Methodology.RunBasis.UsageTier = string(a.res.provenance.Tier)
				ar.Methodology.RunBasis.UsageProvenance = a.res.provenance.Detail
			}
		}
	}},
	{name: "service map", needs: []string{"events.verdict", "log.command-safety"}, provides: []string{"architecture", "events.map", "log.service-map"},
		run: (*assembly).serviceMap},
	{name: "stack sentence", needs: []string{"methodology.sources.2"}, provides: []string{"methodology.sources.3"}, run: func(a *assembly) {
		// What the CR reads touched (status/spec only, never Secrets) and as of when.
		a.ar.Methodology.DataSources = append(a.ar.Methodology.DataSources,
			fmt.Sprintf("Stack CRDs: read via dynamic discovery (status/spec only, no secrets) as of %s", a.ar.GeneratedAt.Format("2006-01-02")))
	}},
	{name: "finding basis", needs: []string{"run-basis", "methodology.sources.3"}, provides: []string{"findings.basis"}, run: func(a *assembly) {
		// What each finding's rule rests on, and which of those this run read. Joined here because internal/report
		// may not import internal/rules (depcheck rule 1).
		attachFindingBasis(a.ar, a.opts.Recorder != nil)
	}},
	{name: "calendar", needs: []string{"findings.basis"}, provides: []string{"calendar"}, run: func(a *assembly) {
		// Dated obligations from findings that read a date and from the cluster's minor in its provider's support
		// window, with every clock this run could not read named beside them. See calendar.go.
		a.ar.Calendar = buildCalendar(a.inv, a.ar)
	}},
	{name: "session trace", needs: []string{keyReport}, provides: []string{"trace"}, run: func(a *assembly) {
		// Before redaction on purpose: the appendix contains no identifier, and routing it through redact.Report
		// anyway is what lets a test assert the redacted and unredacted appendices are byte-identical.
		attachSessionTrace(a.ar, a.opts.Recorder, a.opts.RecorderSince, execPluginName(a.opts.Collector))
	}},
	{name: "request basis", needs: []string{"trace", "findings.basis"}, provides: []string{"findings.request-basis"}, run: func(a *assembly) {
		// Joins findings to ledger rows, which do not exist until the recorder has been read, and refines the basis
		// that put the kinds there.
		attachRequestBasis(a.ar)
	}},
	{name: "headline",
		needs: []string{"findings.price-basis", "findings.pillar", "findings.boundaries", "findings.owner", "calendar",
			"findings.request-basis", "trace", "compliance", "run-basis", "methodology.usage", "methodology.unmodelled",
			"architecture", "tables"},
		provides: []string{"headline"},
		run: func(a *assembly) {
			// At most five claims a stranger reads first, selected once so the terminal, the document and the app
			// cannot lead with different arguments. One of the five lines is the reading's own cost, so the selection
			// comes after everything it quotes.
			h := headline.SelectWith(a.ar, headline.Options{ComputeDiscount: a.opts.Discount})
			a.ar.Headline = &h
		}},
}

// serviceMap upgrades Architecture from declared to observed when a telemetry source is reachable through the
// Prometheus the usage layer used. The client is resolved once, in priority order: an explicit --prometheus-url,
// else the auto-connected client fetchUsage already built and pinged, else none and the map stays declared.
// Unreachable, a detection error or a build error each leave the report on declared — never fatal, never a
// fabricated edge. Ingress telemetry is not a mesh: it carries no service-to-service edge, so it never promotes
// the map. Exactly one MapBuilt is emitted (guard 4: the tier pill is never absent).
func (a *assembly) serviceMap() {
	ar, inv, log := a.ar, a.inv, a.log
	mapEvt := progress.MapBuilt{Tier: "declared", Window: "5m", NamespacesTotal: len(inv.Namespaces)}
	if c, connNote := a.promC, a.promConnNote; c != nil && ar.Architecture != nil {
		if src, derr := a.rd.telemetry(a.ctx, c); derr == nil && src != prom.SourceNone && src != prom.SourceIngress {
			g, gerr := a.rd.observedGraph(a.ctx, c, src)
			if gerr == nil {
				// ONE READING, ONE CLOCK: the map is dated by the clock every other field of the reading is read against.
				g.AsOf = ar.GeneratedAt
				collect.ApplyObservedGraph(ar.Architecture, promGraphAdapter{g: g})
				fmt.Fprintf(log, "service-map: %s telemetry%s — %d observed edges over %s (reporter=%s)\n",
					g.Source, connNote, len(g.Edges), g.Window, g.Reporter)
				mapEvt.Tier = "observed"
				mapEvt.Source = string(g.Source)
				mapEvt.Window = g.Window
				mapEvt.Edges = len(g.Edges)
				// Coverage the telemetry actually demonstrated (B-007).
				mapEvt.NamespacesObserved = g.NamespacesObserved
				if len(g.Edges) == 0 {
					// Mesh present, zero traffic in the window — a first-class honest state, never a blank map.
					mapEvt.Note = "mesh detected, but no service-to-service traffic in the " + g.Window + " window"
				}
			} else {
				fmt.Fprintf(log, "service-map: %s detected but graph build failed (%v); staying on declared\n", src, gerr)
				mapEvt.Note = "telemetry detected but the graph build failed — showing declared wiring"
			}
		} else if derr == nil && src == prom.SourceIngress {
			mapEvt.Note = "ingress telemetry only — no service-to-service edges; showing declared wiring"
		}
	}
	a.prog.MapReady(mapEvt)
}

// reverseStagesForTest reverses the declaration before ordering it, which flips every tie the order does not
// decide. Only internal/fixture's TestAssembly_OrderIsDerivedNotListed sets it, through ReverseAssemblyForTest.
var reverseStagesForTest bool

// ReverseAssemblyForTest is the test seam for that gate. It lives here, not in an _test.go file, because the gate
// runs in internal/fixture over the persona, and a test file's exports reach only its own package.
func ReverseAssemblyForTest(on bool) { reverseStagesForTest = on }

// assemble runs every stage in derived order.
func assemble(a *assembly) error {
	decl := assemblyStages
	if reverseStagesForTest {
		decl = make([]stage, len(assemblyStages))
		for i, s := range assemblyStages {
			decl[len(decl)-1-i] = s
		}
	}
	order, err := orderStages(decl)
	if err != nil {
		return fmt.Errorf("assembly is misdeclared (bug): %w", err)
	}
	for _, s := range order {
		s.run(a)
	}
	return nil
}

// orderStages derives a run order from the declarations: a stage runs once every key it needs is provided. Among the
// stages that are ready, the one declared first runs first. It refuses a key no stage provides, a key two stages
// provide and a cycle, naming each.
func orderStages(decl []stage) ([]stage, error) {
	provider := map[string]int{keyReport: -1}
	var problems []string
	for i, s := range decl {
		for _, k := range s.provides {
			if j, dup := provider[k]; dup {
				other := "the report itself"
				if j >= 0 {
					other = decl[j].name
				}
				problems = append(problems, fmt.Sprintf("%q is provided by both %s and %s", k, other, s.name))
				continue
			}
			provider[k] = i
		}
	}
	for _, s := range decl {
		for _, k := range s.needs {
			if _, ok := provider[k]; !ok {
				problems = append(problems, fmt.Sprintf("%s needs %q, which no stage provides", s.name, k))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	have := map[string]bool{keyReport: true}
	done := make([]bool, len(decl))
	out := make([]stage, 0, len(decl))
	for len(out) < len(decl) {
		next := -1
		for i, s := range decl {
			if done[i] {
				continue
			}
			ready := true
			for _, k := range s.needs {
				if !have[k] {
					ready = false
					break
				}
			}
			if ready {
				next = i
				break
			}
		}
		if next < 0 {
			var stuck []string
			for i, s := range decl {
				if !done[i] {
					stuck = append(stuck, s.name)
				}
			}
			return nil, fmt.Errorf("a cycle among: %s", strings.Join(stuck, ", "))
		}
		done[next] = true
		out = append(out, decl[next])
		for _, k := range decl[next].provides {
			have[k] = true
		}
	}
	return out, nil
}
