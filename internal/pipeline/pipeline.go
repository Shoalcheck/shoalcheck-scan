// Package pipeline is the OSS audit pipeline: collect → rules → assemble →
// compliance → validate → (optional) redact. It produces a schema-v1
// *types.AuditReport and nothing else — no HTML, no proprietary rendering.
//
// This package is the shared spine of the open-core split. Both entry points
// call Run so they cannot drift:
//
//   - cmd/shoalcheck        (proprietary): pipeline.Run → internal/report renders HTML.
//   - cmd/shoalcheck-scan   (OSS-only):    pipeline.Run → JSON to stdout/file.
//
// IMPORT BOUNDARY: pipeline imports only Apache-2.0 packages
// (analyzers, collect, pricing, progress, prom, redact, rules, types, verdict).
// It MUST NOT import internal/report. scripts/depcheck.sh enforces this and
// scripts/oss-tree.sh builds the subset standalone; breaking either breaks the OSS build.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/divergence"
	"github.com/Shoalcheck/shoalcheck-scan/internal/headline"
	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/progress"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/redact"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
	"github.com/Shoalcheck/shoalcheck-scan/internal/verdict"
)

// Options configures a single audit run. The zero value is usable: it runs
// every rule on operator namespaces only, with no usage data and no redaction.
type Options struct {
	// Collector is the read-only cluster collector. Required.
	// Callers build it via collect.New (real cluster) or
	// collect.NewWithClient (tests / fake clientset).
	Collector *collect.Collector

	// ClusterName is the display name. When empty, Run falls back to the
	// collected context name, then "cluster".
	ClusterName string

	// Collected, when set, is handed the inventory exactly as read — after collection, before anything evaluates
	// it — once per run. `shoalcheck audit --capture` keeps it to write a capture. The callee must not modify it: the
	// rules read the same memory next. nil means nobody asked.
	Collected func(*collect.Inventory)

	// PriorReadingsFor is the caller's history, asked once the cluster's display name is known and before the
	// rules run: it returns what earlier readings recorded about the cluster's node pools, oldest-first
	// (pipeline.PriorReadings builds it from a history.Store). nil means no history is offered. It is a callback
	// rather than a value because the name a reading is stored under is decided inside Run.
	PriorReadingsFor func(clusterName string) []rules.PriorReading

	// IncludeSystem evaluates rules in system namespaces too.
	IncludeSystem bool

	// OwnerLabel is the namespace label whose value names the team that owns a finding. Empty means no owner
	// is resolved and none is invented — see owner.go for why the product does not pick the key itself.
	OwnerLabel string

	// PrometheusURL, when set, enables usage-based rightsizing. When empty,
	// Run attempts in-cluster autodiscovery and prints a port-forward hint.
	PrometheusURL string

	// UsageAuth is applied to the Prometheus endpoint (bearer/basic/orgid). Zero
	// value (AuthNone) is the in-cluster / port-forward default.
	UsageAuth prom.PromAuth

	// AutoConnect, when true and PrometheusURL is empty, resolves an in-cluster
	// Prometheus Service and connects via the API-server service-proxy using
	// RESTConfig — terminal-free. Set by the desktop app and the CLI alike, so one
	// cluster gives one reading whichever surface reads it (the CLI left it false
	// and read 151 findings and $42 where the app read 155 and $90). Auto-connect
	// NEVER fails the audit: every failure degrades to usage-less, exactly like the
	// autodiscover hint.
	AutoConnect bool

	// RESTConfig is the authenticated config for proxy/port-forward auto-connect,
	// supplied from collect.Collector.RESTConfig(). Ignored unless AutoConnect.
	RESTConfig *rest.Config

	// AllowPortForward permits the opt-in port-forward fallback (create
	// pods/portforward) when the service-proxy is blocked. Default false — the
	// pure-read service-proxy is the only path unless the operator opts in.
	AllowPortForward bool

	// Clientset is the read-only clientset used ONLY for the port-forward
	// fallback's EndpointSlice lookup, supplied by the app from the same
	// Collector. Ignored unless AutoConnect && AllowPortForward.
	Clientset kubernetes.Interface

	// Recorder counts every HTTP request the run issues, so the report and the theater can state what the
	// session did rather than assert what it would do. nil disables recording entirely and the CLI's
	// output is unchanged.
	//
	// It is threaded rather than created here because on the app path it must OUTLIVE the run: the
	// pre-flight probes issue a full collection before a run exists, and a recorder created per run would
	// present the run's number as the session total.
	Recorder *trace.Recorder

	// RecorderSince bounds the window this report may claim: only requests recorded after this sequence
	// number belong to it. The app passes the recorder's sequence at the moment the run began, so a second
	// audit in the same session does not stamp the first one's requests into its own report under the words
	// "issued while producing this report". Zero means the whole process, which is right for the CLI: one
	// process, one audit.
	RecorderSince int64

	// VPALister / MetricsLister are the opportunistic Tier-2/3 usage seams,
	// injected by cmd/shoalcheck only (kube-trust-boundary). Nil ⇒ that tier is
	// unavailable; the resolver falls through to the next tier.
	VPALister     prom.VPALister
	MetricsLister prom.MetricsLister

	// Discount is the fractional list-price discount in [0,0.9] applied to
	// spend figures. Validated by the caller; Run does not re-check it.
	Discount float64

	// PriceProvider is the price table this run reads. Nil means the embedded snapshot — the offline,
	// deterministic, air-gapped default.
	//
	// PASSED IN, NEVER RESOLVED HERE. A pipeline that resolved its own provider could read a disk cache
	// mid-audit, and "a refresh is never a side effect of an audit" would become a convention rather than a
	// property. The caller resolves once, before the run, and the run prices from what it was handed — which
	// is also what makes the report's stamp name the table it actually used.
	PriceProvider pricing.PriceProvider

	// Redact tokenizes cluster/node/namespace/workload/RBAC identifiers so the
	// report is safe to share outside the operator's trust boundary.
	Redact bool

	// Log receives human-readable progress notes (collection, prometheus,
	// redaction). nil discards them. Never carries report data.
	Log io.Writer

	// Progress, when set, receives the STRUCTURED Glass-Box live-stream events
	// (collection counts, findings with dollars, node pricing, the service map)
	// at the real engine moment each becomes known. nil discards them (the CLI
	// path). The desktop app sets it to feed the theater UI. It is emitted
	// alongside Log, never instead of it. See internal/progress.
	Progress progress.Func
}

// Run executes the audit pipeline and returns a validated AuditReport.
//
// It is cluster-free except for opts.Collector.Collect, which the caller wires
// to either a real kubeconfig or a fake clientset. The returned report has
// already passed types.AuditReport.Validate, so a non-nil error from Run is a
// real failure (collection, an unreachable explicit --prometheus-url, or — a
// bug — an invalid assembled report), not a validation footgun for the caller.
func Run(ctx context.Context, opts Options) (*types.AuditReport, error) {
	rd, err := read(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer rd.close()
	return rd.evaluate(ctx, opts, rd.inv, rd.prog, rd.log)
}

// RunWithChange reads the cluster ONCE and evaluates two inventories through the same rules, analyzers and
// assembly: the one the read returned, and a copy of it with change applied. It is what `shoalcheck gate --with`
// stands on — "the cluster now" and "the cluster with this pull request in it" — and the comparison between the
// two is only worth having if they differ by the change and by nothing else.
//
// SO EVERYTHING EXCEPT THE INVENTORY IS SHARED. One collection, one clock, one usage resolution, one temporal
// read, one price table, one set of prior readings, one session trace. Two audits a few seconds apart would differ
// by whatever the cluster did in between and by whatever a second Prometheus query returned, and the gate would
// report that difference as the pull request's.
//
// THE COPY IS TAKEN BEFORE EITHER HALF IS EVALUATED, so nothing a rule does to the inventory it reads can reach the
// other half, and the change never touches the inventory the first half is judged on.
//
// The second half is evaluated silently: no progress events and no log lines, because every line it would print
// is one the first half already printed about the same read.
func RunWithChange(ctx context.Context, opts Options, change func(*collect.Inventory) error) (now, with *types.AuditReport, err error) {
	rd, err := read(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	defer rd.close()
	changed, err := rd.inv.Clone()
	if err != nil {
		return nil, nil, err
	}
	if err := change(changed); err != nil {
		return nil, nil, err
	}
	if now, err = rd.evaluate(ctx, opts, rd.inv, rd.prog, rd.log); err != nil {
		return nil, nil, err
	}
	if with, err = rd.evaluate(ctx, opts, changed, nil, io.Discard); err != nil {
		return nil, nil, fmt.Errorf("with the change: %w", err)
	}
	return now, with, nil
}

// reading is everything a run resolves before a rule runs: the inventory, and every external input the rules and
// the assembly read beside it. Evaluating an inventory needs all of it and changes none of it.
type reading struct {
	inv *collect.Inventory
	log io.Writer
	// prog is the caller's progress sink AS read() wrapped it — every event scrubbed of terminal controls on its way
	// out — so the half that evaluates emits through the same scrub as the half that read.
	prog         progress.Func
	res          usageResult
	um           *prom.UsageMethodology
	dataSrc      string
	pp           pricing.PriceProvider
	name         string
	ropts        rules.Options
	promC        *prom.Client
	promConnNote string

	// The cluster's own telemetry, asked once per reading however many inventories are evaluated against it.
	// It is what the cluster's Prometheus OBSERVED, so it is resolved against the inventory that was read: a
	// change laid over a copy has carried no traffic yet, and a second query would only add requests.
	telemetryAsked bool
	telemetrySrc   prom.TelemetrySource
	telemetryErr   error
	graphAsked     bool
	graph          *prom.ObservedGraph
	graphErr       error
}

func (rd *reading) close() {
	if rd.res.portForward != nil {
		rd.res.portForward.Close()
	}
}

func (rd *reading) telemetry(ctx context.Context, c *prom.Client) (prom.TelemetrySource, error) {
	if !rd.telemetryAsked {
		rd.telemetryAsked = true
		rd.telemetrySrc, rd.telemetryErr = prom.DetectTelemetry(ctx, c)
	}
	return rd.telemetrySrc, rd.telemetryErr
}

func (rd *reading) observedGraph(ctx context.Context, c *prom.Client, src prom.TelemetrySource) (*prom.ObservedGraph, error) {
	if !rd.graphAsked {
		rd.graphAsked = true
		rd.graph, rd.graphErr = prom.BuildObservedGraph(ctx, c, src, "5m", collect.ResolveWorkloadID(rd.inv))
	}
	return rd.graph, rd.graphErr
}

// read is the first half of Run: collection, usage, the temporal signals, the price table and the cluster's name.
func read(ctx context.Context, opts Options) (*reading, error) {
	if opts.Collector == nil {
		return nil, fmt.Errorf("pipeline: Collector is required")
	}
	log := opts.Log
	if log == nil {
		log = io.Discard
	}
	prog := opts.Progress // nil-safe: every prog.* call no-ops when unset (CLI path)
	if emit := prog; emit != nil {
		// Every event is scrubbed of terminal controls on its way out: the live workbench draws an unpriced node's
		// instance-type label, a region label or an API error's text as it arrives, long before the reading is
		// scrubbed at the end of the run (types.SanitizeControls below).
		prog = func(e progress.Event) {
			types.SanitizeAny(&e)
			emit(e)
		}
	}

	fmt.Fprintln(log, "collecting (read-only — Secrets/ConfigMaps/env are never read)...")
	// Stream the collection ledger (Act 1): one event per resource kind as its
	// list call returns, with the real item count; a denied kind streams an amber
	// row. Set before Collect; a no-op for the CLI (prog is nil).
	opts.Collector.SetOnStep(func(kind string, count int, cause string) {
		if cause != "" {
			prog.Unread(kind, cause)
			return
		}
		prog.Collected(kind, count)
	})
	// Phase 3: thread the analyzer-registry GVR union into Collect so the
	// dynamic client lists exactly the operator CRDs an analyzer needs that are
	// ALSO served by this cluster (collect intersects wantGVRs with PresentGVRs).
	inv, err := opts.Collector.Collect(ctx, analyzers.RequiredGVRsUnion())
	if err != nil {
		prog.Error("collect", err.Error())
		return nil, fmt.Errorf("collect: %w", err)
	}
	if opts.Collected != nil {
		opts.Collected(inv)
	}
	// Node cards (Act 1) — grouped by instance type, BEFORE any pricing (no
	// dollars yet, by design; pricing lands in Act 2 as node_priced events).
	for _, ns := range nodeSeenGroups(inv.Nodes) {
		prog.NodeSeen(ns.instanceType, ns.spec, ns.count)
	}
	fmt.Fprintf(log, "collected: %s\n", strings.Join(inv.Meta.Collected, ", "))
	if len(inv.Meta.Denied) > 0 {
		// The LOCAL log keeps the API's own error text — it is the operator's own machine and they need the
		// cause. The report gets a classified cause and no error text; see collect.deniedSourceNote. The
		// wording here no longer says "access denied" either, because a refused connection is not that.
		fmt.Fprintf(log, "partial — could not read: %s\n", strings.Join(inv.Meta.Denied, "; "))
	}

	// Prometheus: verify an explicit URL (fatal if unreachable) or autodiscover.
	// usage is nil when no URL was given or metrics couldn't be fetched — the
	// rightsizing rule then no-ops honestly. dataSrc is the Methodology note.
	// res.mapClient (+ res.connectMode) surfaces the one auto-connected client so
	// the observed-service-map block below can REUSE it instead of dialing again;
	// res.portForward (when non-nil) is kept alive until after the map is built.
	res, err := fetchUsage(ctx, opts, inv, log)
	if err != nil {
		prog.Error("usage", err.Error())
		return nil, err
	}
	// The forward backing the auto-connected client stays open until the caller is done evaluating: the observed
	// map is built through it, after the rules run. reading.close ends it.
	usage, dataSrc, um := res.usage, res.dataSrc, res.methodology
	// Usage layer resolved (Act 2 chip). PromConnect fires when a live client was
	// established (service-proxy / port-forward / explicit URL); Usage carries the
	// window + aggregation + series count that back the rightsizing dollars. When
	// no source resolved, um.Source == "none" and no usage chip lights — honest.
	if res.connectMode != "" || res.mapClient != nil {
		prog.PromConnect(um.Backend, res.connectMode)
	}
	if um != nil && um.Source != "" && um.Source != "none" {
		prog.UsageResolved(progress.Usage{
			Source:      um.Source,
			Window:      um.Window,
			Aggregation: usageAggregation(um.Source),
			Series:      len(usage),
			Quality:     string(um.Confidence),
		})
	}

	// THE TEMPORAL AXIS — the signals only the second data source can produce. Resolved here, before the
	// rules run, because they read it through rules.Options like usage.
	//
	// The client is mapClient's, resolved ONCE and reused by the observed-map block below rather than
	// dialled twice. The gate is res.provenance: FetchTemporal returns nil for anything short of a source
	// PROVEN to be this cluster's, so Tier 1b — a Prometheus answered and nothing establishes whose it is —
	// produces no temporal claim at all. That is B-145's lesson applied before the defect rather than after:
	// a temporal sentence built on another cluster's series is wrong the same way a dollar figure is, and
	// reads more confidently.
	promC, promConnNote := mapClient(opts, res)
	temporal, terr := prom.FetchTemporal(ctx, promC, res.provenance)
	if terr != nil {
		// NOT FATAL, AND NOT SILENT. Usage already succeeded against this source; a failing ALERTS or
		// up{} query means this Prometheus does not serve that series (a plain remote-write receiver
		// often does not), which is a coverage fact rather than a run failure. The rules stay silent and
		// the methodology says why.
		fmt.Fprintf(log, "temporal: %v — alert, throttling and scrape signals not assessed\n", terr)
		temporal = nil
	}
	if temporal != nil {
		fmt.Fprintf(log, "temporal: %s firing, %s with throttling series, "+
			"%d of %d scrape targets down\n", nWord(len(temporal.Alerts), "alerting rule", "alerting rules"), nWord(len(temporal.Throttling), "container", "containers"), temporal.Scrape.Down, temporal.Scrape.Up+temporal.Scrape.Down)
	}

	// THE PROVIDER IS RESOLVED ONCE, HERE, AND EVERY DOLLAR ON THE PAGE COMES FROM IT — the rules' and the
	// headline's alike. It used to be resolved after the rules had already priced everything from the
	// embedded tables, which is how a refreshed bundle could move the cover and not the findings.
	pp := opts.PriceProvider
	if pp == nil {
		pp = pricing.Embedded()
	}
	// The display name is decided here, before the rules run, so history can be asked about the right cluster.
	name := opts.ClusterName
	if name == "" {
		if inv.Meta.Context != "" {
			name = inv.Meta.Context
		} else {
			name = "cluster"
		}
	}
	// The window the usage ACTUALLY covers travels with the usage: prom's provider measures it, and
	// without it the rules printed the span their queries ask for — a "7d p95" over an hour of
	// history, beside a methodology block that said 1h (M-127).
	usageWindow := ""
	if um != nil {
		usageWindow = um.Window
	}
	ropts := rules.Options{IncludeSystem: opts.IncludeSystem, Usage: usage, UsageWindow: usageWindow, Temporal: temporal, Prices: pp}
	if opts.PriorReadingsFor != nil {
		ropts.PriorReadings = opts.PriorReadingsFor(name)
	}
	return &reading{inv: inv, log: log, prog: prog, res: res, um: um, dataSrc: dataSrc, pp: pp, name: name, ropts: ropts,
		promC: promC, promConnNote: promConnNote}, nil
}

// evaluate is the second half of Run over one inventory: rules, analyzers, assembly, compliance, the basis and
// trace joins, the headline, validation and redaction. prog and log are the caller's, so a second evaluation of
// the same reading can stay silent.
func (rd *reading) evaluate(ctx context.Context, opts Options, inv *collect.Inventory, prog progress.Func, log io.Writer) (*types.AuditReport, error) {
	pp, name, um, dataSrc, res, ropts := rd.pp, rd.name, rd.um, rd.dataSrc, rd.res, rd.ropts
	promC, promConnNote := rd.promC, rd.promConnNote
	var findings []types.Finding
	for _, r := range rules.All() {
		findings = append(findings, r.Evaluate(inv, ropts)...)
	}

	// Stack analyzers run on the SAME inventory and merge into the SAME findings
	// slice that feeds BuildReport/BuildCompliance/Validate/redact. Each is gated
	// on inv.PresentGVRs so an absent operator emits nothing — no 404 List, no
	// "not found" noise, no fabricated PASS.
	// analyzers.RunAll, not a loop here: internal/e2e needs the same one, and it had been walking
	// rules.All() alone — so the analyzer path was never exercised against a real API server by anything.
	findings = append(findings, analyzers.RunAll(inv)...)

	ar := collect.BuildReport(inv, findings, name, opts.Discount, pp)
	// The checks a person would make by hand to cover the same ground: every rule above ran, over every
	// object of every kind it reads.
	countPairs(ar.Methodology.Volume, FindingDependencies())
	// Region-coverage pre-flight: warn LOUDLY when the audited cluster's cloud
	// region has no node prices in the tables. BuildReport already suppressed the
	// misleading near-zero headline into the honest $0/unpriced state; this
	// surfaces the reason to the operator so it's caught before a paid run.
	warnIfRegionUnpriced(log, ar.Cluster.Provider, ar.Cluster.Region)
	// Pricing landed (Act 2): the summary chip ("N of M priced") then one
	// node_priced per pool. An unpriced pool (SKU not in the table) streams
	// Priced=false so the UI renders "unpriced", never "$0", never ticks.
	emitPricing(prog, ar)
	// Every finding gets a price basis before anything reads its dollar figure, because a zero in
	// DollarImpactMonthly means three different things and every reader downstream had to guess.
	classifyPriceBasis(ar.Findings)
	// And which of the two headline claims it belongs to. The renderer may not import internal/rules, so the
	// declaration travels on the finding — see pillar.go.
	attachPillar(ar.Findings)
	// And what each finding does NOT establish. After the rules have run, because a CONDITIONAL boundary is
	// appended by a rule at Evaluate time and this merges the family ones in on top of it.
	attachClaimBoundaries(ar.Findings)
	// And who owns each one, when the operator has told us which namespace label says so.
	attachOwner(ar.Findings, inv.Namespaces, opts.OwnerLabel)
	// And whether each remediation command may be offered behind a one-click copy button. Same reason the
	// two above are here: the renderer may not import internal/rules, and rules.SafeRemediationCommand is
	// the single definition of which verbs get a button. See command_safety.go.
	attachCommandSafety(ar, log)
	// Finding cards (Act 2): streamed from the FINAL, report-order findings so the
	// running dollar counter sums to exactly the report headline (validate.go
	// enforces headline == Σ DollarImpactMonthly). One event per finding.
	for i := range ar.Findings {
		prog.FindingFound(progress.FindingEvt{Finding: &ar.Findings[i]})
	}
	// The opinion, once — after every finding is counted, because a podium formed halfway
	// through the stream would be a guess. It is an additional event, not a reordering of the
	// stream above: the stream records what was found in the order found, and this records what
	// we think about it. Blurring the two would cost the stream its evidentiary value.
	emitVerdict(prog, ar, inv.Meta.Context)
	// Compliance is derived here, not in collect.BuildReport: internal/rules
	// imports internal/collect for Inventory, so collect cannot import rules
	// without a cycle. These are OBSERVATIONS mapped to controls, never an
	// audit verdict — the renderer reframes Status="gap" as "Potential gap".
	ar.Compliance = rules.BuildCompliance(ar.Findings)
	// COVERAGE IS PASSED, NOT ASSUMED. A control PASSes only when its evidence rule ran; a rule whose inputs
	// were refused returns nothing, which is indistinguishable from "found nothing" unless the assessment is
	// told what the collector actually managed to read. Without this, a cluster whose auditor Role omits
	// `clusterroles` would report "5.1.2 Minimize access to secrets: PASS".
	ar.ComplianceAssessment = rules.BuildComplianceAssessmentWithCoverage(ar.Findings, inv.Meta.HasCollected)
	if dataSrc != "" {
		ar.Methodology.DataSources = append(ar.Methodology.DataSources, dataSrc)
	}
	ar.Methodology.UsageMethodology = um
	// Complete the run basis with the settings only this layer knows. The comparison guard reads
	// these to decide whether two readings are comparable at all: a run with usage and one without
	// produce different rule populations, and a run that skipped system namespaces produces findings
	// that appear and vanish wholesale from the setting rather than from the cluster.
	if ar.Methodology.RunBasis == nil {
		ar.Methodology.RunBasis = &types.RunBasis{}
	}
	ar.Methodology.RunBasis.IncludeSystem = opts.IncludeSystem
	// The owner label and what it reached. "12 of 134 findings have an owner" is the honest form; four team
	// names with no denominator would let a reader assume the rest were covered.
	if opts.OwnerLabel != "" {
		ar.Methodology.RunBasis.OwnerLabel = opts.OwnerLabel
		ar.Methodology.RunBasis.OwnerResolved, ar.Methodology.RunBasis.OwnerOwnable = ownerCoverage(ar.Findings)
	}
	ar.Methodology.RunBasis.EngineVersion = rules.EngineVersion()
	ar.Methodology.RunBasis.RuleSet = RuleSetStamp()
	if um != nil {
		ar.Methodology.RunBasis.UsageSource = um.Source
		// The tier travels with the source, always — including when it is "unproven", which is the case
		// a reader most needs to see. An absent field would read as "not applicable" and this is the one
		// state where absence and unproven must not look alike.
		if res.provenance.Tier != "" {
			ar.Methodology.RunBasis.UsageTier = string(res.provenance.Tier)
			ar.Methodology.RunBasis.UsageProvenance = res.provenance.Detail
		}
	}
	// Observed service map: if a telemetry source is reachable through the SAME
	// Prometheus the usage layer used, upgrade Architecture from Tier-3 declared to
	// observed. The client is resolved once, in priority order:
	//   1. explicit --prometheus-url (its own 30s-budget client for the heavier
	//      mesh aggregation);
	//   2. else the auto-connected client (service-proxy / opt-in port-forward)
	//      that fetchUsage already built and Pinged — ONE connection powers both
	//      usage-$ and the map, and adds no new RBAC (same kubeconfig + opt-in
	//      role the usage path already used);
	//   3. else none ⇒ stay on declared.
	// Mirrors fetchUsage's degrade-gracefully contract: unreachable, detection
	// error, or build error each leave the report on declared — never fatal,
	// never a fabricated edge.
	// SourceIngress (nginx/envoy ingress) is detected for completeness but is NOT
	// a service mesh: it carries no service-to-service edge telemetry, so it must
	// never promote Architecture to "observed" or be reported as "mesh present".
	// Excluding it here leaves an ingress-only cluster honestly on TierDeclared.
	// mapEvt defaults to the honest declared tier; the observed path below upgrades
	// it. Exactly one MapBuilt is emitted (guard 4: the tier pill is never absent).
	mapEvt := progress.MapBuilt{Tier: "declared", Window: "5m", NamespacesTotal: len(inv.Namespaces)}
	if c, connNote := promC, promConnNote; c != nil && ar.Architecture != nil {
		if src, derr := rd.telemetry(ctx, c); derr == nil && src != prom.SourceNone && src != prom.SourceIngress {
			g, gerr := rd.observedGraph(ctx, c, src)
			if gerr == nil {
				// ONE READING, ONE CLOCK. The graph was dated by the wall clock inside BuildObservedGraph, so a
				// reading taken at one moment said its traffic was observed at another — the sample, read on 15
				// September, said "as of" the day it was regenerated. The map is the reading's: it is dated by the
				// clock every other field of it is read against.
				g.AsOf = ar.GeneratedAt
				collect.ApplyObservedGraph(ar.Architecture, promGraphAdapter{g: g})
				fmt.Fprintf(log, "service-map: %s telemetry%s — %d observed edges over %s (reporter=%s)\n",
					g.Source, connNote, len(g.Edges), g.Window, g.Reporter)
				mapEvt.Tier = "observed"
				mapEvt.Source = string(g.Source)
				mapEvt.Window = g.Window
				mapEvt.Edges = len(g.Edges)
				// Coverage the telemetry actually demonstrated. Left unassigned until
				// B-007, this always emitted 0 beside a non-zero edge count — a contract
				// field that promised observation coverage and understated it.
				mapEvt.NamespacesObserved = g.NamespacesObserved
				if len(g.Edges) == 0 {
					// Mesh present, zero traffic in the window — a first-class honest
					// state, never a blank map (guard 4).
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
	prog.MapReady(mapEvt)

	// Stack-analyzer DataSources note: honestly state what the CR reads touched
	// (status/spec only, never Secrets) and as-of when. GeneratedAt is stamped by
	// BuildReport above.
	ar.Methodology.DataSources = append(ar.Methodology.DataSources,
		fmt.Sprintf("Stack CRDs: read via dynamic discovery (status/spec only, no secrets) as of %s", ar.GeneratedAt.Format("2006-01-02")))
	// The coverage basis of every finding: what its rule rests on, and which of those this run read. Computed
	// here because internal/report may not import internal/rules (depcheck rule 1), so the join has to happen on
	// the pipeline side and travel on the schema.
	attachFindingBasis(ar, opts.Recorder != nil)
	// Things with a clock: dated obligations from findings that read a date and from the cluster's minor in its
	// provider's support window, with every clock this run could not read named beside them. See calendar.go.
	ar.Calendar = buildCalendar(inv, ar)

	// Attached BEFORE redaction on purpose. The appendix contains no identifier, so redaction has nothing to
	// do to it — and routing it through redact.Report anyway is what lets a test assert the redacted and
	// unredacted appendices are byte-identical. Attaching afterwards would make that test trivially true and
	// therefore worthless.
	attachSessionTrace(ar, opts.Recorder, opts.RecorderSince, execPluginName(opts.Collector))
	// AFTER the trace, necessarily: this joins findings to ledger rows, and the rows do not exist until the
	// recorder has been read. It is also after attachFindingBasis, because it refines the basis that put the
	// kinds there. Both orderings are load-bearing and a test asserts the join is non-empty on a real run.
	attachRequestBasis(ar)

	// The opening: at most five claims a stranger reads first, selected once here so the terminal, the document
	// and the app cannot lead with different arguments.
	//
	// LAST ON PURPOSE, and a live run is what proved it has to be. Selected beside the calendar — three lines
	// earlier — every run printed "this reading recorded no session trace" while the recorder held 84 requests,
	// because attachSessionTrace had not run yet. One of the five lines is the reading's own cost, so the
	// selection has to come after everything it quotes: the pillars, the calendar, the basis join and the trace.
	h := headline.SelectWith(ar, headline.Options{ComputeDiscount: opts.Discount})
	ar.Headline = &h

	// Strip the control bytes a terminal acts on from every string the cluster supplied — a finding title, an
	// evidence line, a resource name — BEFORE the reading is validated, kept or rendered. The report escapes
	// these for HTML, but `shoalcheck findings`/`explain`/the table print them to a terminal that interprets
	// them, where an attacker's condition message could clear the screen or paint a fake clean verdict. One
	// strip here covers every sink: the reading itself is clean, not each renderer's copy.
	types.SanitizeControls(ar)

	if err := ar.Validate(); err != nil {
		prog.Error("validate", err.Error())
		return nil, fmt.Errorf("assembled report failed validation (bug): %w", err)
	}

	// THE IDENTITY THE LICENCE COUNTS, recorded before redaction can tokenize it. Never serialized; see
	// types.AuditReport.Identity for the double charge and the refused bound key this prevents.
	ar.Identity = &types.ReadingIdentity{ClusterName: ar.Cluster.Name, Context: inv.Meta.Context}
	if rb := ar.Methodology.RunBasis; rb != nil {
		ar.Identity.ClusterUID = rb.ClusterUID
	}

	// Redaction is applied AFTER Validate (which needs the real summary) and
	// BEFORE return, so every downstream sink (JSON, HTML) sees tokenized names.
	if opts.Redact {
		ar = redact.Report(ar)
		fmt.Fprintln(log, "redaction: cluster/node/namespace/workload/RBAC identifiers tokenized")
	}

	return ar, nil
}

// hasAllAnalyzerGVRs reports whether every GVR an analyzer needs is in the
// server's present set. An HPA-style analyzer with no RequiredGVRs always runs.
// Kept local so the pipeline doesn't reach into an unexported analyzers func.
// warnIfRegionUnpriced emits a prominent stderr WARNING when the cluster's cloud
// provider is recognized (EKS/AKS/GKE) but its REGION has no node prices in the
// tables — the case that would otherwise show a misleadingly empty/near-zero
// cost headline (e.g. an AKS cluster in francecentral). BuildReport has already
// suppressed the headline into the honest $0/unpriced state; this names the
// reason and points at the fix so it's never missed before a paid run. It is a
// no-op for covered regions and for non-cloud providers (kind/onprem/unknown),
// which have no cloud region semantics.
func warnIfRegionUnpriced(log io.Writer, provider, region string) {
	switch provider {
	case "eks", "aks", "gke":
	default:
		return
	}
	if pricing.RegionCovered(provider, region) {
		return
	}
	fmt.Fprintf(log,
		"WARNING: no pricing table for %s/%s — cost figures are UNPRICED, not $0. "+
			"Cost headline suppressed. Add the region to internal/pricing or footnote it before a paid run.\n",
		provider, region)
	if covered := pricing.CoveredRegions(provider); len(covered) > 0 {
		fmt.Fprintf(log, "         (priced %s regions: %s)\n", provider, strings.Join(covered, ", "))
	}
}

// --- Glass-Box live-stream emission helpers --------------------------------

// nodeSeenGroup is one instance-type group for the Act-1 node cards.
type nodeSeenGroup struct {
	instanceType string
	spec         string
	count        int
}

// nodeSeenGroups groups collected nodes by instance type for the Act-1 node
// cards, BEFORE any pricing (no dollars yet — pricing lands as node_priced in
// Act 2). Spec is a render-ready "N vCPU · M GiB" from advertised capacity.
// Deterministic order (sorted by instance type) keeps the stream stable.
func nodeSeenGroups(nodes []corev1.Node) []nodeSeenGroup {
	type agg struct {
		spec  string
		count int
	}
	byType := map[string]*agg{}
	for i := range nodes {
		it := nodeInstanceType(&nodes[i])
		a := byType[it]
		if a == nil {
			a = &agg{spec: nodeSpec(&nodes[i])}
			byType[it] = a
		}
		a.count++
	}
	out := make([]nodeSeenGroup, 0, len(byType))
	for it, a := range byType {
		out = append(out, nodeSeenGroup{instanceType: it, spec: a.spec, count: a.count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].instanceType < out[j].instanceType })
	return out
}

// nodeInstanceType reads the node's instance type from the GA (then beta) label,
// or "unknown" when unlabelled — NEVER guessed.
func nodeInstanceType(n *corev1.Node) string {
	for _, k := range []string{"node.kubernetes.io/instance-type", "beta.kubernetes.io/instance-type"} {
		if v := n.Labels[k]; v != "" {
			return v
		}
	}
	return "unknown"
}

// nodeSpec renders "N vCPU · M GiB" from the node's advertised capacity.
func nodeSpec(n *corev1.Node) string {
	cpu := n.Status.Capacity.Cpu()
	mem := n.Status.Capacity.Memory()
	gib := float64(mem.Value()) / (1024 * 1024 * 1024)
	return fmt.Sprintf("%s vCPU · %.0f GiB", cpu.String(), gib)
}

// emitPricing streams the Act-2 pricing from the assembled report: one
// node_priced per pool, then the "N of M priced" summary. A pool whose SKU is
// absent from the pricing table streams Priced=false (CostMo 0) so the UI shows
// "unpriced" — never "$0", never a counter tick (honesty guard 3).
// verdictLeaders is how many findings the podium shows. Three, because the point of the
// judgment layer is that a client can hold the answer in their head — a top ten is another
// list.
const verdictLeaders = 3

// emitVerdict runs the judgment layer over the FINAL findings and emits one Verdict event.
//
// It reads ar.Findings (the same slice the report renders and validate.go reconciles against),
// so the podium can never disagree with the report about what exists or what it costs.
func emitVerdict(prog progress.Func, ar *types.AuditReport, kubeContext string) {
	if ar == nil || len(ar.Findings) == 0 {
		return
	}
	replicas := verdict.ReplicasFromArchitecture(ar.Architecture)
	sel := verdict.SelectWith(ar.Findings, verdictLeaders, replicas)
	evt := progress.Verdict{
		Cluster:       ar.Cluster.Name,
		RestCount:     sel.RestCount,
		RestDollars:   sel.RestDollars,
		TotalDollars:  sel.TotalDollars,
		DollarsPriced: types.DollarsAreAMeasurementForReading(ar),
	}
	for _, r := range sel.Top {
		evt.Leaders = append(evt.Leaders, verdictItem(r, kubeContext))
	}
	if sel.StartHere != nil {
		it := verdictItem(*sel.StartHere, kubeContext)
		evt.StartHere = &it
	}
	// Named, not handed over: the line says what the podium left out and why; its commands are in the queue.
	if m := verdict.MostSevereLeftOut(sel.Top, verdict.RankAll(ar.Findings, replicas)); m != nil {
		it := verdictItem(*m, kubeContext)
		it.Handoff = nil
		evt.MostSevere = &it
	}
	prog.VerdictReady(evt)
}

// verdictItem flattens a Ranked for the wire. Score is deliberately dropped — see
// progress.VerdictItem.
func verdictItem(r verdict.Ranked, kubeContext string) progress.VerdictItem {
	return progress.VerdictItem{
		FindingID:     r.Finding.ID,
		RuleID:        r.Finding.RuleID,
		Title:         r.Finding.Title,
		Severity:      string(r.Finding.Severity),
		Safety:        string(r.Safety),
		Rationale:     r.Rationale,
		Band:          r.Tier.Label(),
		DollarMonthly: r.Finding.DollarImpactMonthly,
		CollapsedFrom: r.CollapsedFrom,
		Resources:     len(r.Finding.AffectedResources),
		Effort:        string(r.Finding.EstimatedEffort),
		Summary:       verdict.SummaryLine(r.Finding, 120),
		Handoff:       handoffView(r, kubeContext),
	}
}

// handoffView attaches the text an operator would run, or nothing.
//
// A judgment layer that says "these three, in this order" and then leaves the reader to work out
// how is half an opinion. The refusal is silent on purpose: a finding with nothing mechanical to
// hand over gets no handoff and no apology, because "no safe command exists for this" is already
// what the safety class says, and repeating it as an error would put a failure where a fact belongs.
func handoffView(r verdict.Ranked, kubeContext string) *progress.HandoffView {
	h, err := verdict.BuildHandoff(r.Finding, r.Safety, kubeContext)
	if err != nil {
		return nil
	}
	v := &progress.HandoffView{
		Class:      string(h.Class),
		Disruption: h.Disruption,
		Summary:    h.Summary,
		Caveat:     h.Caveat,
		StagedNote: h.StagedNote,
	}
	for _, st := range h.Steps {
		v.Steps = append(v.Steps, progress.HandoffStep{Label: st.Label, Command: st.Command, Why: st.Why})
	}
	return v
}

func emitPricing(prog progress.Func, ar *types.AuditReport) {
	if ar == nil || ar.Architecture == nil {
		return
	}
	priced, total := 0, 0
	for _, p := range ar.Architecture.NodePools {
		total += p.Count
		isPriced := p.CostMo > 0
		if isPriced {
			priced += p.Count
		}
		prog.NodePriced(progress.NodePriced{
			InstanceType: p.Type,
			Count:        p.Count,
			Priced:       isPriced,
			CostMo:       p.CostMo,
			CapacityType: string(p.Capacity),
		})
	}
	prog.PricingRan(progress.Pricing{
		Provider:    ar.Cluster.Provider,
		Region:      ar.Cluster.Region,
		PricedNodes: priced,
		TotalNodes:  total,
	})
}

// usageAggregation maps the usage SOURCE to the aggregation label shown on the chip.
//
// It keys on the source, not on the window string. The Tier-1 Prometheus path is a
// windowed p95 whatever span the data supports; Tier 2/3 (VPA recommendations,
// metrics.k8s.io) are instantaneous snapshots with no aggregation to name. This used to
// test `window == "7d"` as a stand-in for "Tier 1", which worked only while the window was
// a hard-coded constant — the moment Methodology began reporting the honest span, a young
// Prometheus reported "15m" and the p95 label silently disappeared even though the
// aggregation had not changed.
func usageAggregation(source string) string {
	if source == "prometheus" {
		return "p95"
	}
	return ""
}

// FleetOptions audits multiple clusters into one FleetReport. The zero value
// is not usable: Contexts must name at least one kube context to audit.
type FleetOptions struct {
	// Kubeconfig is the path to the kubeconfig used for every context. Empty
	// means the standard client-go loading rules.
	Kubeconfig string

	// Contexts are the explicit kube contexts to audit, one cluster each. Each
	// context is passed through friendlyClusterName to derive the cluster's
	// display name (Options.ClusterName): an EKS ARN or GKE context is reduced
	// to its bare cluster name, everything else is used as-is.
	Contexts []string

	// PrometheusURL is applied to EVERY cluster, best-effort. A single shared
	// URL (e.g. one `kubectl port-forward` to a local 9090) is the common demo
	// case. Real multi-cluster Prometheus needs per-cluster URLs; that is NOT
	// modeled here — a cluster whose Prometheus is unreachable simply yields no
	// usage-based rightsizing for that cluster and does not fail the fleet.
	//
	// ONE URL ACROSS N CLUSTERS IS UNPROVEN FOR AT LEAST N-1 OF THEM, and since B-145 the product acts
	// on that rather than describing it.
	//
	// This comment used to read "pointing it at one cluster's Prometheus will (best-effort) attribute
	// that one endpoint's series to every cluster's rightsizing" — a limitation stated in a comment
	// nobody reading the report would ever see. RunFleet calls Run per cluster, Run proves the source
	// against THAT cluster's own pod UIDs, and a cluster whose pods are not in the source fails
	// containment. So usage is now withheld per cluster, with the reason, and only the cluster the
	// endpoint actually belongs to keeps its figures.
	//
	// Per-cluster runs remain better; they are no longer the difference between a right number and a
	// wrong one.
	PrometheusURL string

	// IncludeSystem evaluates rules in system namespaces too, for every cluster.
	IncludeSystem bool

	// Discount is the fractional list-price discount in [0,0.9] applied to spend
	// figures for every cluster. Validated by the caller.
	Discount float64

	// Redact tokenizes identifiers in every cluster's report so the fleet is
	// safe to share outside the operator's trust boundary.
	Redact bool

	// AutoConnect resolves each cluster's in-cluster Prometheus via the
	// API-server service-proxy using THAT cluster's own RESTConfig (built fresh
	// per context below). Set by the desktop app and the CLI alike. When
	// both PrometheusURL and AutoConnect are set, the explicit URL wins in
	// fetchUsage (its branch is first), so a shared --prometheus-url demo is
	// unchanged.
	AutoConnect bool

	// AllowPortForward permits the opt-in port-forward fallback per cluster.
	AllowPortForward bool

	// Recorder counts every HTTP request the fleet run issues. One recorder is shared across clusters and
	// labelled per context via SetCluster, which is correct because the fleet loop is sequential; a
	// parallel fleet would need one per cluster.
	Recorder *trace.Recorder

	// Log receives human-readable progress notes, including per-cluster skip
	// warnings. nil discards them.
	Log io.Writer

	// Progress, when set, receives the structured Glass-Box live-stream events for
	// every cluster (they interleave by cluster in fleet order). nil discards them.
	// See Options.Progress and internal/progress.
	Progress progress.Func

	// PriorReadingsFor is Options.PriorReadingsFor, asked for every cluster of the fleet. A fleet's members are
	// kept in the history one per cluster, as a single reading is, so each is offered its own earlier readings
	// as a single reading is. nil offers none.
	PriorReadingsFor func(clusterName string) []rules.PriorReading
}

// RunFleet audits every context in opts.Contexts into a single FleetReport.
//
// ROBUSTNESS: a fleet of the reachable clusters is still useful, so one cluster
// failing (unreachable, auth denied, collection error) does NOT abort the run —
// it is logged and skipped, and the audit continues with the rest. RunFleet
// returns an error only when EVERY cluster fails or when no contexts were given.
//
// The returned FleetReport is stamped SchemaVersion "v1" and GeneratedAt now,
// then Validate()d before return; a validation failure is returned as an error.
//
// Prometheus is shared across clusters best-effort — see FleetOptions.PrometheusURL.
func RunFleet(ctx context.Context, opts FleetOptions) (*types.FleetReport, error) {
	log := opts.Log
	if log == nil {
		log = io.Discard
	}
	if len(opts.Contexts) == 0 {
		return nil, errors.New("fleet: at least one --context is required")
	}

	var (
		reports  []*types.AuditReport
		failures []error
		skipped  []types.SkippedCluster
	)
	for _, kctx := range opts.Contexts {
		fmt.Fprintf(log, "fleet: auditing context %q...\n", kctx)
		var copts []collect.Option
		if opts.Recorder != nil {
			opts.Recorder.SetCluster(friendlyClusterName(kctx))
			copts = append(copts, collect.WithTransportRecorder(opts.Recorder))
		}
		// The run's stop ends every request of every cluster, discovery included (collect.WithStop).
		copts = append(copts, collect.WithStop(ctx))
		var fleetSince int64
		if opts.Recorder != nil {
			fleetSince = opts.Recorder.Seq()
		}
		col, err := collect.New(opts.Kubeconfig, kctx, copts...)
		if err != nil {
			fmt.Fprintf(log, "fleet: WARNING context %q: %v — skipping\n", kctx, err)
			failures = append(failures, fmt.Errorf("%s: %w", kctx, err))
			skipped = append(skipped, types.SkippedCluster{Context: kctx, Reason: collect.ClassifyCause(err.Error())})
			continue
		}
		ar, err := Run(ctx, Options{
			Collector: col,
			// Friendly display name derived from the raw context: an EKS ARN or
			// GKE context becomes its bare cluster name; everything else is
			// unchanged. This name is also the per-cluster switcher key — a
			// short name (dev-cluster) is a better key than a full ARN.
			ClusterName:      friendlyClusterName(kctx),
			IncludeSystem:    opts.IncludeSystem,
			PrometheusURL:    opts.PrometheusURL,
			AutoConnect:      opts.AutoConnect,
			RESTConfig:       col.RESTConfig(),
			AllowPortForward: opts.AllowPortForward,
			Clientset:        col.Clientset(),
			Discount:         opts.Discount,
			Redact:           opts.Redact,
			Log:              log,
			Progress:         opts.Progress,
			// Forwarded so each cluster's report carries its own session-trace appendix. Without this the
			// fleet run counted requests and then attached them to nothing: `shoalcheck fleet` shipped with no
			// trace at all, and the fleet Prometheus leg was unrecorded.
			Recorder: opts.Recorder,
			// Each cluster's report claims only its own requests, not the ones made for the clusters
			// audited before it in the same fleet run.
			RecorderSince:    fleetSince,
			PriorReadingsFor: opts.PriorReadingsFor,
		})
		if err != nil {
			fmt.Fprintf(log, "fleet: WARNING context %q: %v — skipping\n", kctx, err)
			failures = append(failures, fmt.Errorf("%s: %w", kctx, err))
			skipped = append(skipped, types.SkippedCluster{Context: kctx, Reason: collect.ClassifyCause(err.Error())})
			continue
		}
		// A cluster nothing could be read from is NOT an audited member. Collect returns no error when every
		// list fails — it records the failures and hands back an empty inventory — so an unreachable cluster
		// used to produce a perfectly successful report with zero findings and fold into the fleet totals as a
		// clean one. Counting it as audited is the fleet-level version of calling an empty reading a clean bill.
		// The question is NothingRead's, shared with `audit` and the app, so a cluster that answered only
		// discovery is skipped here exactly as one that refused the connection is.
		if NothingRead(ar) != nil {
			fmt.Fprintf(log, "fleet: WARNING context %q: no resource list succeeded — not counting it as audited\n", kctx)
			skipped = append(skipped, types.SkippedCluster{Context: kctx, Reason: "nothing could be read"})
			continue
		}
		reports = append(reports, ar)
	}

	if len(reports) == 0 {
		// Built from `skipped`, not from `failures`: a cluster can now be skipped WITHOUT an error — the
		// "nothing could be read" case returns no error at all — and errors.Join of an empty slice is nil,
		// which %w renders as the literal "%!w(<nil>)". The message names each context and its classified
		// cause, which is what an operator needs and what the raw errors would have buried.
		var why []string
		for _, sk := range skipped {
			why = append(why, fmt.Sprintf("%s (%s)", sk.Context, sk.Reason))
		}
		if len(failures) > 0 {
			return nil, fmt.Errorf("fleet: none of the %s could be audited: %s: %w", nWord(len(opts.Contexts), "cluster", "clusters"), strings.Join(why, ", "), errors.Join(failures...))
		}
		return nil, fmt.Errorf("fleet: none of the %s could be audited: %s", nWord(len(opts.Contexts), "cluster", "clusters"), strings.Join(why, ", "))
	}
	if len(skipped) > 0 {
		fmt.Fprintf(log, "fleet: %d of %s audited; %d not audited\n",
			len(reports), nWord(len(opts.Contexts), "cluster", "clusters"), len(skipped))
	}

	// The skip list travels IN the document, and it is handed to the assembler rather than attached
	// afterwards: the divergence surface has to carry it too, and a field set after assembly is a field the
	// assembler cannot use.
	fr, err := assembleFleet(reports, skipped, opts.Redact)
	if err != nil {
		return nil, err
	}
	return fr, nil
}

// AssembleFleet is RunFleet's tail for readings already taken: the same topology, divergence and validation the
// fleet command runs, stamped at the moment given. The sample fleet is three synthetic clusters read through fake
// API servers, and it is assembled here so that nothing about it is assembled by hand.
func AssembleFleet(reports []*types.AuditReport, skipped []types.SkippedCluster, at time.Time) (*types.FleetReport, error) {
	fr, err := assembleFleet(reports, skipped, false)
	if err != nil {
		return nil, err
	}
	fr.GeneratedAt = at.UTC().Truncate(time.Second)
	return fr, nil
}

// assembleFleet rolls already-audited per-cluster reports into one validated
// FleetReport. It is the cluster-free tail of RunFleet, factored out so the
// aggregation contract (skip nils, stamp the envelope, validate) is unit-testable
// without standing up real clusters.
//
// It stamps SchemaVersion "v1" and GeneratedAt now, drops nil reports, and runs
// FleetReport.Validate (which rejects empty fleets, nameless or duplicate-named
// clusters, and any invalid child report). A validation failure is returned to
// the caller rather than swallowed.
func assembleFleet(reports []*types.AuditReport, skipped []types.SkippedCluster, redactEnvelope bool) (*types.FleetReport, error) {
	clusters := make([]*types.AuditReport, 0, len(reports))
	for _, ar := range reports {
		if ar == nil {
			continue
		}
		clusters = append(clusters, ar)
	}
	// Derive the cross-cluster topology (peers + relationships) from the
	// audited reports so the multi-cluster diagram renders from real data.
	deriveFleetTopology(clusters)
	fr := &types.FleetReport{
		SchemaVersion: "v1",
		// UTC, AND TO THE SECOND — see the same assignment in internal/collect/assemble.go for what the
		// local zone leaked out of a redacted document.
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Clusters:    clusters,
		// A line on stderr is not a record — the reader of the HTML would see three clusters where five
		// were asked for, with nothing to say the other two were unreachable rather than clean.
		Skipped: skipped,
	}
	// What these clusters DECLARE differently. Computed here, in the pipeline, so the renderer consumes an
	// assembled document rather than assembling one — the same boundary scripts/depcheck.sh enforces for
	// internal/rules. Nil below two audited clusters, which is why it is safe to call unconditionally.
	fr.Divergence = divergence.Compute(clusters, skipped)
	// THE ENVELOPE'S OWN FIELD, which no child report carries. Each cluster's report was redacted inside
	// Run as it was audited; Skipped names the contexts that were ASKED for and never became a report, and a
	// kubeconfig context on a managed cluster carries the account, the region and the cluster's name. See
	// redact.Fleet. Computed BEFORE Validate, so the document that is checked is the document that ships.
	if redactEnvelope {
		fr = redact.Fleet(fr)
	}
	if err := fr.Validate(); err != nil {
		return nil, fmt.Errorf("assembled fleet failed validation: %w", err)
	}
	return fr, nil
}

// usageResult is fetchUsage's full output. It carries the rightsizing inputs the
// rules need AND the auto-connect plumbing the observed-service-map block reuses,
// so ONE Prometheus connection powers both usage-$ and the map.
type usageResult struct {
	// usage is the rightsizing map, or nil when no usable source resolved (the
	// rule no-ops honestly — nil means "no data", never zeros).
	usage map[string]prom.ContainerUsage
	// dataSrc is a human note for Methodology.DataSources.
	dataSrc string
	// methodology is the always-non-nil UsageMethodology stamp.
	methodology *prom.UsageMethodology

	// mapClient is the auto-connected client (service-proxy / opt-in port-forward)
	// the usage layer built and Pinged, surfaced so Run's observed-service-map
	// block can reuse it instead of dialing again. nil when no auto-connect client
	// was established (no URL given, no service, blocked proxy, …); Run then uses
	// the explicit-URL client or skips. It is independent of whether usage series
	// resolved — a reachable-but-no-usage endpoint can still carry mesh telemetry.
	mapClient *prom.Client
	// connectMode is the disclosed connect-mode label for mapClient ("" when none).
	connectMode string
	// portForward is the live forward backing mapClient when ModePortForward was
	// used; Run defers its Close so the client stays usable through the map build.
	portForward *prom.PortForward

	// provenance is the access-tier verdict for the usage source: was it PROVEN to be this cluster's, or
	// merely reachable? Zero value (TierNone) when no source resolved or none needed proving.
	//
	// B-145: "a Prometheus answered" is not "this cluster's Prometheus answered", and the four usage
	// queries carry no cluster selector. When this comes back unproven the usage map is DROPPED rather
	// than used, because a rightsizing dollar computed from another cluster's consumption is worse than
	// no dollar at all — absence is honest and a wrong number is not.
	provenance prom.Provenance
}

// fetchUsage resolves exactly one usage provider for the cluster, fetches
// per-container usage, and surfaces the auto-connected client (see usageResult).
//
// err is non-nil ONLY when an explicit PrometheusURL is unreachable — a wrong URL
// must fail loudly, not silently produce a metrics-less report.
//
// Lives in pipeline (not cmd) so the OSS scan binary and the proprietary CLI
// share one prometheus-wiring path. Unexported: the only entry point is Run.
func fetchUsage(ctx context.Context, opts Options, inv *collect.Inventory, log io.Writer) (usageResult, error) {
	// A nil inventory is a legitimate "nothing was collected" state rather than a programming error, and
	// this function's whole contract is to degrade rather than fail. Crashing here would turn an empty
	// read into a lost report.
	if inv == nil {
		inv = &collect.Inventory{}
	}
	services := inv.Services
	// Keep the explicit-URL fatal contract: an unreachable --prometheus-url is a
	// loud failure, NOT a silent fall-through to a metrics-less report.
	if opts.PrometheusURL != "" {
		ping := prom.NewClient(opts.PrometheusURL, opts.UsageAuth, promRecorderOpts(opts.Recorder)...)
		if perr := ping.Ping(ctx); perr != nil {
			return usageResult{}, fmt.Errorf("--prometheus-url %s: %w", opts.PrometheusURL, perr)
		}
	}

	// Auto-connect (desktop app): when no explicit URL was given, try to reach an
	// in-cluster Prometheus through the API-server service-proxy using the SAME
	// read-only creds, with an opt-in port-forward fallback. This NEVER fails the
	// audit — every failure leaves preClient nil and degrades to the URL/detect
	// path below, exactly like the no-URL autodiscover hint. The connect mode is
	// appended to the methodology note so the path is always disclosed.
	//
	// preClient (when non-nil) is also surfaced via usageResult.mapClient so Run's
	// observed-service-map block reuses this one connection. Run owns pf's Close so
	// the forward stays alive through the map build, not just through p.Usage.
	var (
		preClient   *prom.Client
		connectMode string
	)
	// Services in hand were read, whatever Meta says; an empty list was read only if Meta says it was.
	servicesRead := len(services) > 0 || collect.Observed(inv, "services")
	pf := autoConnect(ctx, opts, services, servicesRead, log, &preClient, &connectMode)
	res := usageResult{mapClient: preClient, connectMode: connectMode, portForward: pf}

	p := prom.ResolveUsageProvider(ctx, prom.UsageConfig{
		PrometheusURL:    opts.PrometheusURL,
		PrometheusClient: preClient,
		Auth:             opts.UsageAuth,
		Services:         services,
		VPALister:        opts.VPALister,
		MetricsLister:    opts.MetricsLister,
		ClientOptions:    promRecorderOpts(opts.Recorder),
	})
	m := p.Methodology()
	res.methodology = &m

	u, uerr := p.Usage(ctx)
	if uerr != nil {
		// A reachable endpoint whose query failed is NOT fatal: warn and proceed
		// without usage-based rightsizing.
		fmt.Fprintf(log, "usage: source %q reachable but query failed (%v); proceeding without usage-based rightsizing\n", m.Source, uerr)
		note := fmt.Sprintf("Usage source %q: query failed (%v) — rightsizing skipped", m.Source, uerr)
		res.dataSrc = appendConnectMode(note, connectMode)
		return res, nil
	}

	if m.Source == "none" {
		// Auto-connect reached an endpoint (Ping ok) but the usage/probe queries
		// returned nothing usable — typically a service-proxy that allows the
		// readiness GET but blocks PromQL reads, or a curated/empty backend. Say so
		// honestly; the audit proceeds without usage-based rightsizing. The endpoint
		// may still carry mesh telemetry, so mapClient is left set for the map block.
		if preClient != nil {
			fmt.Fprintf(log, "auto-connect: endpoint reachable via %s but usage queries returned no usable series (proxy blocked / empty backend); proceeding without usage-based rightsizing\n", connectMode)
		}
		if found, hint := prom.Detect(services); found && preClient == nil {
			fmt.Fprintln(log, hint)
		}
		// Disclose the connect mode here too (every other return path does): if an
		// opt-in port-forward/service-proxy was actually exercised, the RBAC note
		// must say so even though no usable series came back. Dropping it would
		// under-state the access used.
		res.dataSrc = appendConnectMode("no usage source available — usage-based rightsizing skipped", connectMode)
		return res, nil
	}

	// PROVE THE SOURCE BEFORE ANY FIGURE RESTS ON IT — B-145.
	//
	// Only providers that CAN be pointed at another cluster implement ClusterProver, so this is a no-op
	// for the in-cluster VPA and metrics.k8s.io paths and runs for Prometheus, which is the one that can
	// be a Thanos holding twelve clusters. On failure the usage map is dropped and the reason is carried
	// into the methodology, so a reader sees a NAMED withholding rather than a silently absent figure.
	if prover, ok := p.(prom.ClusterProver); ok {
		res.provenance = prover.ProveCluster(ctx, podUIDs(inv), len(inv.Pods))
		if !res.provenance.Proven() {
			fmt.Fprintf(log, "usage: source %q could not be proven to be this cluster's (%s: %s); "+
				"usage-based rightsizing withheld\n", m.Source, res.provenance.Method, res.provenance.Detail)
			res.dataSrc = appendConnectMode(fmt.Sprintf(
				"Usage source %q reached but NOT PROVEN to be this cluster's — %s. Every usage-derived "+
					"figure is withheld: an unqualified query against a source holding more than one "+
					"cluster attributes another cluster's consumption to this one.",
				m.Source, res.provenance.Detail), connectMode)
			return res, nil
		}
	}

	fmt.Fprintf(log, "usage: source=%s backend=%s window=%s — %d container series; usage-based rightsizing active\n",
		m.Source, m.Backend, m.Window, len(u))
	res.usage = u
	res.dataSrc = appendConnectMode(usageNote(m, len(u)), connectMode)
	return res, nil
}

// usageNote is the methodology sentence every consumption figure in the document rests on.
//
// IT USED TO PRINT AN EMPTY SLOT. The format string was
// `"Usage: %s (%s, window %s) — %d container series"` and it assumed UsageMethodology.Backend is always
// set. It is the resolved Prometheus FLAVOUR — thanos, mimir, amp, gmp, victoria-metrics — and is empty for
// every other tier, which is metrics.k8s.io and VPA. Measured on the shipped golden:
//
//	Usage: metrics.k8s.io (, window instant) — 28 container series
//
// A leading comma and an empty first element, in a parenthetical, on the line that qualifies every
// rightsizing number in the reading. It shipped on every non-Prometheus reading.
//
// The parenthetical is built from the parts that EXIST, and when none do it is not printed at all. Same
// rule the money cells took in M-53: an absence is not a value, and printing it as one puts a slot on the
// page where a reader looks for a fact.
func usageNote(m types.UsageMethodology, series int) string {
	var parts []string
	if m.Backend != "" {
		parts = append(parts, m.Backend)
	}
	if m.Window != "" {
		parts = append(parts, "window "+m.Window)
	}
	note := "Usage: " + m.Source
	if len(parts) > 0 {
		note += " (" + strings.Join(parts, ", ") + ")"
	}
	note += fmt.Sprintf(" — %d container series", series)
	if len(m.Caveats) > 0 {
		note += " — caveats: " + strings.Join(m.Caveats, "; ")
	}
	return note
}

// podUIDs collects the audited cluster's live pod UIDs, which are the only globally unique identifiers a
// read-only snapshot holds. A UID is an RFC 4122 value assigned by the API server, so finding one in a
// metrics source proves the source holds THIS cluster's data — where a namespace name proves nothing,
// because prod and staging share them by design.
func podUIDs(inv *collect.Inventory) []string {
	out := make([]string, 0, len(inv.Pods))
	for i := range inv.Pods {
		if u := string(inv.Pods[i].UID); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// mapClient picks the client the observed-service-map block uses and the
// connect-mode note to append to its log line, in the same priority Run
// documents: explicit --prometheus-url first (its own 30s-budget client for the
// heavier mesh aggregation), else the auto-connected client fetchUsage already
// built and Pinged, else (nil, "") ⇒ skip. Reusing the auto-connected client
// adds NO new RBAC: it is the same kubeconfig + opt-in role the usage path used.
func mapClient(opts Options, res usageResult) (*prom.Client, string) {
	if opts.PrometheusURL != "" {
		return prom.NewClientWithTimeout(opts.PrometheusURL, opts.UsageAuth, 30*time.Second,
			promRecorderOpts(opts.Recorder)...), ""
	}
	if res.mapClient != nil {
		return res.mapClient, " via " + res.connectMode
	}
	return nil, ""
}

// autoConnect resolves an in-cluster Prometheus terminal-free when opts.AutoConnect
// is set and no explicit URL was given. On success it sets *preClient to a
// connected client (service-proxy preferred, opt-in port-forward fallback) and
// *mode to a disclosed connect-mode label, and returns a non-nil *PortForward the
// caller must Close after usage is read. It NEVER returns an error: any failure
// leaves *preClient nil (the resolver then falls through to the next tier) and is
// logged honestly.
func autoConnect(ctx context.Context, opts Options, services []corev1.Service, servicesRead bool, log io.Writer, preClient **prom.Client, mode *string) *prom.PortForward {
	if !opts.AutoConnect || opts.PrometheusURL != "" || opts.RESTConfig == nil {
		return nil
	}
	// AN ABSENCE NEEDS ITS CAUSE. Every run against an unreachable cluster said "no in-cluster Prometheus Service
	// found" — a sentence about the cluster's monitoring from a run that never saw one of its Services.
	if !servicesRead {
		fmt.Fprintln(log, "auto-connect: services were not read, so no Prometheus was looked for — report runs without usage-based rightsizing")
		return nil
	}
	// Ranked candidates, not a single guess. A stock kube-prometheus-stack install
	// exposes eleven Services whose names contain "prometheus" and only one of them
	// answers PromQL, so the endpoint is decided by dialling, never by name alone.
	eps := prom.RankEndpoints(services)
	if len(eps) == 0 {
		fmt.Fprintln(log, "auto-connect: no in-cluster Prometheus Service found — report runs without usage-based rightsizing")
		return nil
	}

	// Mechanism A (preferred, pure read): API-server service-proxy GET.
	c, ep, cerr := prom.DialFirstServiceProxy(ctx, opts.RESTConfig, eps, promRecorderOpts(opts.Recorder)...)
	if cerr == nil {
		fmt.Fprintf(log, "auto-connect: reached %s/%s:%d via API-server service-proxy\n", ep.Namespace, ep.Name, ep.Port)
		*preClient = c
		*mode = string(prom.ModeServiceProxy)
		return nil
	}

	// Mechanism B (fallback, opt-in): in-process port-forward, over the same ranked
	// candidates — the service-proxy may be blocked cluster-wide, which says nothing
	// about which Service is the real Prometheus.
	if opts.AllowPortForward && opts.Clientset != nil {
		var perr error
		// Bounded by the SAME cap the read path uses. This loop issues `create pods/portforward` per
		// attempt, so an unbounded walk of every Prometheus-shaped Service would make the count of
		// non-read verbs a function of the cluster's monitoring stack rather than of what we needed.
		tried := eps
		if len(tried) > prom.MaxProbeCandidates {
			tried = tried[:prom.MaxProbeCandidates]
		}
		for _, cand := range tried {
			pc, pf, err := prom.DialServiceProxyFallback(opts.RESTConfig, opts.Clientset, cand,
				promRecorderOpts(opts.Recorder)...)
			if err != nil {
				perr = err
				continue
			}
			fmt.Fprintf(log, "auto-connect: reached %s/%s:%d via in-process port-forward\n", cand.Namespace, cand.Name, cand.Port)
			*preClient = pc
			*mode = string(prom.ModePortForward)
			return pf
		}
		fmt.Fprintf(log, "auto-connect: service-proxy blocked and port-forward fallback failed for %d of %d "+
			"candidate(s) tried (%v); proceeding without usage-based rightsizing\n", len(tried), len(eps), perr)
		return nil
	}

	fmt.Fprintf(log, "auto-connect: service-proxy did not answer for any of %s (%v); enable the opt-in port-forward fallback to retry\n", nWord(len(eps), "candidate", "candidates"), cerr)
	return nil
}

// appendConnectMode annotates the methodology note with the disclosed connect
// mode (service-proxy / port-forward), or returns the note unchanged when the
// usage came from a URL / lower tier (mode == "").
func appendConnectMode(note, mode string) string {
	if mode == "" {
		return note
	}
	return note + " — connected via " + mode
}

// promGraphAdapter adapts a *prom.ObservedGraph to the collect.ObservedGraphInput
// interface ApplyObservedGraph expects, so collect never imports prom. The
// interface and its methods are exported because Go requires both for a type in
// another package to satisfy a cross-package interface.
type promGraphAdapter struct{ g *prom.ObservedGraph }

func (a promGraphAdapter) GraphSource() string              { return string(a.g.Source) }
func (a promGraphAdapter) GraphWindow() string              { return a.g.Window }
func (a promGraphAdapter) GraphAsOf() time.Time             { return a.g.AsOf }
func (a promGraphAdapter) GraphNote() string                { return a.g.Note }
func (a promGraphAdapter) GraphEdges() []types.ObservedEdge { return a.g.Edges }

// FindingDependencies is the single map a comparison needs: for every finding in a report, keyed by the
// rule or analyzer that produced it, what that finding rests on.
//
// It lives here because the pipeline is the one place that knows the report's findings come from TWO
// registries. internal/analyzers and internal/rules are deliberately leaves that do not import each
// other, so neither could build this, and a comparison handed only one of them would silently have no
// declaration for the other's findings.
//
// A comparison consuming this must treat an ID that is ABSENT from the map as not comparable rather than
// as unchanged: an unknown producer is a finding from a build whose dependencies we cannot state.
func FindingDependencies() map[string]rules.Dependencies {
	out := rules.DependenciesByRule()
	for id, kinds := range analyzers.DependenciesByAnalyzer() {
		if _, clash := out[id]; clash {
			// Two producers sharing an ID would make one of them invisible to the comparison. Rather
			// than pick a winner, keep the union of what both rest on: the effect is to withhold a
			// comparison more often, never to license one that is unsafe. The test below fails on the
			// collision so it is fixed at the source.
			existing := out[id]
			out[id] = rules.Dependencies{Kinds: unionKinds(existing.Kinds, kinds), Usage: existing.Usage}
			continue
		}
		out[id] = rules.Dependencies{Kinds: kinds}
	}
	return out
}

func unionKinds(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// attachFindingBasis records, per finding, the collector steps its rule depends on and which of them this run
// could not read.
//
// The chain needs no new vocabulary and that is why this rung ships first: Dependencies.Kinds are collector step
// names verbatim as Methodology.CollectedKinds records them, so RuleID → Kinds → Collected/Denied is complete with
// nothing to translate. A later rung joins a kind to the requests that read it, and that one DOES need a table.
//
// A finding whose producer this build cannot describe is marked Unknown rather than given a basis of zero kinds —
// "rests on nothing" and "we cannot say" are different statements and only one of them is true.
func attachFindingBasis(ar *types.AuditReport, _ bool) {
	if ar == nil || len(ar.Findings) == 0 {
		return
	}
	deps := FindingDependencies()

	read := make(map[string]bool, len(ar.Methodology.CollectedKinds))
	for _, k := range ar.Methodology.CollectedKinds {
		read[k] = true
	}
	usage := ""
	if ar.Methodology.RunBasis != nil {
		usage = ar.Methodology.RunBasis.UsageSource
	}

	for i := range ar.Findings {
		d, known := deps[ar.Findings[i].RuleID]
		if !known {
			ar.Findings[i].Basis = &types.FindingBasis{Unknown: true}
			continue
		}
		b := &types.FindingBasis{
			Kinds:         append([]string(nil), d.Kinds...),
			UsageRequired: d.Usage,
		}
		// THE SOURCE ONLY WHERE SOMETHING REQUIRED IT. This was `UsageSource: usage` unconditionally, so the
		// run's usage source landed on every finding whether or not the rule reads usage. Measured on a real
		// 192-finding reading: 186 carried `usageSource: "prometheus"` with `usageRequired: false`, and only
		// 4 genuinely require usage.
		//
		// The page was fine — FindingBasis.Summary() guards its usage clause behind UsageRequired — and the
		// AGENT SURFACE was not: shoalcheck-mcp serialises the struct, `usageRequired: false` is dropped by
		// omitempty, and a model reading `explain_finding` on an RBAC grant saw a bare
		// `"usageSource": "prometheus"` with nothing to qualify it. Asked which findings depend on metrics,
		// it would answer 186 instead of 4.
		//
		// The two fields are defined as a pair in their own doc — "UsageRequired marks a finding that exists
		// only where Prometheus usage was resolved; UsageSource names what supplied it. TOGETHER they say
		// why a rightsizing figure is present at all." One without the other is a different statement, not a
		// partial one. Fixing it at the producer means every surface inherits the guard instead of each
		// renderer having to remember it, which is M-53's argument about the money cell.
		if d.Usage {
			b.UsageSource = usage
		}
		// Refused means "not confirmed read", the same discipline the comparison gates use: a kind recorded
		// neither way was never confirmed, and treating an unlooked-at list as an empty one is the mistake this
		// codebase keeps finding.
		for _, k := range d.Kinds {
			if !read[k] {
				b.Refused = append(b.Refused, k)
			}
		}
		sort.Strings(b.Refused)
		ar.Findings[i].Basis = b
	}
}

// attachSessionTrace puts the recorder's own account of the run into the report.
//
// Built from the tally rather than recomputed, so the appendix cannot disagree with the live ticker or with
// --trace-out: three surfaces, one measurement.
func attachSessionTrace(ar *types.AuditReport, rec *trace.Recorder, since int64, execPlugin string) {
	if ar == nil || rec == nil {
		return
	}
	t := rec.TallySince(since)
	if t.Total == 0 {
		// No measurement is reported as no appendix, never as a zeroed one: "0 requests" would be a claim,
		// and an absent section is not.
		return
	}
	st := &types.SessionTrace{
		Total: t.Total, Run: t.Run, Preflight: t.Preflight,
		ObjectWrites: t.Write, Streams: t.Stream, External: t.External,
		Denied: t.Denied, NoResponse: t.NoResponse, Retried: t.Retried,
		ExecCredentialPlugin: execPlugin,
	}
	for _, g := range rec.GroupsSince(since) {
		st.Rows = append(st.Rows, types.SessionTraceRow{
			Verbs: g.Verbs, Resource: g.Resource, Scope: g.Scope,
			Requests: g.Requests, Outcome: summariseOutcomes(g.Outcomes),
			Class: g.Class.String(), Paths: g.NonResourcePaths,
		})
	}
	ar.Methodology.SessionTrace = st
}

// execPluginName reports the kubeconfig's credential plugin, when it uses one. Those plugins run as SEPARATE
// PROCESSES and talk to a cloud identity provider, so their traffic is structurally uncountable here — this is
// how the appendix scopes its own claim instead of implying a totality it cannot have. It fires on every EKS,
// AKS and GKE context.
func execPluginName(col *collect.Collector) string {
	if col == nil {
		return ""
	}
	cfg := col.RESTConfig()
	if cfg == nil || cfg.ExecProvider == nil {
		return ""
	}
	return cfg.ExecProvider.Command
}

// summariseOutcomes renders a group's outcomes with the unhappy ones named. "ok" alone stays bare; anything
// else is spelled out, because a refused list that reads as a plain count is the exact shape of a coverage
// gap presented as coverage.
func summariseOutcomes(m map[string]int) string {
	if len(m) == 1 {
		for k := range m {
			return k
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", m[k], k))
	}
	return strings.Join(parts, ", ")
}

// promRecorderOpts adapts a possibly-nil recorder into the option slice the prom constructors take, so
// every call site reads the same and none of them has to branch on nil.
func promRecorderOpts(r *trace.Recorder) []prom.Option {
	if r == nil {
		return nil
	}
	return []prom.Option{prom.WithTransportRecorder(r)}
}

// countPairs fills Volume.Pairs: Σ over the registry's rules of the objects in the kinds each one reads. Every
// rule in rules.All() is evaluated on every run, so the registry IS the set that ran. A kind the reading did
// not read contributes nothing, which is the truth: no rule examined an object nobody read.
func countPairs(v *types.ReadVolume, deps map[string]rules.Dependencies) {
	if v == nil {
		return
	}
	objects := make(map[string]int, len(v.ByKind))
	for _, k := range v.ByKind {
		objects[k.Kind] = k.Objects
	}
	n := 0
	for _, d := range deps {
		for _, k := range d.Kinds {
			n += objects[k]
		}
	}
	v.Pairs = n
}

// HistoryDeps is FindingDependencies in the shape internal/history takes. history defines its own Deps
// type rather than importing a registry, so that it stays a leaf; this is the one conversion, kept next
// to the map it converts so the two cannot fall out of step.
func HistoryDeps() map[string]history.Deps {
	src := FindingDependencies()
	producer := analyzers.ProducerByFinding()
	out := make(map[string]history.Deps, len(src))
	for id, d := range src {
		out[id] = history.Deps{Kinds: d.Kinds, Usage: d.Usage, Datasets: datasetDepsFor(id), Producer: producer[id]}
	}
	return out
}
