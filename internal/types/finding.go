package types

// Finding is a single audit observation about the cluster.
//
// Every Finding renders to one card in the HTML report. Fields documented as
// "rendered" appear directly on the card.
type Finding struct {
	// ID is a stable hash of (RuleID + canonical resource ref). Used for
	// idempotent diffing across audit runs in later phases.
	ID string `json:"id"`

	// RuleID identifies the detection rule, e.g. "k8s.workload.cpu-overprovisioned".
	// Stable across versions; rule logic changes bump RuleVersion, not RuleID.
	RuleID string `json:"ruleId"`

	// RuleVersion is the semver of the detection rule's logic at scan time.
	RuleVersion string `json:"ruleVersion"`

	// Title is rendered. 6-12 words, action-oriented, customer-facing.
	Title string `json:"title"`

	// Description is rendered. 2-3 sentences explaining what's wrong.
	Description string `json:"description"`

	// WhyItMatters is rendered. 1 sentence on business impact.
	// LLM-fillable in Phase 3; hand-written in v0.
	WhyItMatters string `json:"whyItMatters"`

	// Evidence is rendered. Concrete data points supporting the finding.
	// Example: ["Pod payments-api-7d4f restartCount=14 in last 1h", ...].
	// Credibility-defining — generic phrasing kills trust.
	Evidence []string `json:"evidence"`

	Severity Severity `json:"severity"`
	Category Category `json:"category"`

	// AffectedResources lists the resources this finding applies to,
	// with owner-chain context to allow workload-level dedup.
	AffectedResources []ResourceRef `json:"affectedResources"`

	// ScopedTo names the specific objects a grant is restricted to, when it is restricted to any. It is
	// populated from rbacv1.PolicyRule.ResourceNames and is empty for every other rule.
	//
	// IT IS A STRUCTURED FIELD RATHER THAN ONLY EVIDENCE PROSE, and that is the whole reason it exists.
	// redact.gatherIdentifiers harvests structured fields; a customer-chosen object name that appears only
	// in free text has no token and survives --redact verbatim. The cert-manager analyzer declined to print
	// an issuer name for exactly this reason (internal/analyzers/certmanager.go:44). Registering the name
	// here is what makes printing it safe, and rep() is a string replacer over the whole report, so the
	// same name is rewritten in the evidence sentence too.
	//
	// On a customer cluster these read `acme-prod-db-credentials`, `payments-oauth-client`. A grant on
	// `secrets` is not assessable without them, which is why Option C prints them rather than a count.
	ScopedTo []string `json:"scopedTo,omitempty"`

	// Deadline is a date this finding read from the object it is about, structured so the calendar block can be
	// assembled from findings without parsing evidence prose. Set by analyzers whose claim IS a date (cert-manager
	// expiry); nil everywhere else. See calendar.go.
	Deadline *Deadline `json:"deadline,omitempty"`

	// DollarImpactMonthly is the estimated USD/month impact. Cluster-wide totals roll this up in
	// Summary.EstimatedSavingsUSD.
	//
	// A ZERO HERE IS AMBIGUOUS, WHICH IS WHY PriceBasis EXISTS. It means all three of "this is a security
	// finding and has no dollars", "this is a cost finding we could not price", and "we priced it at nothing".
	// Any renderer reading the number alone must guess, and the cost chart guessed: it dropped every finding at
	// or below zero and counted none of them, so a reader could count the bars and never learn the input was
	// three times longer. Read PriceBasis, not the sign of this field.
	DollarImpactMonthly float64 `json:"dollarImpactMonthly"`

	// PriceBasis says which of those three a zero is. Optional so older reports still parse; absent is
	// treated as PriceUnknown, which renderers must handle as "do not claim either way".
	PriceBasis PriceBasis `json:"priceBasis,omitempty"`

	// SpendKind says what the dollar above is denominated in — compute, storage, network or control plane —
	// so that a compute commitment (--discount) scales exactly the compute-denominated figures and leaves the
	// rest at list. Optional so older reports still parse; absent is SpendUnknown, which the discount never
	// reaches. See types.SpendKind.
	SpendKind SpendKind `json:"spendKind,omitempty"`

	EstimatedEffort EffortLevel `json:"estimatedEffort"`

	// RemediationYAML is a kubectl-applyable patch or manifest. Validated via
	// `kubectl apply --dry-run=server` in CI (make validate-fixture).
	RemediationYAML string `json:"remediationYaml,omitempty"`

	// RemediationCommand is an alternative kubectl/helm command — used when
	// a YAML patch is awkward (e.g., scale commands, helm upgrade flags).
	RemediationCommand string `json:"remediationCommand,omitempty"`

	// CommandSafety is whether RemediationCommand may be offered behind a one-click copy button. Computed in
	// internal/pipeline from rules.SafeRemediationCommand, because internal/report may not import
	// internal/rules. The zero value fails safe — see types.CommandSafety.
	CommandSafety CommandSafety `json:"commandSafety,omitempty"`

	// Confidence ranges 0.0-1.0. Always populated; v0 hand-crafted findings
	// default to 0.95. Phase 3 LLM enrichment populates with real values.
	//
	// NOT A MEASURED DISTRIBUTION, and it must not be printed as a percentage. The values are a handful of
	// authored constants, and one of them is a deliberate 0.0 — internal/rules/netpol.go sets it with the
	// comment "we observed nothing; this is a coverage gap, not a problem we are certain of", an authored
	// intent of LOOK HERE. Through a percentage formatter that became "conf 0%", which reads as "this finding
	// is certainly wrong". Render it with report.confidenceWord.
	Confidence float64 `json:"confidence"`

	// ClaimBoundaries is what this finding does NOT establish.
	//
	// THE SECOND RUNG OF THE PROVENANCE LADDER. Basis calls itself the first — it names the kinds read and
	// the kinds refused, and answers "why do you say this?". This answers the question a careful reader asks
	// next and which the product has never answered in a form a machine can read: "what does this not tell
	// me?" A PodDisruptionBudget gates voluntary eviction only. A model that checks a subset of the
	// scheduler's predicates can refuse soundly and cannot promise a placement. A list price is not the bill.
	//
	// TWO PRODUCERS, ONE FIELD. FAMILY boundaries are properties of the rule, true on every cluster, and come
	// from internal/boundaries by rule id. CONDITIONAL boundaries are properties of THIS RUN — "three of
	// these pods matched no endpoint entry", "this cluster carries only the beta zone label" — and a rule
	// appends them itself at Evaluate time. They are the more valuable half, because they say what this
	// particular reading could not establish, and a static table cannot hold them.
	//
	// WHY THE FIELD RATHER THAN A LOOKUP. internal/report may not import internal/rules (depcheck rule 1), so
	// a renderer cannot ask a rule anything; the same is true of the evidence pack, a SARIF export and the
	// app. Resolving by rule id at each surface would put the boundaries only where somebody remembered to
	// look them up. This is the path CommandSafety, Pillar, PriceBasis and Basis already take, and it is the
	// fifth time that shape has been the answer.
	//
	// Empty on a reading written before 2026-09-07, which a renderer must treat as "not stated" rather than
	// as "this claim has no limits".
	ClaimBoundaries []string `json:"claimBoundaries,omitempty"`

	// IDBasis is the resource reference this finding's ID was derived from, so a reader can recompute it.
	//
	// THE PUBLISHED RECIPE IS f- + sha256(RuleID|Kind|Namespace|Name)[:12], AND UNTIL NOW IT WAS ONLY
	// SOMETIMES APPLICABLE. For a per-object finding the reader has all four slots — the rule id is on the
	// finding and the resource is its first affected one. For an AGGREGATE finding the id is minted from a
	// synthesized reference the finding never published: job-no-ttl hashes (Namespace, ns,
	// "jobs-without-ttl") while its affected resources are the individual Jobs; node-headroom hashes a pool
	// identity; the zone rules hash a zone. Measured over the golden's 134 findings, 105 were checkable with
	// sha256sum and 29 were not, across 21 rules. Those ids were always stable and always reproducible BY THE
	// ENGINE; they simply could not be checked by the person holding the report.
	//
	// This field publishes the three slots, so the recipe applies to every finding with no exception list.
	//
	// IT CARRIES CUSTOMER TEXT — a Kind, a Namespace and a Name — so internal/redact rewrites it exactly as
	// it rewrites AffectedResources. A REDACTED REPORT THEREFORE CANNOT BE USED TO CHECK AN ID, which was
	// already true of every id (the recipe needs the real names) and is said here rather than left for
	// somebody to discover with sha256sum.
	IDBasis *ResourceRef `json:"idBasis,omitempty"`

	// Owner is who this finding belongs to, read from a namespace label the OPERATOR named with
	// --owner-label. Empty when no label was named, when the namespace does not carry it, and always for a
	// cluster-scoped finding, which has no namespace to read one from.
	//
	// THE PRODUCT DOES NOT PICK THE LABEL. Kubernetes has no owner label and the ecosystem has several
	// habits — `team`, `owner`, `squad`, `app.kubernetes.io/part-of` — so choosing one for everybody would
	// be wrong for most clusters. The operator is the only person who knows their own convention, so they
	// state it and this is the arithmetic that follows.
	//
	// AND IT NEVER GUESSES. An unlabelled namespace produces no owner rather than falling back to the
	// namespace name dressed as a team: "owned by payments" and "in the payments namespace" are different
	// statements, and a queue that conflates them routes work to people who never agreed to it.
	//
	// A LABEL VALUE IS CUSTOMER TEXT, so internal/redact rewrites it like any other name.
	Owner string `json:"owner,omitempty"`

	// Pillar is which of the product's two headline claims this finding belongs to — see pillar.go. Empty
	// means neither, which is a deliberate assignment rather than an absence: internal/rules requires every
	// registered rule to declare one. Additive and omitempty, like Basis and PriceBasis, so a report written
	// by today's build still parses tomorrow and one written tomorrow still parses today.
	Pillar Pillar `json:"pillar,omitempty"`

	Provenance Provenance `json:"provenance"`

	// Basis states what this finding's claim RESTS ON, and whether the run could read it. Optional and
	// additive: absent on a report produced by a build that did not compute it.
	//
	// It is the first rung of a provenance ladder, and the label matters as much as the content. "Basis" says
	// which collector steps the producing rule depends on and how many of them this run actually read. It does
	// NOT say those reads support the conclusion — a citation implies support, and knowing that a list was read
	// establishes only that the rule had its inputs. Saying the weaker thing accurately is the point.
	Basis *FindingBasis `json:"basis,omitempty"`
}

// FindingBasis is the coverage basis of one finding: the inputs its rule needs, and which of them this run got.
//
// Buildable with no new vocabulary, which is why it ships first. Dependencies.Kinds are collector step names
// verbatim as Methodology.CollectedKinds records them, so RuleID → Kinds → Collected/Denied is a complete
// derivation with nothing to translate.
type FindingBasis struct {
	// Kinds are the collector steps the producing rule depends on, sorted.
	Kinds []string `json:"kinds"`

	// Refused are the kinds among Kinds that this run could not read. A finding still exists when some of its
	// inputs were refused — the rule fired on what it had — and that is exactly when the reader needs to know:
	// the finding is a floor, not a count, and nothing else on the card says so.
	Refused []string `json:"refused,omitempty"`

	// UsageRequired marks a finding that exists only where Prometheus usage was resolved; UsageSource names
	// what supplied it. Together they say why a rightsizing figure is present at all.
	UsageRequired bool   `json:"usageRequired,omitempty"`
	UsageSource   string `json:"usageSource,omitempty"`

	// Unknown is set when this build cannot describe the producing rule — an ID from a registry it does not
	// have. The card then states that rather than printing a basis of zero kinds, which would read as "rests on
	// nothing" when the truth is "we cannot say".
	Unknown bool `json:"unknown,omitempty"`

	// Requests are the session-trace references — "T-04" — for the rows whose requests read this finding's
	// kinds, sorted. The rung above Kinds: Kinds says WHAT this rests on and that the run read it, Requests
	// says WHICH REQUESTS did the reading.
	//
	// IT ESTABLISHES THAT A REQUEST WAS ISSUED AND NOTHING MORE. It is not evidence that the request supports
	// the finding, and the label a reader sees must not imply that it is — which is why the chip is worded
	// "requests issued" rather than "sources" or "evidence".
	Requests []string `json:"requests,omitempty"`

	// RequestsUnknown says the request-level citation was WITHHELD, and it is set whenever even one of Kinds
	// could not be resolved to a ledger row.
	//
	// ALL OR NOTHING, DELIBERATELY. A finding resting on four kinds, three of them traceable, must not print
	// three chips: a reader counts them, reads them as the whole basis, and concludes the fourth input was
	// never read. A partial citation is a false one, and "we cannot cite the requests for this finding" is
	// both shorter and true.
	RequestsUnknown bool `json:"requestsUnknown,omitempty"`
}

// Summary renders the basis as the one line a finding card prints. Kept on the type so the report, the fleet
// document and any future surface cannot word it three different ways.
func (b *FindingBasis) Summary() string {
	if b == nil {
		return ""
	}
	if b.Unknown {
		return "basis · not recorded for this rule"
	}
	n := len(b.Kinds)
	unit := "kinds"
	if n == 1 {
		unit = "kind"
	}
	out := ""
	switch {
	case n == 0 && b.UsageRequired && b.UsageSource != "" && b.UsageSource != "none":
		// A rule that reads telemetry and no object (alerts firing, scrape targets down) has a basis: the series.
		// "not recorded" here printed a recorded basis as a missing one.
		out = "basis · no object kind, telemetry only"
	case n == 0:
		out = "basis · not recorded"
	case len(b.Refused) == 0:
		out = "basis · " + itoaBasis(n) + " " + unit + ", all read"
	default:
		out = "basis · " + itoaBasis(n) + " " + unit + ", " + itoaBasis(len(b.Refused)) + " refused (" +
			joinBasis(b.Refused) + ")"
	}
	if b.UsageRequired {
		src := b.UsageSource
		if src == "" || src == "none" {
			// A usage-dependent finding cannot exist without a source, so this state means the basis was
			// computed from a run that did not record one. Say that rather than name a source.
			out += " · usage source not recorded"
		} else {
			out += " · usage from " + src
		}
	}
	return out
}

func itoaBasis(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func joinBasis(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ResourceRef identifies a Kubernetes resource and its ownership chain.
type ResourceRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	// OwnerChain would climb from this resource up to its top-level owner — for a Pod,
	// [ReplicaSet x, Deployment y].
	//
	// NOTHING IN THIS PRODUCT POPULATES IT, AS OF 2026-09-04. The field is on the schema and has three
	// consumers that handle it correctly when empty — internal/tracker prints one `owner=` per link and so
	// prints none, internal/redact rewrites the names it would carry, and the structural sentinel classifies
	// it — but the only writer anywhere in the tree is one redaction test. Its previous comment said "empty
	// for top-level resources", which reads as "populated for the rest", and that is how it came to be
	// reached for as a grouping key: keying on it would have put every finding under "" and looked like it
	// worked.
	//
	// Grouping by workload therefore uses the FIRST AFFECTED RESOURCE OF A WORKLOAD KIND instead
	// (internal/report/workload_rollup.go, mirrored in cmd/shoalcheck-mcp), which needs nothing this product does
	// not already collect. Populating this field is a change to the collector and to what every surface may
	// say about ownership; it is not a gap to close casually, and until somebody closes it deliberately this
	// comment is the honest description.
	OwnerChain []OwnerLink `json:"ownerChain,omitempty"`
}

// OwnerLink is a single step in a resource's ownership chain.
type OwnerLink struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid,omitempty"`
}

// Provenance records which collector produced a finding.
//
// Collector accepts "kubernetes" | "polaris" | "opencost". v0 produces only
// "kubernetes" (and even that is hand-crafted in fixtures), but the schema
// accepts the future values forward-compatibly so Phase 2+ collectors slot in.
type Provenance struct {
	Collector string `json:"collector"`
	Version   string `json:"version"`
}
