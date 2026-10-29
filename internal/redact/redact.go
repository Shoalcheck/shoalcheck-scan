// Package redact rewrites an AuditReport so it can be shared outside the
// operator's trust boundary: cluster name, node names, namespaces, workload
// names, and RBAC subjects are replaced with stable, opaque tokens. The
// finding shapes, counts, dollars, severities, and remediation STRUCTURE are
// preserved — only the identifying strings change. Tokens are deterministic
// (same input → same token) so a redacted report still reads coherently and
// two runs diff cleanly, but the originals cannot be recovered from the output.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// token derives a stable opaque token like "ns-3f9a2b" from a prefix + value.
func token(prefix, val string) string {
	h := sha256.Sum256([]byte(prefix + "|" + val))
	return prefix + "-" + hex.EncodeToString(h[:])[:6]
}

// Fleet redacts the fleet envelope. The child reports are redacted by the pipeline as each cluster is
// audited, so the only thing left here is the one field a child cannot carry: the contexts that were asked
// for and could not be read.
//
// SkippedCluster.Context SAID IT WAS NOT CLUSTER DATA — "a local name the operator chose" — and that is true
// in principle and false on every managed cluster. A kubeconfig context is written by cloud tooling: an EKS
// one is `arn:aws:eks:<region>:<account-id>:cluster/<name>`, a GKE one is `gke_<project>_<zone>_<cluster>`,
// an AKS one is the cluster's own name. Redacting the cluster's name two fields away while printing the
// context that contains it, the account that owns it and the region it runs in is not a coherent position.
//
// TOKENIZED RATHER THAN BLANKED. A reader has to be able to tell two unreachable clusters apart, and an
// empty string says one was never asked for — which is the same "an absence is not a state" mistake this
// product refuses everywhere else. The reason is left verbatim: it is a classified value from this product's
// own vocabulary, never the API's error text.
func Fleet(fr *types.FleetReport) *types.FleetReport {
	if fr == nil {
		return nil
	}
	out := *fr
	out.Skipped = tokenizeSkipped(fr.Skipped)
	// THE SAME LIST, REACHED TWICE. FleetDivergence.Unreached is built from the same skipped slice, before
	// this function runs — so redacting one and not the other would leak the context AND disagree with the
	// field two screens away about what that cluster is called. Both go through the same token, so the two
	// surfaces name it identically.
	if fr.Divergence != nil {
		nd := *fr.Divergence
		nd.Unreached = tokenizeSkipped(fr.Divergence.Unreached)
		out.Divergence = &nd
	}
	return &out
}

func tokenizeSkipped(in []types.SkippedCluster) []types.SkippedCluster {
	if in == nil {
		return nil
	}
	out := make([]types.SkippedCluster, len(in))
	for i, s := range in {
		ns := s
		if ns.Context != "" {
			ns.Context = token("context", s.Context)
		}
		out[i] = ns
	}
	return out
}

// Report returns a redacted deep-ish copy of ar. The input is not mutated.
func Report(ar *types.AuditReport) *types.AuditReport {
	if ar == nil {
		return nil
	}
	idents := gatherIdentifiers(ar)
	rep := buildReplacer(idents)

	out := *ar // shallow copy; we rebuild every slice/string field we touch

	// A STABLE TOKEN, NOT THE CONSTANT "cluster", and a fleet is why.
	//
	// This used to assign the literal string. FleetReport.Validate rejects a duplicate cluster name — the
	// type says "Cluster.Name is the stable key for the switcher" — so the moment `shoalcheck fleet --redact`
	// audited a SECOND cluster the document failed validation and no fleet came out at all. The feature that
	// makes a reading shareable was unusable on the reading that most needs sharing.
	//
	// The token is derived from the name, so two readings of one cluster tokenize identically and stay
	// comparable, and two clusters in one fleet stay distinct.
	out.Cluster.Name = token("cluster", ar.Cluster.Name)
	out.Cluster.Region = rep(ar.Cluster.Region)
	// The kubeconfig context is never serialized, but the instrument prints it in the empty "Since the last
	// reading" command — and a context is usually named after the cluster. A redacted document prints no command
	// with a real context in it. The copy keeps the licence identity (ClusterUID/ClusterName) the charge needs.
	if ar.Identity != nil && ar.Identity.Context != "" {
		id := *ar.Identity
		id.Context = ""
		out.Identity = &id
	}
	// Free text the operator typed may name anything — a cluster, a customer, a ticket. Cleared, not tokenized:
	// a token stands for a name, and a label is a sentence.
	out.Methodology.Label = ""

	// PolicyPosture carries a NAMESPACE NAME PER ROW, which is customer data and the same string the
	// Architecture namespaces above are redacted for. It is the FOURTH field to reach the schema after this
	// function and need rebuilding by hand — after Architecture.NodePools, Architecture.Flows and
	// Architecture.UnpricedStorageClasses — which is the shape completeness_test.go exists to catch, and it
	// caught this one only once the sentinel was taught to populate the field.
	//
	// OPERATORS ARE HARVESTED AND TOKENIZED, ALL OF THEM. The first version of this reasoned that a vendor
	// group like `cert-manager.io` is public and could be left verbatim while a customer's own group was
	// caught by the registry — and the sentinel test refuted it immediately, because nothing else in a
	// report registers `acmebank.internal`, so it survived intact.
	//
	// There is no rule separating the two that does not fail open: a known-vendor allowlist leaks every
	// group not on it, which is precisely the customer-authored ones. So all of them are registered in
	// gatherIdentifiers and replaced here.
	//
	// NOTHING IS LOST BY THIS. Architecture.Stack already carries vendor identity for a human reader and its
	// Name field is deliberately NOT redacted, so a redacted document still says cert-manager is installed.
	// PolicyPosture.Operators is a COMPARISON KEY — the fleet divergence surface asks whether two clusters
	// hold the same set — and a consistently tokenized key compares identically to an untokenized one.
	if ar.PolicyPosture != nil {
		pp := *ar.PolicyPosture
		pp.Operators = repSlice(rep, ar.PolicyPosture.Operators)
		pp.Namespaces = make([]types.NamespacePosture, len(ar.PolicyPosture.Namespaces))
		for i, np := range ar.PolicyPosture.Namespaces {
			nnp := np
			nnp.Name = rep(np.Name)
			// The PSA labels are a CLOSED Kubernetes vocabulary — privileged / baseline / restricted — so
			// they are not customer strings and are left as read. Redacting them would delete the only
			// content of the row.
			pp.Namespaces[i] = nnp
		}
		out.PolicyPosture = &pp
	}

	// THE PROSE AND THE PATCHES ALSO GO THROUGH THE SHAPES: the names no structured field carries — a container's,
	// a ServiceAccount's in a binding's sentence, a label map, a Prometheus job, an image repository. See shapes.go.
	prose := func(s string) string { return scrubShapes(rep(s)) }

	out.Findings = make([]types.Finding, len(ar.Findings))
	for i, f := range ar.Findings {
		nf := f
		nf.Title = prose(f.Title)
		nf.Description = prose(f.Description)
		nf.WhyItMatters = prose(f.WhyItMatters)
		nf.Evidence = repSlice(prose, f.Evidence)
		// ScopedTo carries PolicyRule.ResourceNames — customer-chosen object names, and the single most
		// identifying strings a dangerous-grant finding prints. Rebuilt here AND registered in
		// gatherIdentifiers, because either alone is useless: registering without rebuilding leaves the
		// field verbatim, and rebuilding without registering leaves the name unmatched in the evidence
		// sentence beside it. The sentinel test caught it half-redacted — "acme-prod-res-cbba08-credentials",
		// because one word of it happened to be registered from elsewhere — which is worse than an obvious
		// leak, since it reads as though redaction worked.
		nf.ScopedTo = repSlice(rep, f.ScopedTo)
		nf.RemediationYAML = scrubPatchContainers(prose(f.RemediationYAML))
		nf.RemediationCommand = prose(f.RemediationCommand)
		nf.AffectedResources = make([]types.ResourceRef, len(f.AffectedResources))
		for j, r := range f.AffectedResources {
			nf.AffectedResources[j] = redactRef(r, rep)
		}

		// IDBASIS CARRIES CUSTOMER TEXT and goes through the SAME function an affected resource does. It is
		// the three slots a finding's id was hashed from, so a redacted report cannot be used to check an id —
		// which was already true of every id, because the recipe needs the real names.
		//
		// One function rather than two copies, because the structural sentinel caught the second copy missing
		// the nested owner chain within a minute of it being written. Two places rewriting one shape is two
		// places to forget a field.
		if f.IDBasis != nil {
			nb := redactRef(*f.IDBasis, rep)
			nf.IDBasis = &nb
		}

		// CLAIM BOUNDARIES ARE OUR OWN SENTENCES and carry no identifier by design — but a CONDITIONAL one is
		// written by a rule at Evaluate time about this particular run, and a rule that named a namespace in
		// one would be exactly the leak B-156 was. They go through the replacer rather than being trusted,
		// which costs nothing and cannot be forgotten by whoever writes the next conditional boundary.
		nf.ClaimBoundaries = repSlice(prose, f.ClaimBoundaries)

		// AN OWNER IS A TEAM NAME the operator chose, which is exactly the class of identifier --redact
		// exists to remove before a report leaves an organisation.
		nf.Owner = rep(f.Owner)

		out.Findings[i] = nf
	}

	if ar.Architecture != nil {
		out.Architecture = redactArchitecture(ar.Architecture, rep)
	}
	if len(ar.Compliance) > 0 {
		out.Compliance = make([]types.ComplianceRow, len(ar.Compliance))
		for i, c := range ar.Compliance {
			nc := c
			nc.Title = rep(c.Title)
			out.Compliance[i] = nc
		}
	}
	if ar.ComplianceAssessment != nil {
		out.ComplianceAssessment = redactComplianceAssessment(ar.ComplianceAssessment, rep)
	}
	out.Methodology.DataSources = repSlice(prose, ar.Methodology.DataSources)

	if len(ar.Highlights) > 0 {
		out.Highlights = make([]types.Highlight, len(ar.Highlights))
		for i, h := range ar.Highlights {
			nh := h
			nh.Label = rep(h.Label)
			nh.Value = rep(h.Value)
			nh.Detail = rep(h.Detail)
			out.Highlights[i] = nh
		}
	}

	// The cluster UID is not a NAME, so the replacer has no token for it — and it is the strongest
	// identifier in the document: anyone with access to the cluster can confirm in one command that a
	// "redacted" report is about theirs. It is tokenized rather than dropped, deterministically and with the
	// same hash the names use, so two redacted readings of the same cluster remain comparable to the tooling
	// while the raw UID is gone.
	// ── FIELDS THE HAND-BUILT SENTINEL NEVER PLANTED, and therefore never checked ──────────────
	//
	// F-1 of the Phase 2 adversarial review. structural_test.go walks the schema by reflection and found
	// that Report rebuilt a fraction of it: Peers, Relationships, Narratives, Assessments, SectionLedes,
	// the session trace and the trend caveat all passed through a --redact document untouched. Each is
	// prose or a name this product generates ABOUT the customer's cluster, which is exactly the material
	// that must not leave their organisation.

	// Peers and Relationships are the FLEET fields, and they carry other clusters' NAMES — the one string
	// Report has always replaced for the audited cluster and never for its neighbours.
	out.Peers = make([]types.ClusterPeer, len(ar.Peers))
	for i, p := range ar.Peers {
		np := p
		np.Name = rep(p.Name)
		np.Region = rep(p.Region)
		np.Description = rep(p.Description)
		out.Peers[i] = np
	}
	out.Relationships = make([]types.ClusterRelationship, len(ar.Relationships))
	for i, r := range ar.Relationships {
		nr := r
		nr.From = rep(r.From)
		nr.To = rep(r.To)
		nr.Note = rep(r.Note)
		out.Relationships[i] = nr
	}

	// Narratives and the section ledes are generated prose that names workloads and namespaces by
	// construction — they exist to say what the reader is looking at.
	out.Narratives = make([]types.Narrative, len(ar.Narratives))
	for i, n := range ar.Narratives {
		nn := n
		nn.Title = rep(n.Title)
		nn.Body = rep(n.Body)
		out.Narratives[i] = nn
	}
	if ar.SectionLedes != nil {
		out.SectionLedes = make(map[string]string, len(ar.SectionLedes))
		for k, v := range ar.SectionLedes {
			// The KEY is a section identifier this product mints ("findings", "architecture"); the VALUE
			// is the lede sentence, which names what it is about.
			out.SectionLedes[k] = rep(v)
		}
	}

	// The domain assessments: four slices of the same shape, each carrying a Detail sentence about the
	// cluster and a Recommended sentence about what to do to it.
	if ar.Assessments != nil {
		na := *ar.Assessments
		na.Observability = redactChecks(ar.Assessments.Observability, rep)
		na.GitOps = redactChecks(ar.Assessments.GitOps, rep)
		na.Deployments = redactChecks(ar.Assessments.Deployments, rep)
		na.Alerts = redactChecks(ar.Assessments.Alerts, rep)
		out.Assessments = &na
	}

	// The session trace's SCOPE is a namespace name on every namespaced row. Resource, Verbs, Outcome,
	// Class, Paths, Ref and ConsumedBy are all vocabulary this product or Kubernetes mints and stay as
	// read — a redacted trace that hid which VERBS were used would defeat the ledger's purpose.
	//
	// SessionTrace is a POINTER and is nil on a report produced without one. The structural gate cannot
	// catch that — it allocates every pointer it walks, precisely so a nil field is still classified — so
	// the two tests here check different things and both are needed.
	if st := ar.Methodology.SessionTrace; st != nil {
		nst := *st
		if len(st.Rows) > 0 {
			rows := make([]types.SessionTraceRow, len(st.Rows))
			for i, r := range st.Rows {
				nr := r
				nr.Scope = rep(r.Scope)
				rows[i] = nr
			}
			nst.Rows = rows
		}
		// An exec credential plugin is usually a well-known binary name, and is sometimes a path into the
		// operator's own tooling.
		nst.ExecCredentialPlugin = rep(st.ExecCredentialPlugin)
		out.Methodology.SessionTrace = &nst
	}

	// The trend caveat is prose naming what could not be compared.
	// The calendar's object rows name a namespace and an object — the same strings the finding they came from
	// registers — and its observation sentence quotes them, so the row is rebuilt through the replacer like a
	// finding is. NotAssessed is prose this product authors about its own coverage and names no cluster object;
	// it is copied, and classified as such in structural_test.go.
	if ar.Calendar != nil {
		nc := types.Calendar{Rows: make([]types.CalendarRow, len(ar.Calendar.Rows)), NotAssessed: append([]types.ClockNotAssessed(nil), ar.Calendar.NotAssessed...)}
		for i, r := range ar.Calendar.Rows {
			nr := r
			nr.Observation = rep(r.Observation)
			nr.FindingIDs = append([]string(nil), r.FindingIDs...)
			if r.Object != nil {
				o := *r.Object
				o.Namespace = rep(r.Object.Namespace)
				o.Name = rep(r.Object.Name)
				o.OwnerChain = make([]types.OwnerLink, len(r.Object.OwnerChain))
				for k, l := range r.Object.OwnerChain {
					nl := l
					nl.Name = rep(l.Name)
					o.OwnerChain[k] = nl
				}
				nr.Object = &o
			}
			nc.Rows[i] = nr
		}
		out.Calendar = &nc
	}
	// The headline's claims and bases QUOTE the cluster's own objects — a PodDisruptionBudget's namespace and
	// name arrive in a basis line verbatim from a finding's evidence. Rebuilt through the same replacer the
	// findings use; the finding ids it carries are already tokens.
	if ar.Headline != nil {
		nh := *ar.Headline
		nh.Lines = make([]types.HeadlineLine, len(ar.Headline.Lines))
		for i, l := range ar.Headline.Lines {
			nl := l
			nl.Claim = rep(l.Claim)
			nl.Basis = rep(l.Basis)
			nl.FindingIDs = append([]string(nil), l.FindingIDs...)
			nh.Lines[i] = nl
		}
		nh.Remainder = rep(ar.Headline.Remainder)
		nh.Trace = rep(ar.Headline.Trace)
		out.Headline = &nh
	}
	if ar.Trend != nil {
		nt := *ar.Trend
		nt.ReferenceDataReason = rep(ar.Trend.ReferenceDataReason)
		// The two readings' labels are operator free text, the same words Methodology.Label carried; cleared for
		// the same reason. The counts and the gates' own sentences are ours and stay.
		nt.Label, nt.PreviousLabel = "", ""
		// The findings that left are named by the EARLIER reading's titles, and those can name an object this
		// reading never held — deleted between the two — whose name the replacer, built from this reading, does
		// not know. Withheld, not replaced: fail closed. The id, rule and severity are ours and travel.
		if len(ar.Trend.NoLongerInSet) > 0 {
			nt.NoLongerInSet = make([]types.TrendFinding, len(ar.Trend.NoLongerInSet))
			for i, g := range ar.Trend.NoLongerInSet {
				g.Title = ""
				nt.NoLongerInSet[i] = g
			}
		}
		out.Trend = &nt
	}

	if sim := ar.Methodology.Simulation; sim != nil {
		ns := *sim
		ns.Files = repSlice(rep, sim.Files)
		redactObjects := func(in []types.SimulatedObject) []types.SimulatedObject {
			if in == nil {
				return nil
			}
			out := make([]types.SimulatedObject, len(in))
			for i, o := range in {
				o.Namespace, o.Name, o.File, o.Reason = rep(o.Namespace), rep(o.Name), rep(o.File), rep(o.Reason)
				out[i] = o
			}
			return out
		}
		ns.Objects = redactObjects(sim.Objects)
		ns.NotEvaluated = redactObjects(sim.NotEvaluated)
		ns.NotSimulated = repCopy(sim.NotSimulated)
		out.Methodology.Simulation = &ns
	}

	if b := ar.Methodology.RunBasis; b != nil {
		nb := *b
		if nb.ClusterUID != "" {
			nb.ClusterUID = token("uid", nb.ClusterUID)
		}
		// THE OWNER LABEL KEY IS THE OPERATOR'S OWN CONVENTION, and a key like `acmecorp.io/owning-squad`
		// names the company as plainly as any value does. The COUNTS beside it survive: "12 of 134 findings
		// have an owner" is arithmetic and says nothing about who anybody is.
		nb.OwnerLabel = rep(b.OwnerLabel)
		// Stamped beside the token so a comparison can say "one of these was redacted" instead of asserting
		// two clusters when the UIDs differ.
		nb.Redacted = true
		out.Methodology.RunBasis = &nb
	}
	return &out
}

// redactComplianceAssessment deep-copies the assessment and tokenizes each
// control Title (the only PII-bearing field — it can echo a workload/namespace
// name, e.g. a remediation-style title). Control numbers, EvidenceRuleIDs, and
// FindingIDs are stable rule/finding identifiers, not customer identifiers, so
// they pass through unchanged. The Score is a pure tally and is copied as-is.
// The input is not mutated (slices/maps are rebuilt).
func redactComplianceAssessment(a *types.ComplianceAssessment, rep func(string) string) *types.ComplianceAssessment {
	na := *a
	na.Controls = make([]types.ComplianceControl, len(a.Controls))
	for i, c := range a.Controls {
		nc := c
		nc.Title = rep(c.Title)
		nc.FindingIDs = repCopy(c.FindingIDs)
		nc.EvidenceRuleIDs = repCopy(c.EvidenceRuleIDs)
		na.Controls[i] = nc
	}
	if a.Score.Totals != nil {
		na.Score.Totals = make(map[types.ControlStatus]int, len(a.Score.Totals))
		for k, v := range a.Score.Totals {
			na.Score.Totals[k] = v
		}
	}
	return &na
}

// repCopy returns a fresh copy of a string slice without tokenizing (used for
// non-PII identifier lists so redaction never aliases the input slice).
func repCopy(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func redactArchitecture(a *types.Architecture, rep func(string) string) *types.Architecture {
	na := *a
	// Prose this product generates ABOUT the observed map — it names namespaces and workloads to say what
	// was observed.
	na.ObservedNote = rep(a.ObservedNote)
	na.AZs = make([]types.AZ, len(a.AZs))
	for i, az := range a.AZs {
		naz := az
		// The zone's own name. Cluster.Region has always been replaced and this had not been — the same
		// locating fact, one level down.
		naz.Name = rep(az.Name)
		naz.Nodes = make([]types.NodeRef, len(az.Nodes))
		for j, n := range az.Nodes {
			nn := n
			nn.Name = rep(n.Name)
			nn.Namespace = rep(n.Namespace)
			naz.Nodes[j] = nn
		}
		na.AZs[i] = naz
	}
	na.Namespaces = make([]types.NamespaceSummary, len(a.Namespaces))
	for i, ns := range a.Namespaces {
		nns := ns
		nns.Name = rep(ns.Name)
		nns.Description = rep(ns.Description)
		// Workloads is a comma-joined list of workload NAMES, not a count. It was the last survivor the
		// sentinel test caught, and it is the field a reader looks at first.
		nns.Workloads = rep(ns.Workloads)
		na.Namespaces[i] = nns
	}
	na.Stack = make([]types.StackEntry, len(a.Stack))
	for i, s := range a.Stack {
		ns := s
		ns.Note = rep(s.Note)
		na.Stack[i] = ns
	}
	na.Topologies = make([]types.NamespaceTopology, len(a.Topologies))
	for i, t := range a.Topologies {
		nt := t
		nt.Name = rep(t.Name)
		nt.Workloads = make([]types.WorkloadNode, len(t.Workloads))
		for j, w := range t.Workloads {
			nw := w
			nw.Name = rep(w.Name)
			nw.ID = rep(w.ID)
			nt.Workloads[j] = nw
		}
		nt.Services = make([]types.ServiceNode, len(t.Services))
		for j, sv := range t.Services {
			nsv := sv
			nsv.Name = rep(sv.Name)
			nsv.ID = rep(sv.ID)
			nsv.Note = rep(sv.Note)
			nt.Services[j] = nsv
		}
		nt.Edges = make([]types.GraphEdge, len(t.Edges))
		for j, e := range t.Edges {
			ne := e
			ne.From = rep(e.From)
			ne.To = rep(e.To)
			// An edge label is generated from what the edge IS — a port name, a service name.
			ne.Label = rep(e.Label)
			// An edge label is generated from what the edge IS — a port name, a service name.
			ne.Label = rep(e.Label)
			nt.Edges[j] = ne
		}
		na.Topologies[i] = nt
	}
	// ObservedEdges carry "Kind/Name" workload identifiers (or external/<name>)
	// in From/To — tokenize them the same way WorkloadNode.ID is tokenized, so
	// the observed map never leaks real workload names. The rep replacer is
	// identifier-aware; an "external/foo" segment is replaced on its "foo"
	// identifier the same as any other workload name. The scalar observed fields
	// (Tier/ObservedSource/ObservedWindow/ObservedAsOf/ObservedNote) carry no
	// cluster identifiers and copy via the `na := *a` shallow assignment above.
	if len(a.ObservedEdges) > 0 {
		na.ObservedEdges = make([]types.ObservedEdge, len(a.ObservedEdges))
		for i, e := range a.ObservedEdges {
			ne := e
			ne.From = rep(e.From)
			ne.To = rep(e.To)
			na.ObservedEdges[i] = ne
		}
	}
	// UnpricedNodeTypes are instance types (m6i.xlarge) and name nobody, so they pass through. StorageClass
	// names are customer-chosen and do not.
	na.UnpricedStorageClasses = repSlice(rep, a.UnpricedStorageClasses)

	na.NodePools = make([]types.NodePoolSummary, len(a.NodePools))
	for i, p := range a.NodePools {
		np := p
		np.Type = rep(p.Type)
		np.Spec = rep(p.Spec)
		na.NodePools[i] = np
	}

	na.Flows = make([]types.FlowDiagram, len(a.Flows))
	for i, fl := range a.Flows {
		nf := fl
		nf.ID = rep(fl.ID)
		nf.Title = rep(fl.Title)
		nf.Steps = make([]types.FlowStep, len(fl.Steps))
		for j, st := range fl.Steps {
			nst := st
			nst.Label = rep(st.Label)
			nst.Namespace = rep(st.Namespace)
			nst.Note = rep(st.Note)
			nf.Steps[j] = nst
		}
		na.Flows[i] = nf
	}

	na.RBAC = make([]types.RBACEntry, len(a.RBAC))
	for i, e := range a.RBAC {
		ne := e
		ne.Subject = rep(e.Subject)
		ne.Binding = rep(e.Binding)
		ne.Role = rep(e.Role)
		// THE SENTENCE CARRIES THE NAME IN A DIFFERENT FORM FROM THE FIELD. The subject is harvested as it
		// appears in Subject — "Group/acme-payments-admins" — and the description says "Group
		// acme-payments-admins bound to …", so the global replacement never matched and a customer's
		// directory group survived --redact beside its own token. Measured on a live reading with
		// system:masters, which is harmless; the same sentence on a real cluster names the company.
		//
		// The bare name is replaced ONLY inside this entry's own description, never registered as a global
		// identifier: a subject called "User/admin" would otherwise rewrite "cluster-admin" everywhere,
		// because the boundary rule counts "-" as a boundary. A scoped replacement needs no such judgement.
		ne.Description = rep(subjectNameInSentence(e.Subject, e.Description, rep))
		na.RBAC[i] = ne
	}
	return &na
}

// isRBACKind reports whether a reference is to one of the four RBAC object kinds, which is where an upstream
// name is a public fact rather than an identifier.
func isRBACKind(kind string) bool {
	switch kind {
	case "ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding":
		return true
	}
	return false
}

// bareSubjectName is the identity half of a chain's Subject — "Group/acme-admins" → "acme-admins" — or ""
// when there is nothing safe to register: an unqualified string, a name the Kubernetes project ships, or one
// short enough to appear inside ordinary words.
func bareSubjectName(subject string) string {
	i := strings.LastIndex(subject, "/")
	if i < 0 || i+1 >= len(subject) {
		return ""
	}
	bare := subject[i+1:]
	// AND THE NAMESPACE IN FRONT OF IT. A subject reads "<ns>/<name>" for a ServiceAccount, and the
	// ServiceAccounts Kubernetes ships live in the namespaces it reserves. Registering one of those bare
	// names rewrote the TAIL of an upstream ClusterRole that contains it — measured on a live reading, where
	// "kube-system/clusterrole-aggregation-controller" turned
	// "system:controller:clusterrole-aggregation-controller" into "system:controller:subj-…", a role that
	// does not exist. A name that identifies nobody is not worth that.
	if ns := subject[:i]; types.KubernetesOwnNamespace(ns) || types.KubernetesOwnNamespace(strings.TrimPrefix(ns, "ServiceAccount/")) {
		return ""
	}
	switch {
	case len(bare) < 4:
		return ""
	case strings.HasPrefix(bare, "system:"), strings.HasPrefix(bare, "kubeadm:"):
		return ""
	case bare == "default", bare == "cluster-admin":
		return ""
	}
	return bare
}

// subjectNameInSentence replaces the bare subject name inside one chain's own description with the token its
// Subject field gets, so "Group acme-payments-admins bound to X" cannot survive when "Group/acme-payments-
// admins" is tokenised. Scoped to this entry: the name is not registered anywhere and nothing else in the
// report is touched by it.
func subjectNameInSentence(subject, description string, rep func(string) string) string {
	if subject == "" || description == "" {
		return description
	}
	bare := subject
	if i := strings.LastIndex(subject, "/"); i >= 0 && i+1 < len(subject) {
		bare = subject[i+1:]
	}
	if bare == "" || bare == subject {
		return description
	}
	token := rep(subject)
	if token == subject {
		return description // nothing was tokenised for this subject, so there is nothing to hide
	}
	return strings.ReplaceAll(description, bare, token)
}

func repSlice(rep func(string) string, in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = rep(s)
	}
	return out
}

// gatherIdentifiers collects the sensitive strings from the report's STRUCTURED
// fields (the reliable source of truth) and maps each to a token. Free-text
// fields are then scrubbed by replacing every occurrence of these identifiers.
func gatherIdentifiers(ar *types.AuditReport) map[string]string {
	m := map[string]string{}
	add := func(prefix, val string) {
		if val == "" || val == "default" || val == "cluster" {
			return
		}
		if _, ok := m[val]; !ok {
			m[val] = token(prefix, val)
		}
	}
	if ar.Cluster.Name != "" {
		m[ar.Cluster.Name] = "cluster"
	}
	// THE REGION AND EVERY ZONE. Both fields were already passed through rep() — line 93 and the AZ loop,
	// whose comment says the zone name "had not been" replaced and now is — and neither string was ever
	// HARVESTED, so both calls were no-ops that read as fixes. Measured on a live redacted reading of the
	// testbed: cluster.region "eu-central-1" and three zones "eu-central-1a/b/c", intact.
	//
	// A region is a locating fact: Frankfurt narrows the customer, and on a private cloud a "region" is a
	// site name. It is the same argument this project used to keep the region out of the support bundle.
	//
	// Zones are harvested as well as the region, and the replacer applies identifiers LONGEST-FIRST, so
	// "eu-central-1a" is replaced as a zone rather than as the region plus a stray "a".
	add("region", ar.Cluster.Region)
	if ar.Architecture != nil {
		for _, az := range ar.Architecture.AZs {
			add("zone", az.Name)
		}
	}
	// A PEER'S REGION TOO. Peers are other clusters in the same org — their names and regions have always
	// gone through rep() here, and the same no-op applied to them.
	for _, p := range ar.Peers {
		add("region", p.Region)
	}
	if ar.PolicyPosture != nil {
		for _, g := range ar.PolicyPosture.Operators {
			// See Report's PolicyPosture block: every operator group, not a heuristic subset. A group is a
			// DNS-style name and a customer's own is indistinguishable from a vendor's without an allowlist
			// that fails open on exactly the ones that matter.
			//
			// WITH ONE EXCEPTION, AND IT IS NOT A VENDOR ALLOWLIST. The groups the Kubernetes project itself
			// ships are a closed set present on every cluster in the world; they identify nobody, and two of
			// them — `apps` and `batch` — are ordinary English words. Registering them rewrote the sentence
			// "a wide kernel surface most apps never use" into a token, and made `apps/v1` unreadable in
			// every place it appeared: measured on a live reading, 45 occurrences and not one surviving
			// `apps/v1`. The failing-open argument above is about vendors and does not reach here, because
			// no customer can own `apps`: Kubernetes already does.
			if kubernetesOwnGroup(g) {
				continue
			}
			add("grp", g)
		}
		for _, np := range ar.PolicyPosture.Namespaces {
			add("ns", np.Name)
		}
	}
	for _, f := range ar.Findings {
		for _, r := range f.AffectedResources {
			add("ns", r.Namespace)
			// The RBAC objects Kubernetes itself ships keep their names: see types.KubernetesOwnRBACName.
			// Keyed on the KIND as well, so a Deployment somebody called "cluster-admin" is a customer
			// object like any other and still gets a token.
			if isRBACKind(r.Kind) && types.KubernetesOwnRBACName(r.Name) {
				continue
			}
			add("res", r.Name)
			for _, o := range r.OwnerChain {
				add("res", o.Name)
			}
		}
		// The objects a grant is scoped to. They are object names like any other and get object tokens; what
		// makes them a distinct source is that nothing else in the report carries them — a ClusterRole's
		// AffectedResources entry names the ROLE, not the Secret the role can read.
		for _, n := range f.ScopedTo {
			add("res", n)
		}
	}
	// Calendar rows come from findings and so are normally registered already; registering them here as well
	// means a hand-built or future row whose object is in no finding still gets a token, and its observation
	// sentence is rewritten with it.
	if ar.Calendar != nil {
		for _, r := range ar.Calendar.Rows {
			if r.Object != nil {
				add("ns", r.Object.Namespace)
				add("res", r.Object.Name)
				for _, o := range r.Object.OwnerChain {
					add("res", o.Name)
				}
			}
		}
	}
	if a := ar.Architecture; a != nil {
		for _, az := range a.AZs {
			for _, n := range az.Nodes {
				add("node", n.Name)
				add("ns", n.Namespace)
			}
		}
		for _, ns := range a.Namespaces {
			add("ns", ns.Name)
		}
		for _, t := range a.Topologies {
			add("ns", t.Name)
			for _, w := range t.Workloads {
				add("res", w.Name)
			}
			for _, sv := range t.Services {
				add("res", sv.Name)
			}
		}
		for _, e := range a.RBAC {
			add("subj", e.Subject)
			if !types.KubernetesOwnRBACName(e.Binding) {
				add("subj", e.Binding)
			}
			if !types.KubernetesOwnRBACName(e.Role) {
				add("subj", e.Role)
			}
			// AND THE BARE NAME, because the rules write it that way in free text: the chain says
			// "User/deploy@acme.example" and a finding's evidence says "ClusterRoleBinding X names User
			// deploy@acme.example, and reaches cluster-wide". Measured on a live kind reading, where the
			// surviving name was kube-apiserver-kubelet-client; on a customer's cluster the same sentence
			// carries a person.
			//
			// TWO GUARDS, because a bare name is a weaker identifier than a qualified one. The groups and
			// users the Kubernetes project ships are a closed set that identifies nobody — the same argument
			// kubernetesOwnGroup makes one block up — and a name under four characters is not registered at
			// all: "edit" or "view" as a token would rewrite ordinary words, and the shortest real identity
			// on a cluster is longer than that.
			add("subj", bareSubjectName(e.Subject))
		}
		// Node-pool names, StorageClass names and flow-step labels are customer-chosen and appear ONLY here:
		// nothing in the findings registers them, so without this the replacer has no token for them and
		// rebuilding those fields would change nothing. A pool called "acme-payments-workers" and a
		// StorageClass called "acmebank-fast-ssd" name the customer as plainly as a namespace does.
		for _, p := range a.NodePools {
			add("pool", p.Type)
		}
		for _, sc := range a.UnpricedStorageClasses {
			add("sc", sc)
		}
		for _, fl := range a.Flows {
			for _, st := range fl.Steps {
				add("ns", st.Namespace)
				// A flow step's label is a workload name — or, for an external step, the client's own public
				// hostname, which is the single most identifying string the report can contain.
				add("res", st.Label)
			}
		}
		// HIGHLIGHT VALUES ARE NOT REGISTERED, and registering them was the worst defect this package has
		// had. `highlight(section, label string, count int, …)` builds every one of them, so Value is always
		// a COUNT — "1", "15" — and never a name. Handing those to a substring replacer made every digit-1
		// in the document a candidate: measured on a live 188-finding reading, the token for "1" appeared
		// 391 times across 61 evidence lines, `spec.replicas = 1` became `spec.replicas = res-7cf452`, and
		// the closing summary read "res-7cf45287 more in the document".
		//
		// Nothing is lost by removing it. A count identifies nobody, and every NAME a highlight's detail
		// might mention is registered from the finding it was derived from.
		for _, e := range a.ObservedEdges {
			// Register the bare workload name from each endpoint so rep() tokenizes
			// it inside the "Kind/Name" or "external/Name" form. Endpoints not also
			// in a topology (e.g. a source-only workload or an external SaaS) would
			// otherwise leak unredacted.
			add("res", lastSegment(e.From))
			add("res", lastSegment(e.To))
		}
	}
	// A SIMULATED READING NAMES WHAT IT LAID OVER — namespaces, object names and the manifest files they came from —
	// and an object the change creates has no finding to have registered its name already. A file path is the
	// repository's layout, which can name a team, a customer or a service as plainly as a namespace can.
	if sim := ar.Methodology.Simulation; sim != nil {
		for _, f := range sim.Files {
			add("file", f)
		}
		for _, o := range append(append([]types.SimulatedObject(nil), sim.Objects...), sim.NotEvaluated...) {
			add("ns", o.Namespace)
			add("res", o.Name)
			add("file", o.File)
		}
	}
	return m
}

// lastSegment returns the substring after the final "/" — the bare workload name
// from a "Kind/Name" or "external/Name" ObservedEdge endpoint.
func lastSegment(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// buildReplacer returns a function that replaces every known identifier with
// its token. Identifiers are applied longest-first so compound names
// (payments-gateway) are replaced before their substrings (payments).
// kubernetesOwnGroup reports whether an API group is one the Kubernetes project ships.
//
// A CLOSED LIST, WHICH IS WHY IT IS SAFE. These are the groups in the upstream API surface: they exist on
// every cluster, a customer cannot own one, and excluding them leaks nothing. It is written out rather than
// matched by suffix because `*.k8s.io` is not a reliable test in either direction — `metrics.k8s.io` is
// upstream and `cert-manager.k8s.io` was somebody's.
// kubernetesOwnGroup defers to types.KubernetesOwnGroup, which is the one copy of this closed list.
//
// IT WAS TWO COPIES AND THEY HAD DIFFERENT CONTENTS. internal/collect excluded only "" and *.k8s.io when
// listing an operator's group, so `apps`, `batch`, `policy` and `autoscaling` were reported as installed
// operators on every cluster; this list had them and that one did not. A closed list kept in two places is
// two lists.
func kubernetesOwnGroup(g string) bool { return types.KubernetesOwnGroup(g) }

// wordChar is a letter or a digit, and it is the boundary test — deliberately NOT the whole character class
// a Kubernetes name is made of.
//
// THE DIFFERENCE IS THE WHOLE POINT, and the first version got it wrong in the safe-looking direction. A pod
// is named after its workload with a suffix: `stripe-webhook-7d4f` CONTAINS `stripe-webhook`, and a flow id
// embeds a namespace as `flow-payments-prod`. Those are real leaks and must be replaced, so `-`, `.`, `_`,
// `/` and punctuation are all boundaries. What must NOT be replaced is a match that continues into a word or
// a number: `waste` inside `wasteful`, `1` inside `187`. Only a letter or a digit does that.
var wordChar = regexp.MustCompile(`[A-Za-z0-9]`)

// buildReplacer swaps whole identifiers, and only whole ones.
//
// IT USED TO BE strings.NewReplacer OVER THE RAW KEYS, which replaces any occurrence anywhere. A namespace
// called "waste" rewrote "wasteful"; a highlight value of "1" rewrote the "1" in "187 more in the document".
// A redacted reading is the artifact a customer forwards, and one that says `spec.replicas = res-7cf452` has
// not protected anything — it has lost the arithmetic and looks broken to the person it was made for.
//
// LONGEST KEY FIRST is kept: a name that contains another name must win, or the shorter one tokenizes half
// of it and the remainder leaks. The boundary test is applied to the WHOLE match, so a longer identifier
// still wins its own span.
//
// A TRIE, NOT ONE ALTERNATION OF EVERY NAME. It was a regexp of every identifier joined by "|", longest first,
// and its answer is the definition this keeps: scanning left to right, at each position the LONGEST identifier
// that starts there is the match (which is what leftmost-first alternation over longest-first keys picks); the
// scan resumes after it whether or not the boundary test lets it be replaced; and where nothing starts, the scan
// moves one character on. On a 2,000-node cluster's reading — tens of thousands of identifiers, 24,000 findings
// — the alternation took 11 seconds, longer than the whole audit it was redacting. The regexp is kept in
// replacer_scale_test.go as the oracle this is held to, byte for byte.
func buildReplacer(idents map[string]string) func(string) string {
	t := newTrie()
	for k := range idents {
		if k != "" {
			t.insert(k)
		}
	}
	if len(t.nodes) == 1 {
		return func(s string) string { return s }
	}
	return func(s string) string {
		if s == "" {
			return s
		}
		var b strings.Builder
		last := 0
		for i := 0; i < len(s); {
			end := t.longest(s, i)
			if end < 0 {
				// One CHARACTER on, not one byte: the alternation stepped by rune, so a match never began
				// inside a multi-byte one.
				_, w := utf8.DecodeRuneInString(s[i:])
				i += w
				continue
			}
			// A MATCH INSIDE A LONGER NAME IS NOT A MATCH — and it is still consumed, as the alternation's was.
			if !(i > 0 && isWordByte(s[i-1])) && !(end < len(s) && isWordByte(s[end])) {
				b.WriteString(s[last:i])
				b.WriteString(idents[s[i:end]])
				last = end
			}
			i = end
		}
		if last == 0 {
			return s
		}
		b.WriteString(s[last:])
		return b.String()
	}
}

// isWordByte is wordChar on one byte.
func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// trie is the identifiers by byte, so the longest one starting at a position is one walk from it.
type trie struct{ nodes []trieNode }

type trieNode struct {
	edges []trieEdge // sorted by byte
	term  bool       // an identifier ends here
}

type trieEdge struct {
	b    byte
	next int32
}

func newTrie() *trie { return &trie{nodes: []trieNode{{}}} }

func (t *trie) child(n int32, c byte) int32 {
	es := t.nodes[n].edges
	i := sort.Search(len(es), func(i int) bool { return es[i].b >= c })
	if i < len(es) && es[i].b == c {
		return es[i].next
	}
	return -1
}

func (t *trie) insert(k string) {
	n := int32(0)
	for j := 0; j < len(k); j++ {
		c := k[j]
		next := t.child(n, c)
		if next < 0 {
			next = int32(len(t.nodes))
			t.nodes = append(t.nodes, trieNode{})
			es := t.nodes[n].edges
			i := sort.Search(len(es), func(i int) bool { return es[i].b >= c })
			es = append(es, trieEdge{})
			copy(es[i+1:], es[i:])
			es[i] = trieEdge{b: c, next: next}
			t.nodes[n].edges = es
		}
		n = next
	}
	t.nodes[n].term = true
}

// longest is the end of the longest identifier that starts at s[i], or -1.
func (t *trie) longest(s string, i int) int {
	best, n := -1, int32(0)
	for j := i; j < len(s); j++ {
		n = t.child(n, s[j])
		if n < 0 {
			break
		}
		if t.nodes[n].term {
			best = j + 1
		}
	}
	return best
}

// redactChecks rebuilds one domain-assessment slice. Title, Detail and Recommended are sentences about the
// customer's cluster; ID, Status and FindingRef are identifiers and a closed vocabulary this product mints.
func redactChecks(in []types.DomainCheck, rep func(string) string) []types.DomainCheck {
	if in == nil {
		return nil
	}
	out := make([]types.DomainCheck, len(in))
	for i, c := range in {
		nc := c
		nc.Title = rep(c.Title)
		nc.Detail = rep(c.Detail)
		nc.Recommended = rep(c.Recommended)
		out[i] = nc
	}
	return out
}

// redactRef rewrites every customer-chosen string on a resource reference: the namespace, the name, and every
// name in its owner chain. The KIND is left alone — it is a Kubernetes kind from a closed set and carries
// nothing of the customer's.
func redactRef(r types.ResourceRef, rep func(string) string) types.ResourceRef {
	nr := r
	nr.Namespace = rep(r.Namespace)
	nr.Name = rep(r.Name)
	nr.OwnerChain = make([]types.OwnerLink, len(r.OwnerChain))
	for k, o := range r.OwnerChain {
		no := o
		no.Name = rep(o.Name)
		nr.OwnerChain[k] = no
	}
	return nr
}
