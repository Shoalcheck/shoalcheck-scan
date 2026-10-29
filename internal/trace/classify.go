// Package trace records the HTTP requests this process issues, so the product can state what it did
// rather than assert what it would do.
//
// The package is a stdlib-only leaf on purpose. It is imported by internal/collect and internal/prom,
// which sit at different depths, and it must not drag internal/progress or internal/types behind it —
// internal/collect deliberately takes a raw callback rather than importing internal/progress, and a
// recorder is not a reason to undo that.
//
// WHAT IS DELIBERATELY ABSENT FROM EVERY RECORD: the path, the query string, the headers, the body. The
// raw URL is consumed by Classify and discarded before a Request exists, which means no export, no
// support bundle and no report appendix can leak an object name, a pagination token or a credential —
// not because each of those paths remembers to strip them, but because the data was never kept.
//
// Two of those are not hypothetical. Our recorder is installed through rest.Config.WrapTransport, which
// client-go applies as the INNERMOST wrapper (transport/round_trippers.go: WrapTransport first, then
// bearer auth, user-agent and impersonation outside it) — so by the time RoundTrip reaches us the request
// carries a live Authorization header. And a list past the first page carries ?continue=<base64>, whose
// payload decodes to a real namespace and object name: on the local testbed a token decoded to
// {"start":"/bookinfo/error-gen-76bd874b85-n7z7t"}. No string replacer can reach inside base64.
package trace

import (
	"net/url"
	"strings"
)

// Class is what a request DOES, which is the axis the read-only claim is actually made on.
type Class uint8

const (
	// ClassRead is get, list, watch, and reads of non-mutating subresources such as a services/proxy GET.
	ClassRead Class = iota

	// ClassStream is a create against a stream subresource — pods/portforward, and in principle
	// exec/attach, which this process never issues. It opens a proxied stream to an object that already
	// exists and writes no object.
	//
	// It is a third state rather than a shade of the other two because both alternatives are false.
	// Calling it a read is a lie: the API server authorises it as `create` on pods/portforward, which is
	// why deploy/rbac.yaml grants it in a SEPARATE ClusterRole from the auditor role. Calling it
	// "mutating" without qualification is also misleading, because nothing in the cluster changes. The
	// honest resolution is to count it, name it on its own line, and never fold it into either total.
	ClassStream

	// ClassWrite is create, update, patch or delete against an object. An audit must never issue one, and
	// the CI guard fails on any occurrence — scoped to this class alone, because failing on ClassStream
	// would fire on every legitimate opt-in run and the guard would end up relaxed.
	ClassWrite

	// ClassExternal is a request to a system the operator configured that is NOT the cluster — today an
	// issue tracker, reached only on an explicit opt-in push.
	//
	// It is a fourth state for the reason ClassStream is a third: both alternatives are false. Calling it
	// a read is a lie, because a ticket create genuinely changes something at the destination. Calling it
	// ClassWrite is a worse lie, because that total means KUBERNETES OBJECT WRITES — it is the number every
	// read-only claim in this product is rendered from — and widening it silently is exactly the corruption
	// internal/tracker built a separate ledger to avoid. So: counted, named on its own line, folded into
	// neither total.
	//
	// AND IT DOES NOT SAY WHETHER ANYTHING CHANGED THERE, because the wire does not say. Every Linear call
	// is a POST to /graphql — Probe, Find and Create alike (internal/tracker/linear.go, postJSON) — and
	// what separates a lookup from a mutation is in the GraphQL document body, which this package
	// deliberately never keeps. A class named "external write" would have claimed a mutation on every
	// dedup lookup. The number of tickets created comes from the API's response, not from counting POSTs.
	ClassExternal
)

func (c Class) String() string {
	switch c {
	case ClassRead:
		return "read"
	case ClassStream:
		return "stream"
	case ClassExternal:
		return "external"
	default:
		return "write"
	}
}

// Scope distinguishes a request about one namespace from one about the whole cluster, and both from a
// path that names no resource at all.
type Scope uint8

const (
	ScopeNonResource Scope = iota
	ScopeCluster
	ScopeNamespaced
)

func (s Scope) String() string {
	switch s {
	case ScopeCluster:
		return "cluster"
	case ScopeNamespaced:
		return "namespaced"
	default:
		return "—"
	}
}

// Target is where the request went. It is fixed when the transport is wrapped and never inferred from the
// URL, because a Prometheus query path is literally /api/v1/query — it would parse as core/v1 resource
// "query" and be reported as a Kubernetes read of a resource that does not exist. Only the destination
// separates them, and only the caller knows the destination.
type Target uint8

const (
	TargetAPIServer Target = iota
	TargetPrometheus
	// TargetTracker is an operator-configured issue tracker. Not a cluster, not Prometheus. Appended last
	// so no existing value renumbers — these are serialised into the app's event journal.
	TargetTracker
	// TargetPublicData is a credential-free public source of REFERENCE DATA — a signed bundle of prices or
	// Kubernetes EOL dates. Not the cluster, not Prometheus, and not the operator's tracker.
	//
	// It sends NOTHING ABOUT THE CUSTOMER: no cluster name, no UID, no finding, no inventory, no licence.
	// Zero egress is a claim about direction, and this is the opposite direction — which is why it is a
	// target rather than a prohibition. It is still counted, on its own line, because a request this binary
	// issued and did not report is the one thing the trace exists to prevent.
	TargetPublicData
)

func (t Target) String() string {
	switch t {
	case TargetPrometheus:
		return "prometheus"
	case TargetTracker:
		return "tracker"
	case TargetPublicData:
		return "public-data"
	default:
		return "api-server"
	}
}

// Phase separates what the app did before the operator pressed Begin from the audit itself. Both are
// requests this process sent, so both are counted; a session total that silently omitted the pre-flight
// would undercount by roughly a third on the app path, where probing Prometheus runs a full collection.
type Phase uint8

const (
	PhasePreflight Phase = iota
	PhaseRun
)

func (p Phase) String() string {
	if p == PhaseRun {
		return "run"
	}
	return "pre-flight"
}

// Request is one completed round trip, canonicalised to the unit the read-only claim is made in:
// (verb, apiGroup, resource, subresource, scope). That is the RBAC unit, the unit deploy/rbac.yaml grants
// in, and the unit internal/collect/permissions.go already publishes as this repo's source of truth.
type Request struct {
	Seq     int64
	Phase   Phase
	Cluster string // fleet attribution; empty on a single-cluster run
	Target  Target

	// Verb is the Kubernetes verb: get, list, watch, create, update, patch, delete. Empty for a
	// Prometheus request, which is not a Kubernetes call and must not be given a Kubernetes verb.
	Verb        string
	Group       string // empty for the core group and for non-resource paths
	Resource    string // plural, lowercase, matching permissions.go; "prometheus" for a Prometheus request
	Subresource string // "proxy", "portforward", or empty
	Scope       Scope
	Class       Class

	// NonResourcePath is the literal path, stored ONLY for the fixed set of non-resource routes the API
	// server authorises as nonResourceURLs: /version, /api, /apis, a group-version root, /openapi and the
	// health probes. Those contain no customer identifier — an API group name is the same class of thing
	// as Methodology.CollectedKinds, which this report already publishes unredacted — and printing them
	// makes the trace checkable against an audit log instead of showing an opaque "discovery".
	//
	// It is a WHITELIST, not "the path when we could not parse it". A route we do not recognise stores
	// nothing and is labelled unclassified, so an unexpected request shows up AS unexpected rather than
	// being filed under discovery with its path attached.
	NonResourcePath string

	// Method and Host are recorded ONLY for a target that is not the cluster — today an issue tracker.
	//
	// Method is the HTTP method and is NOT a Verb: `POST` is what the destination's own access log will
	// show, and it is what makes an external row checkable there. A Kubernetes request stores its Verb
	// instead, because the API server's audit log records the verb, not the method.
	//
	// Host is the destination authority — host and port, never a path or a query. The API server's address
	// comes from the kubeconfig the operator chose and is not restated; an issue tracker's does not, and
	// "what did this binary contact" is the only question an operator can check from their own terminal.
	// Deriving it from what was ACTUALLY contacted rather than from what was configured is the point: a
	// redirect or a mistyped base URL shows up.
	//
	// DELIBERATELY NOT IN THE REPORT'S APPENDIX. A self-hosted tracker's hostname is a customer
	// identifier, and types.SessionTraceRow carries Resource, Scope and a whitelist of discovery routes and
	// nothing else. TestSessionTrace_NeverCarriesAnExternalHost is the guard.
	Method string
	Host   string

	Status   int    // HTTP status; 0 when no response was received at all
	Outcome  string // ok | unauthorized | forbidden | not-found | throttled | server-error | other | no-response
	Retry    bool   // an identical tuple preceded by a 429 or 5xx
	Duration int64  // nanoseconds
}

// nonResourcePrefixes are paths the API server itself authorises as nonResourceURLs rather than as
// resources — which is why they are matched here and not fed to the resource parser. Kubernetes' own
// system:discovery ClusterRole grants `get` on exactly these. A parser that guessed from the response
// body ("it is a List kind, so the verb is list") gets every one of them wrong.
var nonResourcePrefixes = []string{
	"/version", "/openapi", "/healthz", "/livez", "/readyz", "/metrics", "/.well-known",
}

// streamSubresources are the terminal subresources whose create opens a stream rather than writing an
// object.
var streamSubresources = map[string]bool{
	"portforward": true, "exec": true, "attach": true,
}

// Classify turns a request into its canonical tuple. It implements the API server's own segment rules:
// the verb is decided by the POSITION of segments, never by a substring match or a segment count, because
// a namespace may legitimately be called "api" and a resource may be called "namespaces".
func Classify(target Target, method string, u *url.URL) Request {
	r := Request{Target: target}
	if target == TargetPrometheus {
		// Not a Kubernetes request. Given no verb on purpose: a Prometheus query has no Kubernetes verb,
		// and inventing "get" here would put a Kubernetes-shaped claim on something the cluster's audit
		// log will never contain.
		r.Resource = "prometheus"
		r.Scope = ScopeNonResource
		r.Class = ClassRead
		// The route is recorded only when it is one THIS client issues. Those four are ours, they carry no
		// identifier, and naming them is what lets a reader check the line against a Prometheus access log.
		// Anything else belongs to the operator's own path space — they supply the URL — so it is left
		// unnamed rather than printed, and never substituted with a route we did not call.
		if u != nil {
			r.NonResourcePath = promRoute(u.Path)
		}
		return r
	}

	if target == TargetPublicData {
		// Not a Kubernetes request, and not a cluster read. Given no verb for the same reason the two
		// branches below are: the cluster's audit log will never contain this, and a Kubernetes verb on it
		// would put a cluster-shaped claim on something that never touched the cluster.
		//
		// ClassExternal rather than ClassRead, and the distinction is the read-only claim's: Tally.Read is
		// what a report's "N reads against your cluster" is drawn from, and a price-table GET is not one of
		// them. Counted, named on its own line, folded into neither cluster total.
		//
		// THE PATH IS NOT KEPT, only the host — same as the tracker. The URL is a compiled-in constant, so
		// there is nothing customer-derived in it either way; not keeping it costs nothing and keeps one rule
		// for every non-cluster target instead of an exception per target.
		r.Resource = "reference-data"
		r.Scope = ScopeNonResource
		r.Class = ClassExternal
		r.Method = strings.ToUpper(method)
		if u != nil {
			r.Host = u.Host
		}
		return r
	}

	if target == TargetTracker {
		// Not a Kubernetes request and not the cluster at all. Given no verb for the same reason a
		// Prometheus request is not: the cluster's audit log will never contain this, and a Kubernetes verb
		// on it puts a cluster-shaped claim on something that never touched the cluster. That is not
		// hypothetical — before this branch existed, a POST to api.linear.app classified as TargetAPIServer
		// fell through to unclassified("POST") and arrived as Verb "create", Class ClassWrite.
		//
		// THE PATH IS NOT KEPT, and unlike the Prometheus branch there is no whitelist of routes to keep
		// either: a Jira issue path names a project key, and the endpoint is the operator's own base URL.
		// The destination host is recorded by the ticket path's own row, which is where it belongs.
		r.Resource = "tracker"
		r.Scope = ScopeNonResource
		r.Class = ClassExternal
		r.Method = strings.ToUpper(method)
		if u != nil {
			r.Host = u.Host // authority only: Host, never Path or RawQuery
		}
		return r
	}

	path := "/"
	if u != nil {
		path = u.Path
	}
	verbFromMethod := func(named bool) (string, Class) {
		switch strings.ToUpper(method) {
		case "POST":
			return "create", ClassWrite
		case "PUT":
			return "update", ClassWrite
		case "PATCH":
			return "patch", ClassWrite
		case "DELETE":
			if named {
				return "delete", ClassWrite
			}
			return "deletecollection", ClassWrite
		default: // GET, HEAD
			if u != nil && u.Query().Get("watch") == "true" {
				return "watch", ClassRead
			}
			if named {
				return "get", ClassRead
			}
			return "list", ClassRead
		}
	}

	for _, p := range nonResourcePrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return withTarget(nonResource(p), target)
		}
	}

	parts := splitPath(path)
	// /api  /apis  /api/v1  /apis/{group}/{version} — discovery, all non-resource.
	switch {
	case len(parts) == 0:
		return withTarget(unclassified(method), target)
	case parts[0] == "api" && len(parts) <= 2, parts[0] == "apis" && len(parts) <= 3:
		return withTarget(nonResource("/"+strings.Join(parts, "/")), target)
	}

	var rest []string
	switch parts[0] {
	case "api":
		r.Group = "" // the core group
		rest = parts[2:]
	case "apis":
		r.Group = parts[1]
		rest = parts[3:]
	default:
		// Not an API path at all. Labelled unclassified WITHOUT its path, so an unexpected request is
		// visible as unexpected rather than filed under discovery — and so a route we never anticipated
		// cannot smuggle an identifier into the trace.
		return withTarget(unclassified(method), target)
	}

	// A namespaces/{ns} prefix makes the request namespaced — but only when something follows it.
	// /api/v1/namespaces is a cluster-scoped LIST of the namespaces resource, and
	// /api/v1/namespaces/default is a GET of one of them; neither is a namespaced request.
	if len(rest) >= 3 && rest[0] == "namespaces" {
		r.Scope = ScopeNamespaced
		rest = rest[2:]
	} else {
		r.Scope = ScopeCluster
	}

	if len(rest) == 0 {
		return withTarget(unclassified(method), target)
	}
	r.Resource = rest[0]
	named := len(rest) >= 2
	if len(rest) >= 3 {
		// The subresource is the third segment, whatever it is; every segment after it is dropped rather
		// than parsed. That matters for the terminal ones — a services/proxy path continues into
		// Prometheus' own routes, and reading those as Kubernetes segments would invent resources that do
		// not exist and put them in a trace the reader is invited to check against their audit log.
		r.Subresource = rest[2]
	}

	r.Verb, r.Class = verbFromMethod(named)
	if r.Subresource != "" && r.Class == ClassWrite && streamSubresources[r.Subresource] {
		r.Class = ClassStream
	}
	return r
}

func withTarget(r Request, t Target) Request {
	r.Target = t
	return r
}

// promRoutes are the Prometheus HTTP API paths this client calls: the two query endpoints, the build-info
// probe and the readiness probe. See internal/prom/prom.go.
var promRoutes = map[string]bool{
	"/api/v1/query": true, "/api/v1/query_range": true,
	"/api/v1/status/buildinfo": true, "/-/ready": true,
}

func promRoute(path string) string {
	if promRoutes[path] {
		return path
	}
	return ""
}

func nonResource(path string) Request {
	return Request{
		Verb: "get", Class: ClassRead, Scope: ScopeNonResource,
		Resource: "nonResourceURL", NonResourcePath: path,
	}
}

// unclassified is a route this parser does not recognise. It stores no path — an unanticipated request must
// not be able to smuggle an identifier into a trace people are invited to share — but it DOES classify its
// method, and that part is load-bearing.
//
// It used to hardcode get/read. On any cluster whose API server sits behind a path prefix — Rancher publishes
// /k8s/clusters/<id>/api/v1/... — nothing is recognised, so every request became a read and the report's
// "0 object writes" held no matter what the process actually sent. A guarantee that cannot fail is not a
// guarantee. An unrecognised POST is now a create, an unrecognised write is ClassWrite, and the CI guard
// trips exactly as it should.
func unclassified(method string) Request {
	r := Request{Scope: ScopeNonResource, Resource: "unclassified"}
	switch strings.ToUpper(method) {
	case "POST":
		r.Verb, r.Class = "create", ClassWrite
	case "PUT":
		r.Verb, r.Class = "update", ClassWrite
	case "PATCH":
		r.Verb, r.Class = "patch", ClassWrite
	case "DELETE":
		r.Verb, r.Class = "delete", ClassWrite
	default:
		r.Verb, r.Class = "get", ClassRead
	}
	return r
}

func splitPath(p string) []string {
	out := make([]string, 0, 8)
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Shape renders the canonical tuple as the request line a reader recognises, with placeholders where the
// names were. It is DERIVED at display time rather than stored, which is what lets the ticker read like a
// real audit log while the journal holds no identifier at all.
func (r Request) Shape() string {
	if r.Target == TargetPrometheus {
		if r.NonResourcePath != "" {
			return "GET {prometheus}" + r.NonResourcePath
		}
		// An unrecognised route on an operator-supplied endpoint. Named as unnamed rather than guessed at.
		return "GET {prometheus}"
	}
	method := map[string]string{
		"get": "GET", "list": "GET", "watch": "GET", "create": "POST",
		"update": "PUT", "patch": "PATCH", "delete": "DELETE", "deletecollection": "DELETE",
	}[r.Verb]
	if method == "" {
		method = "GET"
	}
	if r.Scope == ScopeNonResource {
		if r.NonResourcePath != "" {
			return method + " " + r.NonResourcePath
		}
		return method + " {unclassified}"
	}
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" ")
	if r.Group == "" {
		b.WriteString("/api/v1")
	} else {
		b.WriteString("/apis/" + r.Group + "/{v}")
	}
	if r.Scope == ScopeNamespaced {
		b.WriteString("/namespaces/{ns}")
	}
	b.WriteString("/" + r.Resource)
	if r.Verb == "get" || r.Subresource != "" {
		b.WriteString("/{name}")
	}
	if r.Subresource != "" {
		b.WriteString("/" + r.Subresource)
		if r.Subresource == "proxy" {
			b.WriteString("/**")
		}
	}
	if r.Verb == "list" {
		b.WriteString("?limit=500")
	}
	if r.Verb == "watch" {
		b.WriteString("?watch=true")
	}
	return b.String()
}

// Tuple is the RBAC-shaped key an appendix groups by.
func (r Request) Tuple() string {
	res := r.Resource
	if r.Group != "" {
		res = r.Group + "/" + res
	} else if r.Scope != ScopeNonResource {
		res = "core/" + res
	}
	if r.Subresource != "" {
		res += "/" + r.Subresource
	}
	return res
}
