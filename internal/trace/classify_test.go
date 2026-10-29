package trace

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The table is the contract. Every row is a path shape this repo actually issues, taken from the collector's
// step() calls, the dynamic CR path, the Prometheus service-proxy path and the port-forward upgrade — plus
// the write verbs, which must be classifiable precisely so the CI guard can trip if one ever appears.
func TestClassify(t *testing.T) {
	cases := []struct {
		name        string
		target      Target
		method      string
		rawURL      string
		verb        string
		group       string
		resource    string
		subresource string
		scope       Scope
		class       Class
	}{
		// --- discovery and other non-resource paths. The API server authorises these as
		// nonResourceURLs, which is why they must not be parsed as resources. A body-shape heuristic
		// ("the response is a List, so the verb is list") gets every one of them wrong.
		{"version", TargetAPIServer, "GET", "https://k/version?timeout=32s", "get", "", "nonResourceURL", "", ScopeNonResource, ClassRead},
		{"api root", TargetAPIServer, "GET", "https://k/api?timeout=32s", "get", "", "nonResourceURL", "", ScopeNonResource, ClassRead},
		{"apis root", TargetAPIServer, "GET", "https://k/apis?timeout=32s", "get", "", "nonResourceURL", "", ScopeNonResource, ClassRead},
		{"core group version", TargetAPIServer, "GET", "https://k/api/v1", "get", "", "nonResourceURL", "", ScopeNonResource, ClassRead},
		{"named group version", TargetAPIServer, "GET", "https://k/apis/apps/v1", "get", "", "nonResourceURL", "", ScopeNonResource, ClassRead},
		{"openapi", TargetAPIServer, "GET", "https://k/openapi/v2", "get", "", "nonResourceURL", "", ScopeNonResource, ClassRead},

		// --- the collector's lists
		{"core list", TargetAPIServer, "GET", "https://k/api/v1/pods?limit=500", "list", "", "pods", "", ScopeCluster, ClassRead},
		{"core list page 2", TargetAPIServer, "GET", "https://k/api/v1/pods?limit=500&continue=eyJ2IjoibWV0YS5rOHMu", "list", "", "pods", "", ScopeCluster, ClassRead},
		{"apps list", TargetAPIServer, "GET", "https://k/apis/apps/v1/deployments?limit=500", "list", "apps", "deployments", "", ScopeCluster, ClassRead},
		{"endpointslices", TargetAPIServer, "GET", "https://k/apis/discovery.k8s.io/v1/endpointslices?limit=500", "list", "discovery.k8s.io", "endpointslices", "", ScopeCluster, ClassRead},
		{"custom resource", TargetAPIServer, "GET", "https://k/apis/cert-manager.io/v1/certificates", "list", "cert-manager.io", "certificates", "", ScopeCluster, ClassRead},

		// --- the namespaces resource is NOT a namespaced request. This is the single easiest rule to get
		// wrong, and getting it wrong mislabels the scope of the two most common calls in the audit.
		{"namespaces list", TargetAPIServer, "GET", "https://k/api/v1/namespaces?limit=500", "list", "", "namespaces", "", ScopeCluster, ClassRead},
		{"one namespace", TargetAPIServer, "GET", "https://k/api/v1/namespaces/kube-system", "get", "", "namespaces", "", ScopeCluster, ClassRead},
		{"namespaced list", TargetAPIServer, "GET", "https://k/api/v1/namespaces/monitoring/services", "list", "", "services", "", ScopeNamespaced, ClassRead},

		// --- the Prometheus service proxy: a GET of a subresource, and the Prometheus routes behind it
		// are another system's API, dropped rather than parsed.
		{"service proxy query", TargetAPIServer, "GET",
			"https://k/api/v1/namespaces/monitoring/services/prom:9090/proxy/api/v1/query?query=up",
			"get", "", "services", "proxy", ScopeNamespaced, ClassRead},

		// --- the one non-read verb this process can issue, and it is neither a read nor an object write
		{"port-forward upgrade", TargetAPIServer, "POST",
			"https://k/api/v1/namespaces/monitoring/pods/prom-0/portforward",
			"create", "", "pods", "portforward", ScopeNamespaced, ClassStream},

		// --- a POST to services/proxy is a CREATE at the API server. The July spec pre-authorised
		// classifying it as a read; that rule is rejected here so the guard trips instead of a genuine
		// create being silently relabelled the day someone moves PromQL to POST.
		{"POST through the proxy", TargetAPIServer, "POST",
			"https://k/api/v1/namespaces/monitoring/services/prom/proxy/api/v1/query",
			"create", "", "services", "proxy", ScopeNamespaced, ClassWrite},

		// --- watch is a read, and it is distinguishable. The collector never watches; if one ever
		// appears the trace must say "watch" rather than "list", because they are different grants.
		{"watch", TargetAPIServer, "GET", "https://k/api/v1/pods?watch=true", "watch", "", "pods", "", ScopeCluster, ClassRead},

		// --- object writes. None may ever occur; all must classify, or the guard cannot see them.
		{"delete one", TargetAPIServer, "DELETE", "https://k/api/v1/namespaces/x/pods/y", "delete", "", "pods", "", ScopeNamespaced, ClassWrite},
		{"delete collection", TargetAPIServer, "DELETE", "https://k/api/v1/namespaces/x/pods", "deletecollection", "", "pods", "", ScopeNamespaced, ClassWrite},
		{"patch", TargetAPIServer, "PATCH", "https://k/apis/apps/v1/namespaces/x/deployments/y", "patch", "apps", "deployments", "", ScopeNamespaced, ClassWrite},
		{"put", TargetAPIServer, "PUT", "https://k/apis/apps/v1/namespaces/x/deployments/y", "update", "apps", "deployments", "", ScopeNamespaced, ClassWrite},

		// --- Prometheus reached directly or through a port-forward. The path is /api/v1/query, which a
		// path-only table would read as core/v1 resource "query" and report as a Kubernetes read of a
		// resource that does not exist. Only the destination separates them.
		{"prometheus direct", TargetPrometheus, "GET", "http://127.0.0.1:9090/api/v1/query?query=up", "", "", "prometheus", "", ScopeNonResource, ClassRead},
		{"prometheus range", TargetPrometheus, "GET", "http://prom.example/api/v1/query_range?query=up", "", "", "prometheus", "", ScopeNonResource, ClassRead},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.rawURL)
			if err != nil {
				t.Fatalf("bad test URL: %v", err)
			}
			got := Classify(c.target, c.method, u)
			if got.Verb != c.verb || got.Group != c.group || got.Resource != c.resource ||
				got.Subresource != c.subresource || got.Scope != c.scope || got.Class != c.class {
				t.Errorf("Classify(%s %s)\n got verb=%q group=%q resource=%q sub=%q scope=%v class=%v\nwant verb=%q group=%q resource=%q sub=%q scope=%v class=%v",
					c.method, c.rawURL,
					got.Verb, got.Group, got.Resource, got.Subresource, got.Scope, got.Class,
					c.verb, c.group, c.resource, c.subresource, c.scope, c.class)
			}
		})
	}
}

// A Prometheus request must never be given a Kubernetes verb. The cluster's own audit log will never
// contain it, so labelling it "get" would put a Kubernetes-shaped claim on something that never touched
// the API server — and a reader comparing the trace against their audit log would find a request that is
// not there and conclude the trace is fabricated.
func TestClassify_PrometheusHasNoKubernetesVerb(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:9090/api/v1/query?query=up")
	got := Classify(TargetPrometheus, "GET", u)
	if got.Verb != "" {
		t.Errorf("a Prometheus query was given the Kubernetes verb %q", got.Verb)
	}
	if got.Group != "" || got.Subresource != "" {
		t.Errorf("a Prometheus query was given a Kubernetes group/subresource: %+v", got)
	}
}

// The whole privacy design rests on this: the record is built from the URL and the URL is then gone. If a
// Request could carry a path, every consumer downstream would have to remember to strip it.
func TestRequest_CarriesNoPathAndNoIdentifier(t *testing.T) {
	raw := "https://k/api/v1/namespaces/payments-prod/services/stripe-webhook:9090/proxy/api/v1/query?query=up&continue=eyJzdGFydCI6Ii9ib29raW5mby9lcnJvci1nZW4ifQ"
	u, _ := url.Parse(raw)
	got := Classify(TargetAPIServer, "GET", u)

	blob := got.Shape() + " " + got.Tuple() + " " + got.Verb + " " + got.Resource + " " + got.Subresource + " " + got.Group
	for _, secret := range []string{"payments-prod", "stripe-webhook", "continue", "eyJzdGFydCI", "9090"} {
		if strings.Contains(blob, secret) {
			t.Errorf("the canonical record leaks %q: %q", secret, blob)
		}
	}
	if got.Shape() != "GET /api/v1/namespaces/{ns}/services/{name}/proxy/**" {
		t.Errorf("Shape() = %q — it must read like a request line while naming nothing", got.Shape())
	}
	if got.Tuple() != "core/services/proxy" {
		t.Errorf("Tuple() = %q, want core/services/proxy (the RBAC unit)", got.Tuple())
	}
}

// The discovery paths are shown literally because they are a fixed, whitelisted set that contains no
// customer identifier — an API group name is the same class of thing as Methodology.CollectedKinds, which
// the report already publishes unredacted. Showing them makes the trace checkable against an audit log
// instead of printing an opaque "discovery".
func TestClassify_DiscoveryPathsAreShownAndNothingElseIs(t *testing.T) {
	// Exact-match routes are stored whole. PREFIX-match routes are stored as the PREFIX ONLY, deliberately:
	// a prefix match has an unbounded tail, and an unbounded tail is exactly the shape that becomes a leak
	// two releases later. /openapi/v3/apis/apps/v1 is harmless today; the rule that keeps it harmless is
	// storing what was verified rather than whatever happened to follow it.
	shown := map[string]string{
		"/version":                 "/version",
		"/api":                     "/api",
		"/apis":                    "/apis",
		"/api/v1":                  "/api/v1",
		"/apis/apps/v1":            "/apis/apps/v1",
		"/openapi/v2":              "/openapi",
		"/openapi/v3/apis/apps/v1": "/openapi",
		"/healthz":                 "/healthz",
	}
	for path, want := range shown {
		u, _ := url.Parse("https://k" + path)
		got := Classify(TargetAPIServer, "GET", u)
		if got.NonResourcePath != want {
			t.Errorf("%s: NonResourcePath = %q, want %q", path, got.NonResourcePath, want)
		}
		if got.Shape() != "GET "+want {
			t.Errorf("%s: Shape() = %q, want %q", path, got.Shape(), "GET "+want)
		}
	}

	// A route we do not recognise keeps NOTHING. This is the difference between a whitelist and "the path
	// when parsing failed": an unanticipated request must be visible AS unanticipated, and must not be able
	// to smuggle a customer identifier into a trace we invite people to share.
	for _, path := range []string{
		"/some/vendor/route/payments-prod",
		"/logs/cluster-acme-prod",
		"/",
	} {
		u, _ := url.Parse("https://k" + path)
		got := Classify(TargetAPIServer, "GET", u)
		if got.Resource != "unclassified" {
			t.Errorf("%s classified as %q — an unrecognised route must be labelled unclassified", path, got.Resource)
		}
		if got.NonResourcePath != "" {
			t.Errorf("%s stored its path (%q); only whitelisted discovery routes may", path, got.NonResourcePath)
		}
		if strings.Contains(got.Shape(), "payments-prod") || strings.Contains(got.Shape(), "acme") {
			t.Errorf("%s leaked into Shape(): %q", path, got.Shape())
		}
	}
}

// A Prometheus request has no Kubernetes verb, and the appendix must SAY that rather than leave the cell
// blank. A blank cell reads as missing data — which invites the reader to distrust the row, or worse, to
// assume a verb we did not measure. The row exists to be checkable; "not a Kubernetes request" is the
// checkable fact about it.
func TestGroups_APrometheusRowSaysItIsNotAKubernetesRequest(t *testing.T) {
	rec := New(nil)
	rt := rec.Wrap(TargetPrometheus)(fnRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))
	for i := 0; i < 3; i++ {
		get(t, rt, "http://127.0.0.1:9090/api/v1/query?query=up")
	}

	gs := rec.Groups()
	if len(gs) != 1 {
		t.Fatalf("got %d groups, want 1", len(gs))
	}
	g := gs[0]
	if g.Resource != "prometheus" || g.Requests != 3 {
		t.Fatalf("unexpected group: %+v", g)
	}
	if len(g.Verbs) == 0 {
		t.Error("the Prometheus group has no verbs at all, so the appendix renders an empty cell that reads " +
			"as missing data rather than as 'not a Kubernetes request'")
	}
	if len(g.Verbs) == 1 && g.Verbs[0] == "get" {
		t.Error("the Prometheus group was given the Kubernetes verb 'get'; the cluster's audit log will never " +
			"contain this request, so a Kubernetes verb on it is a false claim")
	}
}

// A displayed request line must be the line that was SENT. Shape() hardcoded /api/v1/query for every
// Prometheus request, so a readiness probe to /-/ready and a version check to /api/v1/status/buildinfo both
// rendered as a PromQL query that was never issued. A trace whose whole purpose is being checkable against
// somebody's logs cannot print a request it did not make — an opaque line is honest, a fabricated one is not.
func TestClassify_PrometheusShapeIsTheRouteThatWasActuallyCalled(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v1/query":            "GET {prometheus}/api/v1/query",
		"/api/v1/query_range":      "GET {prometheus}/api/v1/query_range",
		"/api/v1/status/buildinfo": "GET {prometheus}/api/v1/status/buildinfo",
		"/-/ready":                 "GET {prometheus}/-/ready",
	} {
		u, _ := url.Parse("http://127.0.0.1:9090" + path + "?query=up")
		got := Classify(TargetPrometheus, "GET", u)
		if got.Shape() != want {
			t.Errorf("%s: Shape() = %q, want %q", path, got.Shape(), want)
		}
	}
	// A route this client does not issue is NOT displayed. The operator supplies the Prometheus URL, so its
	// path space is theirs, not ours, and an unknown path there could carry anything.
	u, _ := url.Parse("http://prom.internal/api/v1/label/customer_id/values")
	got := Classify(TargetPrometheus, "GET", u)
	if strings.Contains(got.Shape(), "customer_id") {
		t.Errorf("an unrecognised Prometheus route leaked into Shape(): %q", got.Shape())
	}
	if got.Shape() != "GET {prometheus}" {
		t.Errorf("Shape() = %q, want the bare %q for an unrecognised route", got.Shape(), "GET {prometheus}")
	}
}

// THE VACUOUS-GUARANTEE BUG. unclassified() hardcoded verb=get and class=read, so any request this
// classifier does not recognise was tallied as a read — including a POST. On a cluster whose API server sits
// behind a path prefix (Rancher publishes /k8s/clusters/<id>/api/v1/...) NOTHING is recognised, so
// "0 object writes" would hold no matter what the process actually sent.
func TestClassify_AnUnrecognisedRouteStillClassifiesItsMethodHonestly(t *testing.T) {
	cases := []struct {
		method string
		verb   string
		class  Class
	}{
		{"GET", "get", ClassRead},
		{"POST", "create", ClassWrite},
		{"PUT", "update", ClassWrite},
		{"PATCH", "patch", ClassWrite},
		{"DELETE", "delete", ClassWrite},
	}
	for _, c := range cases {
		u, _ := url.Parse("https://rancher.example/k8s/clusters/c-m-abc123/api/v1/namespaces/prod/pods")
		got := Classify(TargetAPIServer, c.method, u)
		if got.Verb != c.verb || got.Class != c.class {
			t.Errorf("%s on an unrecognised route: verb=%q class=%v, want %q/%v — an unrecognised write "+
				"counted as a read makes the object-write guarantee vacuous",
				c.method, got.Verb, got.Class, c.verb, c.class)
		}
		if strings.Contains(got.Shape(), "prod") || strings.Contains(got.Shape(), "c-m-abc123") {
			t.Errorf("%s: an unrecognised route leaked into Shape(): %q", c.method, got.Shape())
		}
	}
}

// The retry flag must not fire across different destinations or different clusters. The key was
// verb+resource only, so in a fleet the same list against cluster B looked like a retry of cluster A's.
func TestRecorder_RetryIsNotClaimedAcrossClustersOrTargets(t *testing.T) {
	rec := New(nil)
	rt := rec.Wrap(TargetAPIServer)(fnRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Body: http.NoBody}, nil
	}))
	ok := rec.Wrap(TargetAPIServer)(fnRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))
	rec.SetCluster("cluster-a")
	get(t, rt, "https://k/api/v1/pods") // throttled on A
	rec.SetCluster("cluster-b")
	get(t, ok, "https://k/api/v1/pods") // a first attempt on B, not a retry of A

	rows, _ := rec.Since(0)
	if len(rows) != 2 {
		t.Fatalf("got %d rows", len(rows))
	}
	if rows[1].Retry {
		t.Error("a first request against a different cluster was labelled a retry of another cluster's")
	}
	if rec.Tally().Retried != 0 {
		t.Errorf("Retried = %d, want 0", rec.Tally().Retried)
	}
}
