// Package collect gathers a READ-ONLY snapshot of a Kubernetes cluster.
//
// SECURITY CONTRACT (deny-by-construction): this package never lists or
// reads Secrets, ConfigMaps, or pod environment values — the API calls do
// not exist in this code. Adding one is a breaking change to the product's
// published trust model. The future OSS ClusterRole mirrors exactly the
// resources listed here.
package collect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Inventory is the typed snapshot every detection rule reads.
type Inventory struct {
	// volume is what this reading read, measured as the API server answered it — BEFORE dropEnvValues took the
	// environment values and the last-applied annotation out. The figure stands for what `kubectl get -o yaml`
	// would print to someone reading the cluster by hand, and kubectl prints both. Unexported, so a capture
	// does not carry it: a replayed inventory measures what it holds.
	volume *types.ReadVolume

	Nodes        []corev1.Node
	Namespaces   []corev1.Namespace
	Deployments  []appsv1.Deployment
	StatefulSets []appsv1.StatefulSet
	DaemonSets   []appsv1.DaemonSet
	Pods         []corev1.Pod
	Services     []corev1.Service
	PDBs         []policyv1.PodDisruptionBudget

	// Identity & access. BINDINGS AND BODIES, since B-1 Option C.
	//
	// The bodies were deliberately left out until 2026-08-28, and the reason is worth keeping: reading them
	// moves the product's read set from "what is deployed and how it is configured" to "who is permitted to
	// do what", which is more sensitive than anything else collected. Nine CIS controls (5.1.2, 5.1.3,
	// 5.1.4, 5.1.8–5.1.13) were held at MANUAL because of it, and the decision to collect them was the
	// founder's, recorded in docs/superpowers/briefs/2026-08-28-next-trace-target-and-b1.md §2.
	//
	// A PolicyRule is {Verbs, APIGroups, Resources, ResourceNames, NonResourceURLs} — five string slices. It
	// says what MAY BE DONE, never what is stored: no object data, no Secret contents, no pod env. What it
	// does carry is customer-chosen object names in ResourceNames, which is why types.Finding.ScopedTo
	// exists and why internal/redact registers them.
	//
	// STILL NOT COLLECTED, and not by omission: no `escalate`, no `bind`, no `impersonate`, no write verb of
	// any kind, and no Secrets. Effective permissions remain unreadable — see internal/rules/rbac_grants.go.
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	RoleBindings        []rbacv1.RoleBinding
	ClusterRoles        []rbacv1.ClusterRole
	Roles               []rbacv1.Role
	ServiceAccounts     []corev1.ServiceAccount

	// Network & isolation.
	NetworkPolicies []networkingv1.NetworkPolicy
	Ingresses       []networkingv1.Ingress

	// EndpointSlices record which addresses a controller published as backends of a Service.
	// They are the difference between "this pod matches the selector" (intent) and "a controller
	// listed this pod as a backend" (fact), which several rules previously had to disclose as
	// unknown. They are NOT request data: a published entry says nothing about whether any
	// request reached it.
	EndpointSlices []discoveryv1.EndpointSlice

	// Governance & scaling.
	ResourceQuotas []corev1.ResourceQuota
	LimitRanges    []corev1.LimitRange
	HPAs           []autoscalingv2.HorizontalPodAutoscaler

	// CronJobs carry status.lastSuccessfulTime, which is the only read-only signal that a
	// scheduled job has quietly stopped succeeding — a backup, a certificate rotation, a cleanup.
	//
	// JOBS ARE DELIBERATELY NOT COLLECTED. Every CronJob run spawns one, so a cluster holds orders
	// of magnitude more of them, and the claim rides on the CronJob's own status rather than on any
	// individual run. The volume is not worth one more thing the report could be wrong about.
	CronJobs []batchv1.CronJob

	// Jobs, COLLECTED WITH A LIMIT AND A DISCLOSED TRUNCATION — founder decision, 2026-08-29 (§10 Q2).
	//
	// The earlier note above says jobs are deliberately not collected because every CronJob run spawns
	// one. That reasoning was half right and the half it missed is the point: the controller ALREADY
	// bounds CronJob-owned jobs (successfulJobsHistoryLimit defaults to 3, failedJobsHistoryLimit to 1),
	// so the volume risk is STANDALONE jobs nobody cleaned up — which is precisely what the TTL rule
	// exists to find. Collecting only CronJob-owned ones would have excluded the entire subject.
	//
	// JobsTruncated says the list did not fit. A truncated list rendered as complete is absence-as-fact
	// in a new hat, so every rule reading Jobs must consult it before making a count claim.
	Jobs          []batchv1.Job
	JobsTruncated bool

	// Storage — raw objects for the cost assembler (Phase 1). PV capacity is
	// authoritative; PVC requests.storage is the fallback when a PVC is
	// Pending/unbound. Also marks genuinely stateful topology nodes (Phase 2).
	PVs  []corev1.PersistentVolume
	PVCs []corev1.PersistentVolumeClaim

	// THREE CLASS OBJECTS, COLLECTED SO A NAME CAN BE RESOLVED RATHER THAN PRINTED.
	//
	// Each is named by something else and, until now, only ever echoed back: silent_failures.go printed a
	// PVC's storageClassName beside the words "the class object itself was not read", and a workload's
	// priorityClassName and an Ingress's ingressClassName were not read at all. A name this product
	// repeats without resolving is a name it cannot tell from a typo.
	//
	// All three are small and cluster-scoped: a cluster has a handful of StorageClasses, fewer
	// IngressClasses, and PriorityClasses in the low tens including the two Kubernetes ships. None
	// carries workload data — a class is a policy object naming a provisioner, a controller or a value.
	// CRDs carry the conversion-webhook declaration the upgrade family reads.
	//
	// READ THROUGH THE DYNAMIC CLIENT AND NARROWED TO A TYPED STRUCT ON THE WAY IN, deliberately. The
	// alternative is the apiextensions-apiserver clientset, which is a new module dependency for four
	// fields — and narrowing here means the Inventory carries exactly what a rule may claim about, rather
	// than a whole CRD whose schema, validation rules and printer columns nothing reads.
	CRDs []CRDInfo

	StorageClasses  []storagev1.StorageClass
	IngressClasses  []networkingv1.IngressClass
	PriorityClasses []schedulingv1.PriorityClass

	// PresentGVRs is the server's preferred served-resource set (one
	// ServerPreferredResources call). The analyzer registry (Phase 3) gates on
	// it so a no-Istio / no-cert-manager cluster silently skips, never 404-Lists.
	PresentGVRs GVRSet

	// ServedGroupVersions is EVERY group/version the API server serves, not only the preferred one.
	//
	// PresentGVRs above comes from ServerPreferredResources, which returns ONE version per group — the
	// one the server prefers. That is exactly right for "is Istio installed" and exactly wrong for "does
	// this cluster still serve batch/v1beta1", because the deprecated version is by definition not the
	// preferred one. ServerGroups() returns all of them, in one more discovery request of the same
	// get-class, and needs no new RBAC.
	ServedGroupVersions []string

	// StackObjects holds the unstructured CR lists keyed by the GVR they were
	// read from. A Phase-3 analyzer reads only the GVRs in its RequiredGVRs().
	// Empty in Phase 0 (callers pass wantGVRs=nil).
	StackObjects StackObjectMap

	Meta Meta

	// KubeadmControlPlane is whether THIS READING, collected live, showed a control plane kubeadm installed (see
	// kubeadmControlPlane). Set once, at the end of a live Collect, from the Nodes and Pods the API server returned,
	// and never recomputed: a replay carries what its live collection set — a capture taken before this field
	// existed, or an empty cluster, carries false — and a copy with a pull request's objects laid over it keeps the
	// live value, so nothing a change supplies is ever kubeadm evidence (security review of c7a9423b: a change
	// carrying a forged API server pod passed its own copy of kubeadm's cluster-admin binding).
	KubeadmControlPlane bool
}

// Meta records what collection actually managed to do — surfaced honestly
// in the report's Methodology section.
type Meta struct {
	Collected     []string
	Denied        []string
	ServerVersion string
	Context       string
	StartedAt     time.Time
	Duration      time.Duration

	// OutOfScope lists the kinds this reading did not read BY DESIGN — a scoped collection (Only) that a question
	// did not need, or the empty cluster of a manifests-only gate — as distinct from Denied, which lists the kinds it
	// asked for and was refused. Declared, never inferred: a kind in neither list is an absence, and whatever reads
	// the inventory must treat it as one.
	OutOfScope []string

	// PartialDiscovery lists GroupVersions that failed discovery (a degraded
	// aggregated APIService — commonly metrics.k8s.io). Surfaced in Methodology
	// so the report distinguishes "absent because not installed" from "absent
	// because discovery was incomplete".
	PartialDiscovery []string
}

// HasCollected reports whether a collector step produced data — collected and not denied.
//
// It is the same question metaCollected asks inside internal/rules, exported here because
// internal/pipeline needs it to tell the compliance assessment which reads actually happened. A control is
// never PASSed on a read that did not happen, and from the outside a denial guard's silence looks exactly
// like a clean result.
//
// A DENIED ENTRY WINS OVER A COLLECTED ONE. Denied entries are formatted "<kind>: <err>", so the prefix is
// matched rather than the whole string.
func (m Meta) HasCollected(kind string) bool {
	for _, d := range m.Denied {
		if d == kind || strings.HasPrefix(d, kind+":") {
			return false
		}
	}
	for _, c := range m.Collected {
		if c == kind {
			return true
		}
	}
	return false
}

type Collector struct {
	cs          kubernetes.Interface
	dyn         dynamic.Interface            // nil under NewWithClient (tests) unless injected
	disco       discovery.DiscoveryInterface // nil under NewWithClient (tests) unless injected
	cfg         *rest.Config                 // captured, no longer discarded — basis of RESTConfig()
	contextName string

	// now is the reading clock. nil means time.Now, which is every real audit; WithClock pins it so a
	// reference reading can be regenerated tomorrow and say the same thing.
	now func() time.Time

	// onStep, when set, fires once per resource kind as Collect finishes it:
	// (kind, item-count, denied). It powers the Glass-Box live stream (Act 1
	// ledger + amber denial rows). Count is the real list-result length; a denied
	// kind reports count 0, denied=true. nil ⇒ no streaming (CLI path). The
	// callback runs synchronously inside Collect, so it must not block.
	onStep func(kind string, count int, cause string)
	// only, when set, is the scope of core kinds to list (see Only). Empty means everything.
	only map[string]bool
	// replay, when set, is the inventory this collector returns instead of reading a cluster (FromInventory).
	replay *Inventory
}

// SetOnStep installs a per-kind collection progress callback (see Collector.onStep).
// Set by the desktop app before Collect to stream the collection ledger; the CLI
// leaves it nil. Returns the receiver for chaining.
func (c *Collector) SetOnStep(fn func(kind string, count int, cause string)) *Collector {
	c.onStep = fn
	return c
}

// Option configures a Collector at construction. Deliberately construction-time only: see
// WithTransportRecorder for why a post-construction setter cannot work here.
type Option func(*options)

type options struct {
	recorder       recorderInstaller
	now            func() time.Time
	stop           context.Context
	requestTimeout time.Duration
}

// DefaultRequestTimeout bounds every request a collector sends, discovery included.
//
// THE CONFIG CARRIED NO TIMEOUT, and the first request of a collection — the server's version — takes no context.
// Against a TLS listener that completed the handshake and never answered, an audit sat at "collecting…" for 296
// seconds, until the listener went away, and then reported "0 problems"; a scheduled run would have held its lock
// for hours. Thirty seconds is the budget each page of a list has (pageTimeout), so a slow cluster loses nothing
// it had.
const DefaultRequestTimeout = 30 * time.Second

// WithRequestTimeout replaces DefaultRequestTimeout. For tests that need a silent server to be silent quickly; an
// audit never passes it.
func WithRequestTimeout(d time.Duration) Option {
	return func(o *options) { o.requestTimeout = d }
}

// recorderInstaller is the narrow shape New needs from a request recorder, kept as a local interface so
// this package does not have to name internal/trace in its signature and so tests can substitute.
type recorderInstaller interface {
	Wrap(trace.Target) func(http.RoundTripper) http.RoundTripper
}

// WithTransportRecorder installs a request recorder on the rest.Config BEFORE any client is built.
//
// The ordering is not stylistic. kubernetes.NewForConfig takes a shallow copy of the config and freezes
// its http.Client at construction, so a recorder installed afterwards — via RESTConfig(), the obvious
// move, since this type already has a post-construction setter in SetOnStep — mutates a config nobody
// reads again. That produces the worst possible state: a recorder that looks installed, reports a
// plausible number, and has silently missed the entire collection. A test pins this.
//
// Installed with cfg.Wrap rather than by assigning cfg.WrapTransport, because an auth provider may
// already have installed a wrapper of its own (client-go does exactly that for exec and auth-provider
// kubeconfigs) and assignment would destroy it — breaking authentication on precisely the managed
// clusters this tool exists for.
func WithTransportRecorder(r recorderInstaller) Option {
	return func(o *options) { o.recorder = r }
}

// WithClock pins the instant a reading is taken at, so a reference reading is REPRODUCIBLE.
//
// Meta.StartedAt is the clock every duration in a finding is measured against — `readingTime(inv)` in
// internal/rules returns it — and it was `time.Now()` with no way to say otherwise. The committed golden
// therefore carried a sentence that changed by itself: "62 day(s) since the pod was created" became 63 at
// midnight, and `make ci` failed the next morning on a tree nobody had touched. The fixture's own objects
// are stamped absolutely on purpose ("a golden document regenerated in a year must still say the same
// thing"), which fixes the STATE and leaves every DURATION drifting, because the other end of the
// subtraction was the wall clock.
//
// A real audit never passes this: the zero value is time.Now and the collector has no idea whether its
// cluster is real.
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// New builds a Collector from a kubeconfig path and optional context name.
func New(kubeconfigPath, contextName string, opts ...Option) (*Collector, error) {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := loader.ClientConfig()
	if err != nil {
		return nil, kubeconfigError(err, rules, contextName)
	}
	// THE CONTEXT THE READING WAS TAKEN THROUGH, NOT THE FLAG. With no --context the flag is empty, and an empty
	// context name made every reading through the current context "cluster": the report's title, a history
	// directory every such cluster shared, and a name `shoalcheck findings` — which resolves the current context,
	// as it should — could not find the reading under. The kubeconfig names its current context; that is the name.
	if contextName == "" {
		if raw, rerr := loader.RawConfig(); rerr == nil {
			contextName = raw.CurrentContext
		}
	}
	// One request in flight at a time, so the limit only binds on pages the server answers faster than 1/50 s.
	// See the constants beside paginate and docs/engine/scale.md.
	cfg.QPS, cfg.Burst = collectorQPS, collectorBurst
	// Bounded unless the kubeconfig bounded it itself. See DefaultRequestTimeout.
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultRequestTimeout
		if o.requestTimeout > 0 {
			cfg.Timeout = o.requestTimeout
		}
	}
	// Before the clients: every one of them copies the transport at construction.
	if o.recorder != nil {
		cfg.Wrap(o.recorder.Wrap(trace.TargetAPIServer))
	}
	// After the recorder, so it wraps it (WithStop says why).
	if o.stop != nil {
		stop := o.stop
		cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { return stopTransport{stop: stop, next: rt} })
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	disco, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build discovery client: %w", err)
	}
	return &Collector{cs: cs, dyn: dyn, disco: disco, cfg: cfg, contextName: contextName, now: o.now}, nil
}

// NewWithClient injects a clientset — used by tests (fake clientset).
// Only limits the collection to the named core kinds (server-resources always runs). It is what makes
// `shoalcheck preflight` take seconds: a drain question needs nodes, pods, PDBs and volumes, not twenty-seven kinds.
// Returns the collector so it chains.
func (c *Collector) Only(kinds ...string) *Collector {
	c.only = make(map[string]bool, len(kinds))
	for _, k := range kinds {
		c.only[k] = true
	}
	return c
}

func NewWithClient(cs kubernetes.Interface) *Collector {
	return &Collector{cs: cs}
}

// NewWithClients injects a clientset PLUS a dynamic client and discovery client
// — used by tests of the dynamic/discovery path (fake dynamic clientset +
// fakediscovery). cfg stays nil, so RESTConfig() returns nil under this
// constructor, exactly as it does under NewWithClient.
func NewWithClients(cs kubernetes.Interface, dyn dynamic.Interface, disco discovery.DiscoveryInterface, opts ...Option) *Collector {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	return &Collector{cs: cs, dyn: dyn, disco: disco, now: o.now}
}

// RESTConfig returns the authenticated rest.Config used for collection, or nil
// when the Collector was built from an injected clientset (tests). Callers (the
// App auto-connect track) use it to reach in-cluster Services via the
// API-server proxy with the SAME read-only creds — there is one captured config,
// exposed once.
func (c *Collector) RESTConfig() *rest.Config { return c.cfg }

// readAt is the instant this reading is taken at. See WithClock.
func (c *Collector) readAt() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Clientset returns the read-only kubernetes.Interface used for collection, or
// nil under NewWithClient(s) (tests without one injected). Used only by the
// App's OPT-IN port-forward fallback (EndpointSlice lookup for a Ready pod); the
// audit itself never needs the clientset exposed. It carries the SAME read-only
// creds as collection — no new trust boundary.
func (c *Collector) Clientset() kubernetes.Interface { return c.cs }

// Collect lists the eighteen in-scope core/typed resource kinds plus any named
// operator CRDs requested via wantGVRs (status/spec only — never Secrets/
// ConfigMaps/pod-env). A per-kind failure (typically RBAC) degrades into
// Meta.Denied instead of failing the run — a partial snapshot still produces an
// honest report. In Phase 0 every caller passes wantGVRs=nil (no analyzers
// registered yet), so the stack-collection pass is a no-op and behaviour is
// byte-identical to the pre-Phase-0 collector.
// ErrClusterSilent marks a cluster that did not answer at all, as distinct from one that answered by refusing.
// The two are different sentences for whoever is reading: the first points at a VPN or a stale kubeconfig
// entry, the second at an RBAC binding.
var ErrClusterSilent = errors.New("cluster did not answer")

// ProbeServices reads the Service list, and nothing else, after one cheap reachability check.
//
// This exists because the Prometheus pre-flight used to call Collect and then consume exactly one field of the
// result. Collect sweeps the whole cluster — around twenty lists plus discovery — so a probe that needed one
// list cost twenty-one requests, and the app re-fires it every time the operator changes the selection. Against
// a cluster that cannot be reached, all twenty-one fail: a real fleet run reported "21 never got an answer",
// and that was one probe of one cluster nobody audited.
//
// The reachability check comes FIRST and returns on failure, so an unreachable cluster costs one request rather
// than twenty-one. /version is the cheapest thing an API server answers and it is unauthenticated-friendly
// enough to distinguish "nothing is listening" from "you may not read Services", which are different sentences
// for the operator.
//
// The requests still travel the collector's own transport, so the session trace counts them exactly as before.
// Spending fewer requests is the point; hiding them would not be.
func (c *Collector) ProbeServices(ctx context.Context) ([]corev1.Service, error) {
	if _, err := c.cs.Discovery().ServerVersion(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClusterSilent, err)
	}
	var out []corev1.Service
	err := paginate(ctx, func() { out = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
		l, err := c.cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return "", err
		}
		out = append(out, l.Items...)
		return l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		// A cluster with no Services is a real answer, and the caller distinguishes "none found" from "could
		// not look" by the error, so never hand back a nil slice with a nil error.
		out = []corev1.Service{}
	}
	return out, nil
}

func (c *Collector) Collect(ctx context.Context, wantGVRs []schema.GroupVersionResource) (*Inventory, error) {
	if c.replay != nil {
		return c.replayed()
	}
	inv := &Inventory{}
	// THE DATE OF THE READING AND HOW LONG IT TOOK ARE TWO CLOCKS. StartedAt is what every duration in a
	// finding is measured against and is pinnable, so a reference reading can be regenerated tomorrow and
	// say the same thing; the run's own duration is wall time and stays wall time, or a pinned reading
	// reports the hours between the pinned instant and the moment it was generated. Measured once: 39,796
	// seconds for a run that took 0.4.
	startWall := time.Now()
	inv.Meta.StartedAt = c.readAt()
	inv.Meta.Context = c.contextName

	// A SERVER THAT DID NOT ANSWER ITS VERSION IS NOT ASKED THIRTY MORE TIMES. A refused connection, a request that
	// timed out, or credentials the server rejects outright (401) will be the answer to every list as well, and
	// sending them one by one turned one bounded failure into minutes of the same failure — 203 seconds against a
	// black-holed address. Every kind is still recorded as unread, with this cause, so the reading says what it
	// could not do exactly as before; it just stops waiting to find out. A 403 on the version is not this case:
	// an identity may be refused /version and allowed its lists.
	var silent error
	if v, err := c.cs.Discovery().ServerVersion(); err == nil {
		inv.Meta.ServerVersion = v.GitVersion
	} else if cause := CauseOf(err.Error()); cause == "not reachable" || cause == "timed out" || apierrors.IsUnauthorized(err) ||
		cause == "credentials not accepted" || cause == "credentials could not be obtained" || cause == "certificate not accepted" {
		silent = err
	}

	// countOf maps a kind to its live item-count getter, so step can report the
	// real list-result length to onStep WITHOUT changing its signature (kept
	// stable because collectStack takes step as a parameter). A kind absent here
	// (e.g. "cr:*" operator CRs) reports 0 — it has no headline count in Act 1.
	countOf := countsOf(inv)
	step := func(kind string, fn func(ctx context.Context) error) {
		// A scoped collection (Only) skips the kinds a question does not need. A skipped kind is neither
		// collected nor denied: the rules that need it see "not read" and stay silent, and the preflight
		// names it as out of scope rather than as refused.
		if len(c.only) > 0 && kind != "server-resources" && !c.only[kind] {
			inv.Meta.OutOfScope = append(inv.Meta.OutOfScope, kind)
			return
		}
		// A LIST'S BUDGET, NOT A PAGE'S. This was thirty seconds for every page of a list together, so a 66-page
		// pod list on a 2,000-node cluster had half a second a page and would have been recorded unread on a
		// server that answered every page; each page now has pageTimeout of its own, inside paginate.
		sctx, cancel := context.WithTimeout(ctx, listBudget)
		defer cancel()
		run := fn
		if silent != nil {
			run = func(context.Context) error { return silent }
		}
		if err := run(sctx); err != nil {
			inv.Meta.Denied = append(inv.Meta.Denied, fmt.Sprintf("%s: %v", kind, err))
			if c.onStep != nil {
				// THE CAUSE, not a bool. A boolean flattened six reasons a list can fail to one, and every
				// live surface downstream then chose a word for it — the terminal frame chose "denied by
				// RBAC", which is a claim about the operator's permissions that an unreachable cluster
				// does not support. CauseOf never returns the error text: it carries the API server's
				// address on a network failure and the caller's identity on a permission failure.
				c.onStep(kind, 0, CauseOf(err.Error()))
			}
			return
		}
		inv.Meta.Collected = append(inv.Meta.Collected, kind)
		if c.onStep != nil {
			n := 0
			if g := countOf[kind]; g != nil {
				n = g()
			}
			c.onStep(kind, n, "")
		}
	}

	step("server-resources", func(ctx context.Context) error {
		if c.disco == nil {
			return fmt.Errorf("discovery client unavailable")
		}
		lists, err := c.disco.ServerPreferredResources()
		// Partial discovery (a broken aggregated APIService — commonly
		// metrics.k8s.io) returns a non-nil ErrGroupDiscoveryFailed AND the
		// groups that DID resolve. Use them; never fail the run on it.
		if err != nil && !discovery.IsGroupDiscoveryFailedError(err) {
			return err
		}
		inv.PresentGVRs = gvrSetFromLists(lists)
		// EVERY served version, for the upgrade family. A deprecated group/version is never the preferred
		// one, so the call above cannot see it — which is why this is a second request rather than a
		// different reading of the first.
		if groups, gerr := c.disco.ServerGroups(); gerr == nil && groups != nil {
			for _, g := range groups.Groups {
				for _, v := range g.Versions {
					inv.ServedGroupVersions = append(inv.ServedGroupVersions, v.GroupVersion)
				}
			}
			sort.Strings(inv.ServedGroupVersions)
		}
		if derr, ok := err.(*discovery.ErrGroupDiscoveryFailed); ok {
			// SORTED, because this ranges a MAP. Nothing downstream reads the list today, but it travels on
			// the Inventory, and the moment an inventory is serialized for replay an unsorted list makes the
			// captured file differ between two readings of one cluster. ServedGroupVersions three lines above
			// is sorted for the same reason; this one was missed.
			for gv := range derr.Groups {
				inv.Meta.PartialDiscovery = append(inv.Meta.PartialDiscovery, gv.String())
			}
			sort.Strings(inv.Meta.PartialDiscovery)
		}
		return nil
	})

	step("nodes", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.Nodes = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().Nodes().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.Nodes = append(inv.Nodes, l.Items...)
			return l.Continue, nil
		})
	})
	step("namespaces", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.Namespaces = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().Namespaces().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.Namespaces = append(inv.Namespaces, l.Items...)
			return l.Continue, nil
		})
	})
	step("deployments", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.Deployments = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.Deployments = append(inv.Deployments, l.Items...)
			return l.Continue, nil
		})
	})
	step("statefulsets", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.StatefulSets = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.StatefulSets = append(inv.StatefulSets, l.Items...)
			return l.Continue, nil
		})
	})
	step("daemonsets", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.DaemonSets = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.DaemonSets = append(inv.DaemonSets, l.Items...)
			return l.Continue, nil
		})
	})
	step("pods", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.Pods = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.Pods = append(inv.Pods, l.Items...)
			return l.Continue, nil
		})
	})
	step("services", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.Services = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.Services = append(inv.Services, l.Items...)
			return l.Continue, nil
		})
	})
	step("endpointslices", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.EndpointSlices = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.EndpointSlices = append(inv.EndpointSlices, l.Items...)
			return l.Continue, nil
		})
	})
	step("poddisruptionbudgets", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.PDBs = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.PolicyV1().PodDisruptionBudgets(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.PDBs = append(inv.PDBs, l.Items...)
			return l.Continue, nil
		})
	})

	// RBAC: bindings AND bodies. A binding names a role; only the body says what that role grants, and
	// without it nine CIS controls could not be evidenced by anything (see the Inventory comment). Each is
	// its own step, so an RBAC denial on one degrades into Meta.Denied rather than failing the run — and
	// internal/rules/rbac_grants.go refuses to reason about absence when the step was denied.
	step("clusterrolebindings", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.ClusterRoleBindings = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.RbacV1().ClusterRoleBindings().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.ClusterRoleBindings = append(inv.ClusterRoleBindings, l.Items...)
			return l.Continue, nil
		})
	})
	step("rolebindings", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.RoleBindings = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.RoleBindings = append(inv.RoleBindings, l.Items...)
			return l.Continue, nil
		})
	})
	step("clusterroles", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.ClusterRoles = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.RbacV1().ClusterRoles().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.ClusterRoles = append(inv.ClusterRoles, l.Items...)
			return l.Continue, nil
		})
	})
	step("roles", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.Roles = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.RbacV1().Roles(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.Roles = append(inv.Roles, l.Items...)
			return l.Continue, nil
		})
	})
	step("serviceaccounts", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.ServiceAccounts = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.ServiceAccounts = append(inv.ServiceAccounts, l.Items...)
			return l.Continue, nil
		})
	})
	step("networkpolicies", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.NetworkPolicies = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.NetworkPolicies = append(inv.NetworkPolicies, l.Items...)
			return l.Continue, nil
		})
	})
	step("resourcequotas", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.ResourceQuotas = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().ResourceQuotas(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.ResourceQuotas = append(inv.ResourceQuotas, l.Items...)
			return l.Continue, nil
		})
	})
	step("limitranges", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.LimitRanges = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().LimitRanges(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.LimitRanges = append(inv.LimitRanges, l.Items...)
			return l.Continue, nil
		})
	})
	step("persistentvolumes", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.PVs = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().PersistentVolumes().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.PVs = append(inv.PVs, l.Items...)
			return l.Continue, nil
		})
	})
	step("persistentvolumeclaims", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.PVCs = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.PVCs = append(inv.PVCs, l.Items...)
			return l.Continue, nil
		})
	})
	step("ingresses", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.Ingresses = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.Ingresses = append(inv.Ingresses, l.Items...)
			return l.Continue, nil
		})
	})
	step("horizontalpodautoscalers", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.HPAs = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.AutoscalingV2().HorizontalPodAutoscalers(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.HPAs = append(inv.HPAs, l.Items...)
			return l.Continue, nil
		})
	})
	// CronJobs only. batch/v1 Jobs are not listed anywhere in this package, by design — see the
	// Inventory field's comment.
	// A NIL DYNAMIC CLIENT IS A HARNESS CONDITION, NOT A CLUSTER ONE. Production always builds one from
	// the kubeconfig; only NewWithClient leaves it nil. Attempting the read anyway would record a DENIAL
	// — "we asked and were refused" — for a request that was never sent, and that lie is exactly the one
	// the denial guards exist to prevent, told about ourselves.
	if c.dyn != nil {
		step("customresourcedefinitions", func(ctx context.Context) error {
			items, err := c.ListCR(ctx, schema.GroupVersionResource{
				Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}, "")
			if err != nil {
				return err
			}
			for i := range items {
				inv.CRDs = append(inv.CRDs, crdInfoFrom(&items[i]))
			}
			return nil
		})
	}
	step("storageclasses", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.StorageClasses = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.StorageV1().StorageClasses().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.StorageClasses = append(inv.StorageClasses, l.Items...)
			return l.Continue, nil
		})
	})
	step("ingressclasses", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.IngressClasses = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.NetworkingV1().IngressClasses().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.IngressClasses = append(inv.IngressClasses, l.Items...)
			return l.Continue, nil
		})
	})
	step("priorityclasses", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.PriorityClasses = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.SchedulingV1().PriorityClasses().List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.PriorityClasses = append(inv.PriorityClasses, l.Items...)
			return l.Continue, nil
		})
	})
	step("jobs", func(ctx context.Context) error {
		// THE LIMIT IS THE CLAIM'S HONESTY, not a performance tweak. A cluster that has been running
		// nightly work for a year holds tens of thousands of Jobs; reading all of them would make one
		// audit dominate the API server's memory for the sake of a hygiene finding. So the read is
		// bounded and the bound is RECORDED — a truncated list that renders as complete would let a rule
		// say "12 Jobs have no TTL" when the true number is unknown.
		const jobPageCap = 2000
		return paginate(ctx, func() { inv.Jobs, inv.JobsTruncated = nil, false }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			for i := range l.Items {
				if len(inv.Jobs) >= jobPageCap {
					inv.JobsTruncated = true
					return "", nil // stop paginating; the flag is what makes this honest
				}
				inv.Jobs = append(inv.Jobs, l.Items[i])
			}
			return l.Continue, nil
		})
	})
	step("cronjobs", func(ctx context.Context) error {
		return paginate(ctx, func() { inv.CronJobs = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
			l, err := c.cs.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, opts)
			if err != nil {
				return "", err
			}
			inv.CronJobs = append(inv.CronJobs, l.Items...)
			return l.Continue, nil
		})
	})

	// Operator-CR collection (Phase 3). wantGVRs is nil in Phase 0, so this is a
	// no-op; collectStack itself runs each CR list through the same step wrapper
	// (30s timeout, degrade into Meta.Denied) when analyzers are registered.
	c.collectStack(ctx, inv, step, wantGVRs)

	inv.Meta.Duration = time.Since(startWall)
	// Environment values leave the inventory before anything reads it. See dropEnvValues. The volume is measured
	// first, because it stands for the objects as the API server sent them.
	inv.volume = volumeOf(inv)
	dropEnvValues(inv)
	inv.KubeadmControlPlane = kubeadmControlPlane(inv.Nodes, inv.Pods)
	return inv, nil
}

// countsOf maps a kind to its live item-count getter over inv. One table for a live read and a replayed one, so
// the live stream cannot report one count for a kind read from the API server and another for the same kind
// replayed from a capture.
func countsOf(inv *Inventory) map[string]func() int {
	return map[string]func() int{
		"server-resources":          func() int { return len(inv.PresentGVRs) },
		"customresourcedefinitions": func() int { return len(inv.CRDs) },
		"nodes":                     func() int { return len(inv.Nodes) },
		"endpointslices":            func() int { return len(inv.EndpointSlices) },
		"namespaces":                func() int { return len(inv.Namespaces) },
		"deployments":               func() int { return len(inv.Deployments) },
		"statefulsets":              func() int { return len(inv.StatefulSets) },
		"daemonsets":                func() int { return len(inv.DaemonSets) },
		"pods":                      func() int { return len(inv.Pods) },
		"services":                  func() int { return len(inv.Services) },
		"poddisruptionbudgets":      func() int { return len(inv.PDBs) },
		"clusterrolebindings":       func() int { return len(inv.ClusterRoleBindings) },
		"rolebindings":              func() int { return len(inv.RoleBindings) },
		"clusterroles":              func() int { return len(inv.ClusterRoles) },
		"roles":                     func() int { return len(inv.Roles) },
		"serviceaccounts":           func() int { return len(inv.ServiceAccounts) },
		"networkpolicies":           func() int { return len(inv.NetworkPolicies) },
		"resourcequotas":            func() int { return len(inv.ResourceQuotas) },
		"limitranges":               func() int { return len(inv.LimitRanges) },
		"persistentvolumes":         func() int { return len(inv.PVs) },
		"persistentvolumeclaims":    func() int { return len(inv.PVCs) },
		"ingresses":                 func() int { return len(inv.Ingresses) },
		"horizontalpodautoscalers":  func() int { return len(inv.HPAs) },
		"cronjobs":                  func() int { return len(inv.CronJobs) },
		"jobs":                      func() int { return len(inv.Jobs) },
		"storageclasses":            func() int { return len(inv.StorageClasses) },
		"ingressclasses":            func() int { return len(inv.IngressClasses) },
		"priorityclasses":           func() int { return len(inv.PriorityClasses) },
	}
}

// HOW A LIST IS READ, and what it costs the API server. Stated in docs/engine/scale.md, and kept here as the
// constants it states:
//
//   - pageSize objects a page (kubectl's own --chunk-size default), one request in flight at a time — the
//     collector reads its kinds one after another, never in parallel — and never a watch;
//   - at most collectorQPS requests a second, with a burst of collectorBurst (client-go's token bucket);
//   - each page has pageTimeout, and a whole list has listBudget, so a 66-page pod list on a large cluster is not
//     held to the thirty seconds a single page gets.
const (
	pageSize       = 500
	collectorQPS   = 50
	collectorBurst = 100
	pageTimeout    = 30 * time.Second
	listBudget     = 10 * time.Minute
	// maxListRestarts bounds how many times an expired continue token restarts a list from its first page.
	maxListRestarts = 2
)

// throttleBackoff is how long a list waits before asking again for a page the server answered 429 without a
// Retry-After, attempt by attempt. client-go retries a 429 itself only when the server says how long to wait —
// priority and fairness always does, an older server or a proxy in front of one may not — so without this a busy
// cluster's throttled list was recorded as unread. A variable so the tests can shorten it.
var throttleBackoff = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}

// errCutShort marks a list that read at least one page and then failed. The pages it did read are dropped: a
// list that stopped part-way is not the cluster's list, and keeping them let the cost model, the architecture and
// every count that walks the slice read part of the cluster as all of it.
type errCutShort struct {
	pages int
	err   error
}

func (e *errCutShort) Error() string {
	return fmt.Sprintf("list cut short after %d page(s): %v", e.pages, e.err)
}
func (e *errCutShort) Unwrap() error { return e.err }

// paginate drives a Limit/Continue list loop, and owns what a list that does not finish means.
//
// list reads one page with the context it is given and appends what it read; reset empties what it appended.
// Three answers are not the end of the list:
//
//   - 429 Too Many Requests that client-go did not already retry is retried after throttleBackoff, from the same
//     page — a throttled list is a busy server, not an unreadable kind;
//   - 410 Gone on a later page is a continue token the server no longer holds (a list slower than its snapshot):
//     the list starts again from its first page, at most maxListRestarts times, after reset — never appending
//     the second attempt to the first;
//   - any other failure after a page was read is a list cut short: reset, and an errCutShort, whose cause the
//     surfaces print as "cut short".
func paginate(ctx context.Context, reset func(), list func(context.Context, metav1.ListOptions) (string, error)) error {
	opts := metav1.ListOptions{Limit: pageSize}
	pages, restarts, throttled := 0, 0, 0
	for {
		pctx, cancel := context.WithTimeout(ctx, pageTimeout)
		cont, err := list(pctx, opts)
		cancel()
		switch {
		case err == nil:
			pages++
			throttled = 0
			if cont == "" {
				return nil
			}
			opts.Continue = cont
			continue
		case apierrors.IsTooManyRequests(err) && throttled < len(throttleBackoff):
			wait := throttleBackoff[throttled]
			throttled++
			if s, ok := apierrors.SuggestsClientDelay(err); ok && time.Duration(s)*time.Second > wait {
				wait = time.Duration(s) * time.Second
			}
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				err = ctx.Err()
			case <-t.C:
				continue
			}
		case (apierrors.IsResourceExpired(err) || apierrors.IsGone(err)) && opts.Continue != "" && restarts < maxListRestarts:
			restarts++
			reset()
			pages, opts.Continue = 0, ""
			continue
		}
		reset()
		if pages > 0 {
			return &errCutShort{pages: pages, err: err}
		}
		return err
	}
}

// kubeconfigError turns client-go's kubeconfig failures into what a stranger can act on. It is the first
// failure most people meet, and client-go's own sentence for an absent kubeconfig recommends
// KUBERNETES_MASTER, a variable this product never reads. Two cases are rewritten; everything else keeps
// client-go's words under the same prefix it always had.
func kubeconfigError(err error, rules *clientcmd.ClientConfigLoadingRules, contextName string) error {
	if clientcmd.IsEmptyConfig(err) {
		where := rules.GetLoadingPrecedence()
		if rules.ExplicitPath != "" {
			where = []string{rules.ExplicitPath}
		}
		return fmt.Errorf("no kubeconfig found (looked at %s): pass --kubeconfig <path>, or set KUBECONFIG",
			strings.Join(where, ", "))
	}
	// client-go reports a missing context inside an aggregate "invalid configuration" error, which
	// IsContextNotFound does not see through, so the kubeconfig itself is asked whether the name is in it.
	if contextName != "" {
		if raw, lerr := rules.Load(); lerr == nil && len(raw.Contexts) > 0 && raw.Contexts[contextName] == nil {
			names := make([]string, 0, len(raw.Contexts))
			for n := range raw.Contexts {
				names = append(names, n)
			}
			sort.Strings(names)
			return fmt.Errorf("context %q is not in this kubeconfig; it has: %s", contextName,
				strings.Join(names, ", "))
		}
	}
	return fmt.Errorf("load kubeconfig: %w", err)
}

// lastApplied is the annotation `kubectl apply` writes: the whole applied manifest, environment values included.
const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// dropEnvValues removes every literal environment value from the inventory. The collector never asks for one —
// but a pod list answers with whole pod specs, so `env[].value` (routinely a connection string or a token) arrived
// in every pod, in every workload's pod template, and inside the last-applied annotation, and sat in memory for
// the whole run beside the published claim that pod environment values are never read (claims review,
// 2026-10-21). The names and the valueFrom references stay: the duplicate-variable and secret-in-environment
// rules are about those, and neither is a value. Nothing reads last-applied — internal/boundaries refuses it as a
// source — so it goes whole.
func dropEnvValues(inv *Inventory) {
	scrub := func(meta *metav1.ObjectMeta, spec *corev1.PodSpec) {
		delete(meta.Annotations, lastApplied)
		for i := range spec.InitContainers {
			dropValues(spec.InitContainers[i].Env)
		}
		for i := range spec.Containers {
			dropValues(spec.Containers[i].Env)
		}
		for i := range spec.EphemeralContainers {
			dropValues(spec.EphemeralContainers[i].Env)
		}
	}
	for i := range inv.Pods {
		scrub(&inv.Pods[i].ObjectMeta, &inv.Pods[i].Spec)
	}
	for i := range inv.Deployments {
		scrub(&inv.Deployments[i].ObjectMeta, &inv.Deployments[i].Spec.Template.Spec)
	}
	for i := range inv.StatefulSets {
		scrub(&inv.StatefulSets[i].ObjectMeta, &inv.StatefulSets[i].Spec.Template.Spec)
	}
	for i := range inv.DaemonSets {
		scrub(&inv.DaemonSets[i].ObjectMeta, &inv.DaemonSets[i].Spec.Template.Spec)
	}
	for i := range inv.Jobs {
		scrub(&inv.Jobs[i].ObjectMeta, &inv.Jobs[i].Spec.Template.Spec)
	}
	for i := range inv.CronJobs {
		scrub(&inv.CronJobs[i].ObjectMeta, &inv.CronJobs[i].Spec.JobTemplate.Spec.Template.Spec)
	}
}

// DropEnvValues is dropEnvValues for an inventory this package did not read: the objects a pull request's
// manifests describe, decoded by internal/overlay. Exported rather than re-implemented there, so a value a read
// would have dropped cannot survive the other path into a reading.
func DropEnvValues(inv *Inventory) { dropEnvValues(inv) }

func dropValues(env []corev1.EnvVar) {
	for i := range env {
		env[i].Value = ""
	}
}
