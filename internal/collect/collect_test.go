package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestCollect_GathersCoreResources(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d1", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "crb1"}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "np1", Namespace: "default"}},
		&autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "hpa1", Namespace: "default"}},
	)
	// A DYNAMIC CLIENT, because customresourcedefinitions is read through it — see collect/crd.go for
	// why it is not the typed clientset. Without one the collector correctly SKIPS that step rather than
	// recording a denial for a request it never sent, and this test would then count 26 kinds against a
	// declared 27 and fail for a reason that is about the harness.
	crdGVR := schema.GroupVersionResource{
		Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{crdGVR: "CustomResourceDefinitionList"})
	inv, err := NewWithClients(cs, dyn, nil).Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(inv.Nodes) != 1 || len(inv.Namespaces) != 1 || len(inv.Deployments) != 1 || len(inv.Pods) != 1 {
		t.Fatalf("inventory miscounts: %d nodes %d ns %d deploys %d pods",
			len(inv.Nodes), len(inv.Namespaces), len(inv.Deployments), len(inv.Pods))
	}
	if len(inv.ClusterRoleBindings) != 1 || len(inv.NetworkPolicies) != 1 || len(inv.HPAs) != 1 {
		t.Fatalf("new-kind miscounts: %d clusterrolebindings %d networkpolicies %d hpas",
			len(inv.ClusterRoleBindings), len(inv.NetworkPolicies), len(inv.HPAs))
	}
	// DERIVED, NOT COUNTED BY HAND. This assertion used to hold the literal 19, and adding the
	// cronjobs step made it fail for the only reason a hand-maintained count ever fails: the number
	// was right about a tree that had changed. CollectedResources() is the same declaration
	// TestRBACContractMatchesCollector pins against deploy/rbac.yaml, so a new always-on step now
	// updates all three sides at once.
	//
	// server-resources is NOT collected here: NewWithClient injects no discovery client, so that
	// step degrades into Meta.Denied (asserted below).
	wantKinds := 0
	for _, ra := range CollectedResources() {
		if !ra.Opportunistic {
			wantKinds++
		}
	}
	if len(inv.Meta.Collected) != wantKinds {
		t.Errorf("Collected = %v (%d kinds), want the %d always-on kinds CollectedResources declares",
			inv.Meta.Collected, len(inv.Meta.Collected), wantKinds)
	}
	gotDiscoveryDenied := false
	for _, d := range inv.Meta.Denied {
		if strings.Contains(d, "server-resources") {
			gotDiscoveryDenied = true
		}
	}
	if !gotDiscoveryDenied {
		t.Errorf("server-resources should degrade into Meta.Denied under NewWithClient (no discovery); Denied = %v", inv.Meta.Denied)
	}
}

func TestCollect_DegradesGracefullyOnRBACDenial(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}})
	cs.PrependReactor("list", "poddisruptionbudgets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "policy", Resource: "poddisruptionbudgets"}, "", nil)
	})
	inv, err := NewWithClient(cs).Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("a single RBAC denial must not fail collection: %v", err)
	}
	if len(inv.Nodes) != 1 {
		t.Error("nodes should still be collected")
	}
	found := false
	for _, d := range inv.Meta.Denied {
		if strings.Contains(d, "poddisruptionbudgets") {
			found = true
		}
	}
	if !found {
		t.Errorf("denial not recorded: %v", inv.Meta.Denied)
	}
}

// SetOnStep must fire once per kind with the REAL item count as each list
// returns, and stream an amber denial (count 0, denied=true) for a blocked kind
// — the collection-count honesty guard for the Glass-Box Act-1 ledger.
func TestCollect_OnStepStreamsCountsAndDenials(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n2"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"}},
	)
	cs.PrependReactor("list", "poddisruptionbudgets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "policy", Resource: "poddisruptionbudgets"}, "", nil)
	})

	type ev struct {
		kind  string
		count int
		cause string
	}
	var got []ev
	col := NewWithClient(cs).SetOnStep(func(kind string, count int, cause string) {
		got = append(got, ev{kind, count, cause})
	})
	if _, err := col.Collect(context.Background(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byKind := map[string]ev{}
	for _, e := range got {
		byKind[e.kind] = e
	}
	if e, ok := byKind["nodes"]; !ok || e.cause != "" || e.count != 2 {
		t.Errorf("nodes step: want count=2 and no cause, got %+v (present=%v)", e, ok)
	}
	if e, ok := byKind["pods"]; !ok || e.cause != "" || e.count != 1 {
		t.Errorf("pods step: want count=1 and no cause, got %+v (present=%v)", e, ok)
	}
	// AND IT MUST NAME THE CAUSE, because the surfaces render what this carries. A bool here is what let
	// the terminal frame print "denied by RBAC" over an unreachable cluster: the step knew the error and
	// threw it away one line after reading it.
	if e, ok := byKind["poddisruptionbudgets"]; !ok || e.cause == "" || e.count != 0 {
		t.Errorf("an unread kind must stream count=0 with a cause, got %+v (present=%v)", e, ok)
	} else if e.cause != "not permitted" {
		t.Errorf("a forbidden list must be classified %q, got %q", "not permitted", e.cause)
	}
	// Every kind fires exactly once (no double-count, no missing kind).
	if len(got) < 19 {
		t.Errorf("expected >=19 onStep events (one per kind), got %d", len(got))
	}
}

func TestCollect_NeverTouchesSecretsOrConfigMaps(t *testing.T) {
	cs := fake.NewSimpleClientset()
	if _, err := NewWithClient(cs).Collect(context.Background(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, a := range cs.Actions() {
		r := a.GetResource().Resource
		if r == "secrets" || r == "configmaps" {
			t.Fatalf("SECURITY CONTRACT VIOLATION: collector touched %q", r)
		}
	}
}

func TestCollect_GathersPVsAndPVCs(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv1"}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv2"}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "default"}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "c2", Namespace: "default"}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "c3", Namespace: "app"}},
	)
	inv, err := NewWithClient(cs).Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(inv.PVs) != 2 {
		t.Errorf("PVs = %d, want 2", len(inv.PVs))
	}
	if len(inv.PVCs) != 3 {
		t.Errorf("PVCs = %d, want 3", len(inv.PVCs))
	}
	wantCollected := map[string]bool{"persistentvolumes": false, "persistentvolumeclaims": false}
	for _, k := range inv.Meta.Collected {
		if _, ok := wantCollected[k]; ok {
			wantCollected[k] = true
		}
	}
	for k, seen := range wantCollected {
		if !seen {
			t.Errorf("Meta.Collected missing %q: %v", k, inv.Meta.Collected)
		}
	}
}

func TestCollect_PVDeniedDegradesIntoMetaDenied(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}})
	cs.PrependReactor("list", "persistentvolumes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "", Resource: "persistentvolumes"}, "", nil)
	})
	inv, err := NewWithClient(cs).Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("a PV denial must not fail collection (honest 'storage excluded' report): %v", err)
	}
	if inv.PVs != nil {
		t.Errorf("PVs should be nil when the list is forbidden, got %d", len(inv.PVs))
	}
	found := false
	for _, d := range inv.Meta.Denied {
		if strings.Contains(d, "persistentvolumes:") {
			found = true
		}
	}
	if !found {
		t.Errorf("persistentvolumes denial not recorded in Meta.Denied: %v", inv.Meta.Denied)
	}
}

func TestRESTConfig_NilUnderInjectedClientset(t *testing.T) {
	if got := NewWithClient(fake.NewSimpleClientset()).RESTConfig(); got != nil {
		t.Errorf("RESTConfig() under NewWithClient must be nil, got %+v", got)
	}
	if got := NewWithClients(fake.NewSimpleClientset(), nil, nil).RESTConfig(); got != nil {
		t.Errorf("RESTConfig() under NewWithClients must be nil, got %+v", got)
	}
}

func TestRESTConfig_NonNilAfterNew(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "config")
	const minimal = `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: c
  context:
    cluster: c
    user: u
current-context: c
users:
- name: u
  user:
    token: t
`
	if err := os.WriteFile(kubeconfig, []byte(minimal), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	c, err := New(kubeconfig, "c")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.RESTConfig() == nil {
		t.Fatal("RESTConfig() must be non-nil after New — the App proxy path depends on the one captured config")
	}
	if c.RESTConfig().Host == "" {
		t.Error("captured rest.Config should carry the server Host")
	}
}

// TestCollect_EveryCollectedKindReportsARealCount guards a silent failure mode.
//
// step() reports an item count to onStep by looking the kind up in the countOf map, and a kind
// ABSENT from that map reports 0 — see the comment on countOf. So forgetting one entry does not
// break anything loudly: the Glass-Box Act-1 ledger simply streams a convincing "endpointslices 0"
// for a list that actually returned hundreds, and every downstream reader believes the cluster has
// none. That is the shape of an honesty bug rather than a crash, which is exactly the kind this
// project ranks above crashes.
//
// The existing coverage cannot catch it: TestCollect_OnStepStreamsCountsAndDenials asserts a floor
// on the number of events and spot-checks three kinds.
func TestCollect_EveryCollectedKindReportsARealCount(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "default"}},
		&discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Name: "s1-abc", Namespace: "default"},
			AddressType: discoveryv1.AddressTypeIPv4,
		},
	)
	c := NewWithClient(cs)

	counts := map[string]int{}
	c.SetOnStep(func(kind string, count int, cause string) {
		if cause == "" {
			counts[kind] = count
		}
	})
	inv, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Every kind whose objects we actually gathered must have reported a non-zero count, or its
	// countOf entry is missing and the ledger is lying about an empty list.
	for kind, got := range map[string]int{
		"nodes":          len(inv.Nodes),
		"namespaces":     len(inv.Namespaces),
		"pods":           len(inv.Pods),
		"services":       len(inv.Services),
		"endpointslices": len(inv.EndpointSlices),
	} {
		if got == 0 {
			t.Errorf("fixture problem: no %s were collected at all", kind)
			continue
		}
		if counts[kind] != got {
			t.Errorf("step reported %s=%d but the inventory holds %d — countOf is missing this kind, "+
				"so the ledger reports a convincing zero for a list that returned data",
				kind, counts[kind], got)
		}
	}
}

// CronJobs are the one collector addition Ground Truth 1b needs, and it is not free: one more list
// against every cluster, a new RBAC group customers review, and a `countOf` entry so the live
// collection ledger reports a real number rather than a silent zero.
//
// Jobs are deliberately NOT collected. Every CronJob run spawns one, so the volume is orders of
// magnitude larger, and status.lastSuccessfulTime on the CronJob itself already carries the claim.
func TestCollect_ListsCronJobsAndCountsThem(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "app"}},
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "rotate", Namespace: "app"}},
	)
	var counted = map[string]int{}
	c := NewWithClient(cs).SetOnStep(func(kind string, n int, cause string) {
		if cause == "" {
			counted[kind] = n
		}
	})
	inv, err := c.Collect(t.Context(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(inv.CronJobs) != 2 {
		t.Fatalf("inventory holds %d CronJobs, want 2", len(inv.CronJobs))
	}
	if !collected(inv, "cronjobs") {
		t.Errorf("Meta.Collected does not record the cronjobs step: %v", inv.Meta.Collected)
	}
	if counted["cronjobs"] != 2 {
		t.Errorf("the collection ledger reported %d cronjobs, want 2 — a kind missing from countOf "+
			"streams a silent zero", counted["cronjobs"])
	}
	// JOBS ARE NOW COLLECTED, BOUNDED, AND THE BOUND IS RECORDED — founder decision, 2026-08-29 (§10 Q2).
	//
	// This assertion used to require the OPPOSITE, on the reasoning that every CronJob run spawns a Job.
	// That reasoning was half right: the CronJob controller already bounds its own jobs
	// (successfulJobsHistoryLimit defaults to 3), so the volume risk is STANDALONE jobs nobody cleaned
	// up — which is exactly the subject the TTL finding exists for. Excluding them excluded the subject.
	if !collected(inv, "jobs") {
		t.Errorf("Meta.Collected does not record the jobs step: %v", inv.Meta.Collected)
	}
}

// The truncation flag is what keeps a bounded read honest: a list that stopped at the cap and renders as
// complete lets a rule say "12 Jobs have no TTL" when the true number is unknown. This asserts the flag is
// FALSE on a small cluster — the state where a rule may count — because a flag that is always set is as
// useless as one that never is.
func TestCollect_JobsAreNotTruncatedOnASmallCluster(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ops", Name: "backup-1"}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ops", Name: "backup-2"}},
	)
	inv, err := NewWithClient(cs).Collect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Jobs) != 2 {
		t.Fatalf("inventory holds %d Jobs, want 2", len(inv.Jobs))
	}
	if inv.JobsTruncated {
		t.Error("a two-Job cluster was reported as truncated, so no rule could ever count Jobs honestly")
	}
}

// The step name must be nameable as an apiGroup/resource tuple, or a finding resting on cronjobs
// cannot cite the request that produced it.
func TestStepToTuple_KnowsCronJobs(t *testing.T) {
	got, ok := StepToTuple("cronjobs")
	if !ok {
		t.Fatal("the cronjobs step does not resolve to a trace tuple, so its provenance would dangle")
	}
	if got != "batch/cronjobs" {
		t.Errorf("cronjobs -> %q, want %q", got, "batch/cronjobs")
	}
}

// AN ENVIRONMENT VALUE IS DROPPED ON ARRIVAL. The pod list answers with whole pod specs, and a container's literal
// `env[].value` routinely holds a connection string or a token — the collector never asked for it, but the API
// server sent it, and it sat in the inventory for the whole run beside the claim "pod environment values are never
// read" (claims review, 2026-10-21). The same value rides inside every workload's pod template and inside the
// `kubectl.kubernetes.io/last-applied-configuration` annotation, which is the whole applied manifest. Names and
// valueFrom references stay: two rules are about them, and neither is a value.
func TestCollect_DropsEnvironmentValuesOnArrival(t *testing.T) {
	const secret = "postgres://admin:s3cr3t@db:5432/app"
	spec := corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", Env: []corev1.EnvVar{{Name: "INIT_DSN", Value: secret}}}},
		Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{
			{Name: "DATABASE_URL", Value: secret},
			{Name: "API_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "api"}, Key: "token"}}},
		}}},
	}
	applied := map[string]string{"kubectl.kubernetes.io/last-applied-configuration": `{"env":[{"value":"` + secret + `"}]}`}
	tmpl := corev1.PodTemplateSpec{Spec: spec}
	cs := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default", Annotations: applied}, Spec: spec},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d1", Namespace: "default", Annotations: applied},
			Spec: appsv1.DeploymentSpec{Template: tmpl}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "default"}, Spec: appsv1.StatefulSetSpec{Template: tmpl}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "ds1", Namespace: "default"}, Spec: appsv1.DaemonSetSpec{Template: tmpl}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "j1", Namespace: "default"}, Spec: batchv1.JobSpec{Template: tmpl}},
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "default"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: tmpl}}}},
	)
	inv, err := NewWithClient(cs).Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(inv.Pods) != 1 || len(inv.Deployments) != 1 || len(inv.CronJobs) != 1 || len(inv.Jobs) != 1 {
		t.Fatalf("the fixture did not arrive: %d pods %d deployments %d jobs %d cronjobs",
			len(inv.Pods), len(inv.Deployments), len(inv.Jobs), len(inv.CronJobs))
	}
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cr3t") {
		t.Errorf("an environment value survived collection; the inventory holds %q", secret)
	}
	for _, name := range []string{"DATABASE_URL", "INIT_DSN", "API_TOKEN", `"token"`} {
		if !strings.Contains(string(b), name) {
			t.Errorf("%s is gone; names and valueFrom references are what the env rules read", name)
		}
	}
}
