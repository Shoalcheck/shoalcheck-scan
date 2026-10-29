package rules

import (
	"strings"
	"testing"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// ---------------------------------------------------------------------------------------------
// GROUND TRUTH 1b — the guard for what these rules may not say.
//
// Every one of these readings has an innocent explanation the snapshot cannot rule out. A CronJob
// may be paused on purpose or have a schedule longer than the window; a PVC may be waiting for its
// first consumer by design; an HPA at its ceiling may be sized at exactly the right number; an
// Ingress backend may be a Service some other controller resolves. So the finding states the
// observation and the window, and never the verdict.
//
// The family's own NAME contains "failures" and its output must not — the same trap rotation.go has
// with the word "rotation".
// ---------------------------------------------------------------------------------------------

var silentFailureBannedPhrases = []string{
	// Verdicts.
	"broken", "failing", "failure", "failed", "misconfigured", "stuck", "wrong",
	"under-provisioned", "underprovisioned", "over-provisioned",
	// Outcome and impact vocabulary. There is no request, revenue or SLA data in the snapshot.
	"outage", "downtime", "traffic", "users", "user-facing", "customer", "impact",
	"is down", "goes down", "data loss",
	// Promises and durations of things that happen.
	// "guaranteed" is global — see TestEveryRuleOutput_ClearsTheGlobalCopyPolicy.
	"will fail", "will take", "no impact", "minutes", "seconds",
}

func silentFailureRuleSet() []Rule {
	return []Rule{HPAPinnedAtMax{}, PVCPendingWithBlockedConsumer{}, IngressBackendUnresolved{}, CronJobNoRecentSuccess{}}
}

func TestSilentFailureRules_EmitNoUnsupportableClaim(t *testing.T) {
	inv := silentInventory()
	for _, r := range silentFailureRuleSet() {
		findings := r.Evaluate(inv, Options{})
		if len(findings) == 0 {
			t.Fatalf("%s produced no findings on the fixture — the guard would be vacuous", r.ID())
		}
		for _, f := range findings {
			blob := strings.ToLower(strings.Join([]string{
				f.Title, f.Description, f.WhyItMatters,
				strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
			}, " "))
			for _, banned := range silentFailureBannedPhrases {
				if strings.Contains(blob, banned) {
					t.Errorf("%s emits the banned phrase %q — the snapshot cannot support it.\n  finding: %s",
						r.ID(), banned, f.Title)
				}
			}
		}
	}
}

func TestSilentFailureRules_NeverCarryDollars(t *testing.T) {
	inv := silentInventory()
	for _, r := range silentFailureRuleSet() {
		for _, f := range r.Evaluate(inv, Options{}) {
			if f.DollarImpactMonthly != 0 {
				t.Errorf("%s put $%.2f on %q", r.ID(), f.DollarImpactMonthly, f.Title)
			}
		}
	}
}

// FOUNDER CONDITION 1. spec.suspend=true is a deliberate pause. Counting it as a silent failure
// would report an operator's own decision back to them as a defect.
func TestCronJob_SuspendIsADeliberatePauseNotAFinding(t *testing.T) {
	fs := (CronJobNoRecentSuccess{}).Evaluate(silentInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no CronJob findings at all, so this test proves nothing")
	}
	for _, f := range fs {
		for _, ref := range f.AffectedResources {
			if ref.Name == "suspended" {
				t.Errorf("a suspended CronJob was reported: %v", f.Evidence)
			}
		}
	}
	// And the exclusion is disclosed, not silent.
	blob := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(blob, "suspend") {
		t.Errorf("the coverage line does not disclose the suspended CronJob:\n  %s", blob)
	}
}

// FOUNDER CONDITION 2. "has never completed successfully" and "last succeeded 9 days ago" are two
// findings' worth of meaning. A nil lastSuccessfulTime is not an old timestamp, and a rule that
// renders it as one has invented a date.
func TestCronJob_NeverSucceededReadsDifferentlyFromAStaleSuccess(t *testing.T) {
	var never, stale string
	for _, f := range (CronJobNoRecentSuccess{}).Evaluate(silentInventory(), Options{}) {
		blob := f.Title + " " + f.Description + " " + strings.Join(f.Evidence, " ")
		switch f.AffectedResources[0].Name {
		case "never":
			never = blob
		case "stale":
			stale = blob
		}
	}
	if never == "" || stale == "" {
		t.Fatalf("fixture did not produce both shapes (never=%t stale=%t)", never != "", stale != "")
	}
	if !strings.Contains(strings.ToLower(never), "never") {
		t.Errorf("the nil-lastSuccessfulTime finding does not say it has never completed:\n  %s", never)
	}
	if strings.Contains(never, "before this reading (2026-") {
		t.Errorf("the nil-lastSuccessfulTime finding printed a successful-completion timestamp it does not have:\n  %s", never)
	}
	if strings.Contains(strings.ToLower(stale), "never completed") {
		t.Errorf("a CronJob with a recorded success was described as never having completed:\n  %s", stale)
	}
	if !strings.Contains(stale, "9d") {
		t.Errorf("the stale finding does not say how old the recorded success is:\n  %s", stale)
	}
	if never == stale {
		t.Error("both shapes produced identical text")
	}
}

// FOUNDER CONDITION 3. The window is named in the finding and no verdict is drawn. A window without
// its length is an unbounded claim; and a schedule longer than the window explains the reading, so
// the schedule is quoted rather than parsed.
func TestCronJob_NamesItsWindowAndQuotesTheSchedule(t *testing.T) {
	fs := (CronJobNoRecentSuccess{}).Evaluate(silentInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range fs {
		blob := f.Title + " " + f.Description + " " + strings.Join(f.Evidence, " ")
		if !strings.Contains(blob, "7d") {
			t.Errorf("finding %q never names the observation window", f.Title)
		}
		if !strings.Contains(blob, "spec.schedule") {
			t.Errorf("finding %q never quotes the schedule, so a period longer than the window reads as a defect", f.Title)
		}
	}
}

// THE MOST LIKELY FALSE POSITIVE IN THE EPIC. A Pending PVC with volumeBindingMode
// WaitForFirstConsumer and nothing consuming it is the normal, healthy state. StorageClasses are
// not collected, so the binding mode cannot be read — the referencing Pending pod is the evidence
// that a consumer exists at all.
func TestPVCPending_SilentWithoutAPendingConsumer(t *testing.T) {
	fs := (PVCPendingWithBlockedConsumer{}).Evaluate(silentInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no findings, so the exclusions below are untested")
	}
	for _, f := range fs {
		for _, ref := range f.AffectedResources {
			switch ref.Name {
			case "wffc":
				t.Errorf("a Pending PVC with no consumer was reported: %v", f.Evidence)
			case "running-consumer":
				t.Errorf("a Pending PVC whose consumer is Running was reported: %v", f.Evidence)
			case "bound":
				t.Errorf("a Bound PVC was reported: %v", f.Evidence)
			}
		}
	}
	// And the finding must not claim which of the two is waiting for the other.
	blob := strings.ToLower(strings.Join(fs[0].Evidence, " ") + fs[0].Description)
	if !strings.Contains(blob, "storageclass") {
		t.Errorf("the finding does not disclose that the binding mode was not read:\n  %s", blob)
	}
}

// Both halves are required. A Deployment legitimately sized at exactly its ceiling is not a
// finding; the ScalingLimited condition is the controller saying it wanted more.
func TestHPAPinnedAtMax_RequiresBothHalves(t *testing.T) {
	fs := (HPAPinnedAtMax{}).Evaluate(silentInventory(), Options{})
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 HPA finding, got %d", len(fs))
	}
	if fs[0].AffectedResources[0].Name != "pinned" {
		t.Errorf("flagged %q, want the HPA that is at max AND reports ScalingLimited",
			fs[0].AffectedResources[0].Name)
	}
	blob := strings.Join(fs[0].Evidence, " ")
	for _, want := range []string{"ScalingLimited", "currentReplicas", "maxReplicas"} {
		if !strings.Contains(blob, want) {
			t.Errorf("evidence does not cite %q:\n  %s", want, blob)
		}
	}
}

// "No such Service" and "a Service that publishes nothing" are different statements about
// different things. Collapsing them loses the only information that tells an operator where to look.
func TestIngressBackendUnresolved_DistinguishesAMissingServiceFromAnEmptyOne(t *testing.T) {
	var missing, empty string
	for _, f := range (IngressBackendUnresolved{}).Evaluate(silentInventory(), Options{}) {
		switch f.AffectedResources[0].Name {
		case "ing-missing":
			missing = strings.Join(f.Evidence, " ")
		case "ing-zero":
			empty = strings.Join(f.Evidence, " ")
		}
	}
	if missing == "" || empty == "" {
		t.Fatalf("fixture did not produce both shapes (missing=%t empty=%t)", missing != "", empty != "")
	}
	if !strings.Contains(missing, "no Service named") {
		t.Errorf("the missing-Service finding does not say the Service does not exist:\n  %s", missing)
	}
	if strings.Contains(missing, "conditions.ready") {
		t.Errorf("the missing-Service finding reasoned about endpoints of a Service that does not exist:\n  %s", missing)
	}
	if !strings.Contains(empty, "conditions.ready=true") {
		t.Errorf("the empty-Service finding does not cite the published readiness count:\n  %s", empty)
	}
}

// A backend this rule cannot judge must be named, not silently dropped.
func TestIngressBackendUnresolved_DisclosesBackendsItCannotJudge(t *testing.T) {
	fs := (IngressBackendUnresolved{}).Evaluate(silentInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	joined := ""
	for _, f := range fs {
		joined += strings.Join(f.Evidence, " ")
	}
	for _, want := range []string{"backend.resource", "ExternalName"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no finding discloses the %q backend shape it skipped", want)
		}
	}
}

// An absent list is not an absence of objects.
func TestSilentFailureRules_DenialGuard(t *testing.T) {
	cases := map[string][]Rule{
		"horizontalpodautoscalers": {HPAPinnedAtMax{}},
		"persistentvolumeclaims":   {PVCPendingWithBlockedConsumer{}},
		"pods":                     {PVCPendingWithBlockedConsumer{}},
		"ingresses":                {IngressBackendUnresolved{}},
		"services":                 {IngressBackendUnresolved{}},
		"endpointslices":           {IngressBackendUnresolved{}},
		"cronjobs":                 {CronJobNoRecentSuccess{}},
	}
	for denied, rs := range cases {
		inv := silentInventory()
		inv.Meta.Collected = withoutKind(inv.Meta.Collected, denied)
		inv.Meta.Denied = append(inv.Meta.Denied, denied+": forbidden")
		for _, r := range rs {
			if fs := r.Evaluate(inv, Options{}); len(fs) != 0 {
				t.Errorf("%s emitted %d findings with %q denied", r.ID(), len(fs), denied)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------------------------

func silentInventory() *collect.Inventory {
	pending := corev1.PersistentVolumeClaimPhase(corev1.ClaimPending)
	return &collect.Inventory{
		HPAs: []autoscalingv2.HorizontalPodAutoscaler{
			silentHPA("shop", "pinned", 10, 10, &autoscalingv2.HorizontalPodAutoscalerCondition{
				Type: "ScalingLimited", Status: corev1.ConditionTrue, Reason: "TooManyReplicas",
				Message: "the desired replica count is more than the maximum replica count",
			}),
			// At its ceiling, but the controller never said it wanted more.
			silentHPA("shop", "sized-at-max", 5, 5, nil),
			// The controller reports a limit, but at the FLOOR, not the ceiling.
			silentHPA("shop", "at-min", 3, 10, &autoscalingv2.HorizontalPodAutoscalerCondition{
				Type: "ScalingLimited", Status: corev1.ConditionTrue, Reason: "TooFewReplicas",
			}),
		},
		PVCs: []corev1.PersistentVolumeClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: "blocked", Namespace: "shop"},
				Status: corev1.PersistentVolumeClaimStatus{Phase: pending}},
			{ObjectMeta: metav1.ObjectMeta{Name: "wffc", Namespace: "shop"},
				Status: corev1.PersistentVolumeClaimStatus{Phase: pending}},
			{ObjectMeta: metav1.ObjectMeta{Name: "running-consumer", Namespace: "shop"},
				Status: corev1.PersistentVolumeClaimStatus{Phase: pending}},
			{ObjectMeta: metav1.ObjectMeta{Name: "bound", Namespace: "shop"},
				Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
		},
		Pods: []corev1.Pod{
			silentPod("shop", "consumer", corev1.PodPending, "blocked"),
			silentPod("shop", "happy", corev1.PodRunning, "running-consumer"),
		},
		Ingresses: []networkingv1.Ingress{
			silentIngress("shop", "ing-missing", "gone"),
			silentIngress("shop", "ing-zero", "zero"),
			silentIngress("shop", "ing-ok", "healthy"),
			silentIngressResourceBackend("shop", "ing-resource"),
			silentIngress("shop", "ing-external", "external"),
		},
		Services: []corev1.Service{
			rotSvc("shop", "zero", map[string]string{"app": "zero"}, nil),
			rotSvc("shop", "healthy", map[string]string{"app": "healthy"}, nil),
			rotSvc("shop", "external", nil, func(s *corev1.Service) {
				s.Spec.Type = corev1.ServiceTypeExternalName
				s.Spec.ExternalName = "db.example.com"
				s.Spec.ClusterIP = ""
			}),
		},
		EndpointSlices: []discoveryv1.EndpointSlice{
			rotSlice("shop", "zero", "IPv4", []rotEntry{
				{uid: "u-z1", ready: boolp(false), node: "node-a", addr: "10.2.0.1"},
			}, nil),
			rotSlice("shop", "healthy", "IPv4", []rotEntry{
				{uid: "u-h1", ready: boolp(true), node: "node-a", addr: "10.2.1.1"},
			}, nil),
		},
		CronJobs: []batchv1.CronJob{
			silentCronJob("shop", "stale", "0 3 * * *", false,
				timep(rotNow.Add(-9*24*time.Hour)), timep(rotNow.Add(-time.Hour))),
			silentCronJob("shop", "never", "*/30 * * * *", false,
				nil, timep(rotNow.Add(-3*time.Hour))),
			silentCronJob("shop", "suspended", "0 4 * * *", true,
				timep(rotNow.Add(-20*24*time.Hour)), timep(rotNow.Add(-20*24*time.Hour))),
			silentCronJob("shop", "fresh", "0 * * * *", false,
				timep(rotNow.Add(-time.Hour)), timep(rotNow.Add(-time.Hour))),
			silentCronJob("shop", "unscheduled", "0 0 1 1 *", false, nil, nil),
		},
		Meta: collect.Meta{
			Collected: []string{"horizontalpodautoscalers", "persistentvolumeclaims", "pods",
				"ingresses", "services", "endpointslices", "cronjobs"},
			StartedAt: rotNow,
		},
	}
}

func timep(t time.Time) *metav1.Time {
	mt := metav1.NewTime(t)
	return &mt
}

func silentHPA(ns, name string, current, max int32, cond *autoscalingv2.HorizontalPodAutoscalerCondition) autoscalingv2.HorizontalPodAutoscaler {
	h := autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			MaxReplicas: max,
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				Kind: "Deployment", Name: name,
			},
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{CurrentReplicas: current, DesiredReplicas: current},
	}
	if cond != nil {
		h.Status.Conditions = []autoscalingv2.HorizontalPodAutoscalerCondition{*cond}
	}
	return h
}

func silentPod(ns, name string, phase corev1.PodPhase, claim string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: apitypes.UID("u-" + name)},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
			},
		}}},
		Status: corev1.PodStatus{
			Phase: phase,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
				Reason:  "Unschedulable",
				Message: "0/3 nodes are available: pod has unbound immediate PersistentVolumeClaims",
			}},
		},
	}
}

func silentIngress(ns, name, backend string) networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: name + ".example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path: "/",
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
						Name: backend,
						Port: networkingv1.ServiceBackendPort{Number: 80},
					}},
				}},
			}},
		}}},
	}
}

func silentIngressResourceBackend(ns, name string) networkingv1.Ingress {
	ing := silentIngress(ns, name, "unused")
	ing.Spec.Rules[0].HTTP.Paths[0].Backend = networkingv1.IngressBackend{
		Resource: &corev1.TypedLocalObjectReference{Kind: "StorageBucket", Name: "assets"},
	}
	return ing
}

func silentCronJob(ns, name, schedule string, suspend bool, lastSuccess, lastSchedule *metav1.Time) batchv1.CronJob {
	s := suspend
	return batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			CreationTimestamp: metav1.NewTime(rotNow.Add(-90 * 24 * time.Hour)),
		},
		Spec: batchv1.CronJobSpec{Schedule: schedule, Suspend: &s},
		Status: batchv1.CronJobStatus{
			LastSuccessfulTime: lastSuccess,
			LastScheduleTime:   lastSchedule,
		},
	}
}

// TestIngressBackend_PortIsARefinementOfTheSameClaim — the Phase 1 overlap census classified the
// "Ingress names a service PORT that is not defined" row as a REFINEMENT rather than a new rule: the
// subject is identical ("this backend does not resolve") and a second rule would put a second card on the
// same backend. These assert the branch behaves like a refinement and not like a rule.
func TestIngressBackend_PortIsARefinementOfTheSameClaim(t *testing.T) {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "api"},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
				{Name: "metrics", Port: 9090},
			},
		},
	}
	ing := func(name string, port networkingv1.ServiceBackendPort) networkingv1.Ingress {
		return networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name},
			Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
				Host: name + ".example",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						Path: "/",
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: "api", Port: port}},
					}},
				}},
			}}},
		}
	}
	base := func(ings ...networkingv1.Ingress) *collect.Inventory {
		return &collect.Inventory{
			Meta:      collect.Meta{Collected: []string{"ingresses", "services", "endpointslices"}},
			Services:  []corev1.Service{svc},
			Ingresses: ings,
			EndpointSlices: []discoveryv1.EndpointSlice{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-abc",
					Labels: map[string]string{discoveryv1.LabelServiceName: "api"}},
				// AddressType is load-bearing: publishedFor resolves an address FAMILY first and returns
				// zero ready addresses when it cannot, so a slice without one makes every backend look
				// unpublished and the test measures the fixture.
				AddressType: discoveryv1.AddressTypeIPv4,
				Endpoints: []discoveryv1.Endpoint{{
					Addresses:  []string{"10.0.0.1"},
					Conditions: discoveryv1.EndpointConditions{Ready: ptrBoolSF(true)},
				}},
			}},
		}
	}

	t.Run("a port the Service does not define is reported", func(t *testing.T) {
		got := (IngressBackendUnresolved{}).Evaluate(
			base(ing("wrong-port", networkingv1.ServiceBackendPort{Number: 8080})),
			Options{IncludeSystem: true})
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		blob := strings.Join(got[0].Evidence, "\n")
		if !strings.Contains(blob, "8080") || !strings.Contains(blob, "no such port") {
			t.Errorf("the evidence does not name the port or say what is wrong with it:\n%s", blob)
		}
		if !strings.Contains(blob, "80") || !strings.Contains(blob, "metrics") {
			t.Errorf("the evidence does not say what the Service DOES define, so the reader cannot fix "+
				"it without another lookup:\n%s", blob)
		}
	})

	t.Run("a port the Service does define is silent", func(t *testing.T) {
		for _, p := range []networkingv1.ServiceBackendPort{{Number: 80}, {Name: "metrics"}} {
			if got := (IngressBackendUnresolved{}).Evaluate(base(ing("ok", p)),
				Options{IncludeSystem: true}); len(got) != 0 {
				t.Errorf("port %+v resolves and was still reported: %s", p, got[0].Title)
			}
		}
	})

	t.Run("a backend naming NO port is not judged", func(t *testing.T) {
		// Legal, and common: the controller resolves it to the Service's single port. A rule reading an
		// unset port as "port 0, undefined" would fire on every Ingress written that way.
		if got := (IngressBackendUnresolved{}).Evaluate(
			base(ing("no-port", networkingv1.ServiceBackendPort{})),
			Options{IncludeSystem: true}); len(got) != 0 {
			t.Errorf("a backend declaring no port was judged: %s", got[0].Title)
		}
	})

	t.Run("ONE card, not two, when the Service is missing entirely", func(t *testing.T) {
		// The refinement must not double-report: a backend whose Service does not exist is already the
		// rule's main claim, and the port branch must never add a second line about the same backend.
		inv := base(ing("gone", networkingv1.ServiceBackendPort{Number: 8080}))
		inv.Services = nil
		got := (IngressBackendUnresolved{}).Evaluate(inv, Options{IncludeSystem: true})
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		blob := strings.Join(got[0].Evidence, "\n")
		if strings.Count(blob, "gone.example") > 1 {
			t.Errorf("the same backend is reported twice — the refinement became a second claim:\n%s", blob)
		}
	})
}

func ptrBoolSF(b bool) *bool { return &b }
