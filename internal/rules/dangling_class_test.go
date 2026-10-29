package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// dangling_class_test.go — Phase 1's reference-integrity rules.
//
// THE ADVERSARIAL CASE IS THE SAME ONE FOUR TIMES, AND IT IS THE COMMON CASE: an UNSET class name is not a
// missing one. An unset storageClassName means "the default class", an unset ingressClassName means "the
// default controller", an unset priorityClassName means zero priority, and an unset serviceName means no
// stable DNS. All four are ordinary, and a rule reading any of them as a name would fire on most objects on
// most clusters — which is B-133's standard: reading a field correctly and reporting something false.

var bannedClassPhrases = []string{
	"will not bind", "cannot bind", "will not be provisioned", "is not routed", "no traffic",
	"will be evicted", "will not schedule", "cannot schedule", "is broken", "is down",
	"guaranteed", "certainly", "must have been",
}

func TestDanglingClass_ClaimsTheReferenceAndNotItsConsequence(t *testing.T) {
	out := allClassFindings(danglingClassFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters, f.RemediationYAML, f.RemediationCommand,
		}, f.Evidence...), "\n"))
		for _, p := range bannedClassPhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — a name that resolves to nothing is the claim, and what it "+
					"produces at runtime is not in the snapshot:\n%s", f.ID, p, blob)
			}
		}
	}
}

func TestDanglingClass_NeverCarriesDollars(t *testing.T) {
	for _, f := range allClassFindings(danglingClassFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f", f.ID, f.DollarImpactMonthly)
		}
	}
}

// THE DENIAL GUARD IS WHOLE-RULE HERE, unlike stuck_status.go, and the difference is the claim's shape:
// every rule in this file asserts "X names Y and Y is not in the list", so a denied TARGET list fabricates
// the absence and the rule must say nothing at all. That is dangling.go's property, and these belong to
// dangling.go's family.
func TestDanglingClass_ADeniedListIsSilence(t *testing.T) {
	rules := []struct {
		name string
		eval func(*collect.Inventory) []types.Finding
		deps []string
	}{
		{"DanglingStorageClass", func(i *collect.Inventory) []types.Finding {
			return (DanglingStorageClass{}).Evaluate(i, Options{IncludeSystem: true})
		}, (DanglingStorageClass{}).RequiredKinds()},
		{"DanglingIngressClass", func(i *collect.Inventory) []types.Finding {
			return (DanglingIngressClass{}).Evaluate(i, Options{IncludeSystem: true})
		}, (DanglingIngressClass{}).RequiredKinds()},
		{"DanglingPriorityClass", func(i *collect.Inventory) []types.Finding {
			return (DanglingPriorityClass{}).Evaluate(i, Options{IncludeSystem: true})
		}, (DanglingPriorityClass{}).RequiredKinds()},
		{"DanglingGoverningService", func(i *collect.Inventory) []types.Finding {
			return (DanglingGoverningService{}).Evaluate(i, Options{IncludeSystem: true})
		}, (DanglingGoverningService{}).RequiredKinds()},
	}
	for _, r := range rules {
		if got := r.eval(danglingClassFixture()); len(got) == 0 {
			t.Fatalf("%s is silent on the fixture that plants its positive, so denying a list below "+
				"would prove nothing", r.name)
		}
		for _, kind := range r.deps {
			inv := danglingClassFixture()
			inv.Meta.Collected = withoutKind(inv.Meta.Collected, kind)
			inv.Meta.Denied = append(inv.Meta.Denied, kind+": forbidden")
			if got := r.eval(inv); len(got) != 0 {
				t.Errorf("%s spoke with %s denied — %d finding(s) about a list it did not read",
					r.name, kind, len(got))
			}
		}
	}
}

// THE FOUR WAYS THIS FAMILY WOULD BE WRONG, and they are the same shape four times.
func TestDanglingClass_AnUnsetNameIsNotAMissingOne(t *testing.T) {
	inv := healthyClassFixture()

	// storageClassName unset -> the default class. Empty string -> no class at all, bind statically.
	empty := ""
	inv.PVCs = append(inv.PVCs,
		corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "default-class"}},
		corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "static-bind"},
			Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &empty}})
	assertSilent(t, (DanglingStorageClass{}).Evaluate(inv, Options{IncludeSystem: true}))

	// ingressClassName unset -> the default controller.
	inv.Ingresses = append(inv.Ingresses,
		networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "default-controller"}})
	assertSilent(t, (DanglingIngressClass{}).Evaluate(inv, Options{IncludeSystem: true}))

	// priorityClassName unset -> zero priority, which is nearly every workload in existence.
	inv.Deployments = append(inv.Deployments, appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "ordinary"},
		Spec: appsv1.DeploymentSpec{Replicas: ptr32(1), Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "app:1"}}}}},
	})
	assertSilent(t, (DanglingPriorityClass{}).Evaluate(inv, Options{IncludeSystem: true}))

	// serviceName unset -> no stable DNS, which is legal and a different claim.
	inv.StatefulSets = append(inv.StatefulSets, appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "no-governing-service"},
		Spec: appsv1.StatefulSetSpec{Replicas: ptr32(1), Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "db:1"}}}}},
	})
	assertSilent(t, (DanglingGoverningService{}).Evaluate(inv, Options{IncludeSystem: true}))
}

// The governing-Service lookup is NAMESPACED. A Service of the same name in another namespace does not
// resolve it, and treating the name as cluster-wide would silence a real dangling reference on any cluster
// where two namespaces run the same chart.
func TestDanglingGoverningService_ResolvesWithinTheNamespace(t *testing.T) {
	// The Service exists — in ANOTHER namespace. The name in the healthy fixture is deliberately not
	// reused: a fixture that already resolves the reference would make this test pass without the rule
	// doing anything, which is how a scoping test measures its fixture instead of its subject.
	inv := healthyClassFixture()
	inv.Services = append(inv.Services, corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "queue-headless"}})
	inv.StatefulSets = append(inv.StatefulSets, appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "queue"},
		Spec: appsv1.StatefulSetSpec{ServiceName: "queue-headless", Replicas: ptr32(3),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c", Image: "q:1"}}}}},
	})
	if got := (DanglingGoverningService{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 1 {
		t.Errorf("a Service of the same name in another namespace resolved a namespaced reference; "+
			"got %d findings, want 1", len(got))
	}
}

func TestDanglingClass_EachRuleFiresOnItsPlantedPositive(t *testing.T) {
	inv := danglingClassFixture()
	for _, c := range []struct {
		name string
		got  []types.Finding
	}{
		{"DanglingStorageClass", (DanglingStorageClass{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"DanglingIngressClass", (DanglingIngressClass{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"DanglingPriorityClass", (DanglingPriorityClass{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"DanglingGoverningService", (DanglingGoverningService{}).Evaluate(inv, Options{IncludeSystem: true})},
	} {
		if len(c.got) == 0 {
			t.Errorf("%s found nothing on a fixture built to make it fire", c.name)
		}
	}
}

func TestDanglingClass_AConsistentClusterProducesNothing(t *testing.T) {
	for _, f := range allClassFindings(healthyClassFixture()) {
		t.Errorf("a cluster whose names all resolve produced %s: %s", f.RuleID, f.Title)
	}
}

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

func classKinds() []string {
	return []string{"persistentvolumeclaims", "storageclasses", "ingresses", "ingressclasses",
		"priorityclasses", "deployments", "statefulsets", "daemonsets", "services"}
}

func healthyClassFixture() *collect.Inventory {
	sc := "fast-ssd"
	ic := "nginx"
	return &collect.Inventory{
		Meta:            collect.Meta{Collected: classKinds(), StartedAt: fixedReading},
		StorageClasses:  []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "fast-ssd"}}},
		IngressClasses:  []networkingv1.IngressClass{{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}}},
		PriorityClasses: []schedulingv1.PriorityClass{{ObjectMeta: metav1.ObjectMeta{Name: "high"}, Value: 1000}},
		Services:        []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "db-headless"}}},
		PVCs: []corev1.PersistentVolumeClaim{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "data"},
			Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &sc},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		}},
		Ingresses: []networkingv1.Ingress{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web"},
			Spec:       networkingv1.IngressSpec{IngressClassName: &ic},
		}},
		StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "db"},
			Spec: appsv1.StatefulSetSpec{ServiceName: "db-headless", Replicas: ptr32(3),
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					PriorityClassName: "high",
					Containers:        []corev1.Container{{Name: "c", Image: "db:1"}}}}},
		}},
	}
}

func danglingClassFixture() *collect.Inventory {
	inv := healthyClassFixture()
	gone := "retired-ssd"
	goneIC := "traefik-v1"
	inv.PVCs = append(inv.PVCs, corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "legacy-data"},
		Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &gone},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	})
	inv.Ingresses = append(inv.Ingresses, networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "legacy-web"},
		Spec:       networkingv1.IngressSpec{IngressClassName: &goneIC},
	})
	inv.Deployments = append(inv.Deployments, appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "batch"},
		Spec: appsv1.DeploymentSpec{Replicas: ptr32(2), Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{PriorityClassName: "gone-tier",
				Containers: []corev1.Container{{Name: "c", Image: "batch:1"}}}}},
	})
	inv.StatefulSets = append(inv.StatefulSets, appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "cache"},
		Spec: appsv1.StatefulSetSpec{ServiceName: "cache-headless", Replicas: ptr32(3),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c", Image: "cache:1"}}}}},
	})
	return inv
}

func allClassFindings(inv *collect.Inventory) []types.Finding {
	o := Options{IncludeSystem: true}
	var out []types.Finding
	out = append(out, (DanglingStorageClass{}).Evaluate(inv, o)...)
	out = append(out, (DanglingIngressClass{}).Evaluate(inv, o)...)
	out = append(out, (DanglingPriorityClass{}).Evaluate(inv, o)...)
	out = append(out, (DanglingGoverningService{}).Evaluate(inv, o)...)
	return out
}
