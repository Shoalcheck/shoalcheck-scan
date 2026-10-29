package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// declaration_validity_test.go — three rules whose whole claim lives inside one object's spec.
//
// EVERY ADVERSARIAL CASE HERE IS "THE FIELD IS OPTIONAL". containerPort is documentation rather than a
// binding, targetPort defaults to the service port, and a numeric targetPort need not be declared anywhere.
// A rule reading any of those as a reference that must resolve fires on most objects in the world — which
// is B-133's standard, and it is the same trap the class rules had in a different costume.

var bannedValidityPhrases = []string{
	"probe fails", "probe will fail", "cannot connect", "no traffic", "is unreachable",
	"restarts", "crashloop", "will be restarted", "is broken", "is down",
	"guaranteed", "certainly", "obviously",
}

func TestDeclarationValidity_ClaimsTheContradictionAndNotItsEffect(t *testing.T) {
	out := allValidityFindings(validityFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters,
		}, f.Evidence...), "\n"))
		for _, p := range bannedValidityPhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — the spec disagreeing with itself is the claim, and what "+
					"that produces at runtime is not in the snapshot:\n%s", f.ID, p, blob)
			}
		}
	}
}

func TestDeclarationValidity_TheOptionalFieldTraps(t *testing.T) {
	one := int32(1)
	mk := func(name string, c corev1.Container) appsv1.Deployment {
		return appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name},
			Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{c}}}},
		}
	}
	base := func(ds ...appsv1.Deployment) *collect.Inventory {
		return &collect.Inventory{
			Meta:        collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets", "services"}},
			Deployments: ds,
		}
	}

	t.Run("a container declaring NO ports is not judged", func(t *testing.T) {
		// containerPort is optional and widely skipped. An empty list means "not documented", never
		// "port absent" — and a rule reading it the other way fires on most containers in existence.
		inv := base(mk("undocumented", corev1.Container{
			Name: "c", Image: "a:1",
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: "/h", Port: intstr.FromInt32(8080)}}},
		}))
		assertSilent(t, (ProbePortNotDeclared{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("an exec probe names no port, so nothing can disagree", func(t *testing.T) {
		inv := base(mk("exec-probe", corev1.Container{
			Name: "c", Image: "a:1",
			Ports: []corev1.ContainerPort{{ContainerPort: 9000}},
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{Command: []string{"/bin/true"}}}},
		}))
		assertSilent(t, (ProbePortNotDeclared{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a probe naming a declared port, by name or number, is silent", func(t *testing.T) {
		for _, port := range []intstr.IntOrString{intstr.FromInt32(9000), intstr.FromString("http")} {
			inv := base(mk("ok", corev1.Container{
				Name: "c", Image: "a:1",
				Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 9000}},
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{Port: port}}},
			}))
			assertSilent(t, (ProbePortNotDeclared{}).Evaluate(inv, Options{IncludeSystem: true}))
		}
	})

	t.Run("a NUMERIC targetPort is not a reference and is not judged", func(t *testing.T) {
		// It is a real port number the process may listen on without declaring. Only the NAMED form must
		// resolve against a containerPort name.
		inv := base(mk("api", corev1.Container{Name: "c", Image: "a:1",
			Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}))
		inv.Services = []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "svc"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"},
				Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(9999)}}},
		}}
		assertSilent(t, (ServiceTargetPortUndeclared{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a Service selecting NO workload is another rule's claim", func(t *testing.T) {
		inv := base(mk("api", corev1.Container{Name: "c", Image: "a:1"}))
		inv.Services = []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "orphan"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "nothing-here"},
				Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("http")}}},
		}}
		assertSilent(t, (ServiceTargetPortUndeclared{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("one env var declared once is not a duplicate", func(t *testing.T) {
		inv := base(mk("fine", corev1.Container{Name: "c", Image: "a:1",
			Env: []corev1.EnvVar{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}}}))
		assertSilent(t, (DuplicateEnvVar{}).Evaluate(inv, Options{IncludeSystem: true}))
	})
}

// An env var's VALUE is customer data — a connection string, a token. The name is what the finding is
// about, and quoting the value would put customer data in a report that leaves the trust boundary.
func TestDuplicateEnvVar_NeverQuotesTheValue(t *testing.T) {
	one := int32(1)
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets"}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "dup"},
			Spec: appsv1.DeploymentSpec{
				Replicas: &one,
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name: "c", Image: "a:1",
							Env: []corev1.EnvVar{
								{Name: "DATABASE_URL", Value: "postgres://user:hunter2@db/prod"},
								{Name: "DATABASE_URL", Value: "postgres://user:hunter2@db/staging"},
							},
						}},
					},
				},
			},
		}},
	}
	got := (DuplicateEnvVar{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	blob := strings.Join(append([]string{got[0].Description}, got[0].Evidence...), "\n")
	if strings.Contains(blob, "hunter2") || strings.Contains(blob, "postgres://") {
		t.Errorf("the finding quotes an env VALUE, which is customer data:\n%s", blob)
	}
	if !strings.Contains(blob, "DATABASE_URL") {
		t.Errorf("the finding does not name the variable, so it cannot be found:\n%s", blob)
	}
}

func TestDeclarationValidity_EachRuleFiresOnItsPlantedPositive(t *testing.T) {
	inv := validityFixture()
	for _, c := range []struct {
		name string
		got  []types.Finding
	}{
		{"ProbePortNotDeclared", (ProbePortNotDeclared{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"DuplicateEnvVar", (DuplicateEnvVar{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"ServiceTargetPortUndeclared", (ServiceTargetPortUndeclared{}).Evaluate(inv, Options{IncludeSystem: true})},
	} {
		if len(c.got) == 0 {
			t.Errorf("%s found nothing on a fixture built to make it fire", c.name)
		}
	}
}

func TestDeclarationValidity_AConsistentClusterProducesNothing(t *testing.T) {
	for _, f := range allValidityFindings(healthyValidityFixture()) {
		t.Errorf("a self-consistent cluster produced %s: %s", f.RuleID, f.Title)
	}
}

func TestDeclarationValidity_NeverCarryDollars(t *testing.T) {
	for _, f := range allValidityFindings(validityFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f", f.ID, f.DollarImpactMonthly)
		}
	}
}

func healthyValidityFixture() *collect.Inventory {
	one := int32(1)
	return &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets", "services"}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api"},
			Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "c", Image: "a:1",
					Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
					Env:   []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "info"}},
					LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{Path: "/h", Port: intstr.FromString("http")}}},
				}}}}},
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"},
				Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("http")}}},
		}},
	}
}

func validityFixture() *collect.Inventory {
	inv := healthyValidityFixture()
	one := int32(1)
	inv.Deployments = append(inv.Deployments, appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "renamed"},
		Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "renamed"}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "c", Image: "a:1",
				// The port was renamed from "http" to "web" and the probe was not updated.
				Ports: []corev1.ContainerPort{{Name: "web", ContainerPort: 8080}},
				Env: []corev1.EnvVar{
					{Name: "REGION", Value: "eu"},
					{Name: "REGION", Value: "us"},
				},
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{Path: "/r", Port: intstr.FromString("http")}}},
			}}}}},
	})
	inv.Services = append(inv.Services, corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "renamed"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "renamed"},
			Ports: []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromString("http")}}},
	})
	return inv
}

func allValidityFindings(inv *collect.Inventory) []types.Finding {
	o := Options{IncludeSystem: true}
	var out []types.Finding
	out = append(out, (ProbePortNotDeclared{}).Evaluate(inv, o)...)
	out = append(out, (DuplicateEnvVar{}).Evaluate(inv, o)...)
	out = append(out, (ServiceTargetPortUndeclared{}).Evaluate(inv, o)...)
	return out
}
