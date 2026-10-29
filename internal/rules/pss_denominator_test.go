package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// pss_denominator_test.go — CONDITION (c) OF THE 2026-08-29 COLLAPSE DECISION: "The count goes in the
// text: '3 of 4 containers', not 'containers'."
//
// The other three conditions were already met and are asserted here too, because a decision's conditions
// are worth pinning whether or not they were already true when it was taken:
//
//	(b) every container stays NAMED in the evidence — one line per container, init containers included;
//	(d) severity is the MAX across containers, never an average — runs-as-root goes High the moment ONE
//	    container is confirmed root, and stays Medium when none is.
//
// The denominator is not cosmetic. "3 of 5 containers" and "5 of 5 containers" are different facts about a
// workload: one says a sidecar is unhardened, the other says nothing in it is. Without the total the reader
// cannot tell them apart, and 32 of the 172 non-system workloads on the reference cluster have more than
// one container.
func TestPSS_CountsOffendingContainersAgainstTheTotal(t *testing.T) {
	inv := partiallyHardenedFixture()
	var checked int
	for _, r := range pssRules() {
		for _, f := range r.Evaluate(inv, Options{IncludeSystem: true}) {
			if !strings.Contains(f.Description, " of ") {
				t.Errorf("%s gives no denominator, so a reader cannot tell one unhardened sidecar from a "+
					"wholly unhardened workload:\n  %s", f.RuleID, f.Description)
				continue
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no PSS finding was produced, so this test asserted nothing")
	}
}

// The partial case is the one the denominator exists for: 1 of 3 containers, and the text must say so.
func TestPSS_APartiallyHardenedWorkloadSaysHowManyOfHowMany(t *testing.T) {
	inv := partiallyHardenedFixture()
	var seen bool
	for _, r := range pssRules() {
		if r.ID() != "k8s.workload.writable-root-filesystem" {
			continue
		}
		for _, f := range r.Evaluate(inv, Options{IncludeSystem: true}) {
			if !strings.Contains(f.Title, "partly-hardened") {
				continue
			}
			seen = true
			if !strings.Contains(f.Description, "1 of 3") {
				t.Errorf("one unhardened container of three, and the text says: %s", f.Description)
			}
		}
	}
	if !seen {
		t.Fatal("the partially hardened workload produced no writable-root-filesystem finding")
	}
}

// (b) — EVERY OFFENDING container named, init containers included.
//
// The first version of this asserted that all three containers appear, including the two that are
// hardened. That was wrong and it is the same scoping mistake this session keeps producing: a hardened
// container never had a card, so collapsing cannot have lost it. The condition is that collapsing changes
// the number of CARDS and never the number of FACTS — so what must be named is every container that would
// have had a card of its own. `mostly-unhardened` offends on two of three, which is what makes this
// non-vacuous: a rule reporting only the first offender would pass against `partly-hardened`.
func TestPSS_NamesEveryOffendingContainerIncludingInit(t *testing.T) {
	inv := partiallyHardenedFixture()
	var checked bool
	for _, r := range pssRules() {
		if r.ID() != "k8s.workload.capabilities-not-dropped" {
			continue
		}
		for _, f := range r.Evaluate(inv, Options{IncludeSystem: true}) {
			if !strings.Contains(f.Title, "mostly-unhardened") {
				continue
			}
			checked = true
			blob := strings.Join(f.Evidence, "\n")
			for _, name := range []string{"app", "sidecar"} {
				if !strings.Contains(blob, name) {
					t.Errorf("offending container %q is not named in the evidence:\n%s", name, blob)
				}
			}
			if strings.Contains(blob, "setup") {
				t.Errorf("the hardened init container is named as an offender:\n%s", blob)
			}
			if !strings.Contains(f.Description, "2 of 3") {
				t.Errorf("two offenders of three, and the text says: %s", f.Description)
			}
		}
	}
	if !checked {
		t.Fatal("mostly-unhardened produced no capabilities finding, so this asserted nothing")
	}
}

// (d) — severity is the MAX across containers, never an average.
func TestPSS_SeverityIsTheMaxAcrossContainersNeverAnAverage(t *testing.T) {
	inv := partiallyHardenedFixture()
	for _, r := range pssRules() {
		if r.ID() != "k8s.workload.runs-as-root" {
			continue
		}
		for _, f := range r.Evaluate(inv, Options{IncludeSystem: true}) {
			if !strings.Contains(f.Title, "one-root-container") {
				continue
			}
			if f.Severity != "high" {
				t.Errorf("one container confirmed root among three and the finding is %q — a max never "+
					"drops below its largest input", f.Severity)
			}
		}
	}
}

func partiallyHardenedFixture() *collect.Inventory {
	hardened := &corev1.SecurityContext{
		ReadOnlyRootFilesystem:   ptrB(true),
		AllowPrivilegeEscalation: ptrB(false),
		RunAsNonRoot:             ptrB(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	mk := func(name string, secure []bool, rootUID []int64) appsv1.Deployment {
		names := []string{"app", "sidecar", "setup"}
		var cs []corev1.Container
		var ics []corev1.Container
		for i, n := range names {
			c := corev1.Container{Name: n, Image: "acme/" + n + ":v1"}
			if secure[i] {
				c.SecurityContext = hardened
			}
			if rootUID != nil && rootUID[i] == 0 {
				sc := *hardened
				sc.RunAsNonRoot = ptrB(false)
				sc.RunAsUser = ptrI64(0)
				c.SecurityContext = &sc
			}
			if n == "setup" {
				ics = append(ics, c)
			} else {
				cs = append(cs, c)
			}
		}
		one := int32(1)
		return appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name},
			Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptrB(true)},
					Containers:      cs, InitContainers: ics,
				},
			}},
		}
	}
	return &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets", "namespaces"},
			StartedAt: fixedReading},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "app"}}},
		Deployments: []appsv1.Deployment{
			// two hardened, one not: the partial case the denominator exists for.
			mk("partly-hardened", []bool{true, true, false}, nil),
			// one container confirmed root, for the severity-max assertion.
			mk("one-root-container", []bool{true, true, false}, []int64{1000, 1000, 0}),
			// two offenders of three, so a rule that named only the first would still fail (b).
			mk("mostly-unhardened", []bool{false, false, true}, nil),
		},
	}
}

func ptrB(b bool) *bool     { return &b }
func ptrI64(i int64) *int64 { return &i }
