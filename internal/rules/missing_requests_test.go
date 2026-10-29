package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// mrDeploy builds a 1-container Deployment. Pass empty strings to omit a
// request or limit value; the resulting ResourceList is left nil when both of
// its entries are empty so we can model "no requests block at all".
func mrDeploy(ns, name, cname, reqCPU, reqMem, limCPU, limMem string) appsv1.Deployment {
	mk := func(cpu, mem string) corev1.ResourceList {
		rl := corev1.ResourceList{}
		if cpu != "" {
			rl[corev1.ResourceCPU] = resource.MustParse(cpu)
		}
		if mem != "" {
			rl[corev1.ResourceMemory] = resource.MustParse(mem)
		}
		if len(rl) == 0 {
			return nil
		}
		return rl
	}
	one := int32(1)
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name:  cname,
					Image: "img",
					Resources: corev1.ResourceRequirements{
						Requests: mk(reqCPU, reqMem),
						Limits:   mk(limCPU, limMem),
					},
				}}},
			},
		},
	}
}

// TestMissingRequests_FlagsGenuinelyRequestless is the headline assertion: a
// container with NO requests, NO limits, and NO namespace LimitRange default is
// flagged — at confidence 0.9 (not 1.0), medium severity, with a NON-applyable
// placeholder remediation when no usage is available.
func TestMissingRequests_FlagsGenuinelyRequestless(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mrDeploy("shop", "api", "api", "", "", "", "")},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Severity != "medium" {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if f.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9 (honest: detection is a spec fact but eviction order depends on peers)", f.Confidence)
	}
	if !strings.Contains(f.RemediationYAML, "PLACEHOLDER") || !strings.Contains(f.RemediationYAML, "DO NOT apply blind") {
		t.Errorf("no-usage remediation must carry a blocking placeholder comment, got:\n%s", f.RemediationYAML)
	}
	if len(f.Evidence) != 1 {
		t.Fatalf("want 1 evidence line, got %d", len(f.Evidence))
	}
	if !strings.Contains(f.Evidence[0], "cpu/memory") {
		t.Errorf("evidence should name both missing resources, got %q", f.Evidence[0])
	}
}

// TestMissingRequests_LimitsOnlyNotFlagged locks the limits->requests defaulting
// path: a container with limits but no requests is fully scheduled (apiserver
// copies limits into requests), so it must NOT be flagged. This is the HIGH
// false-positive from the honesty audit.
func TestMissingRequests_LimitsOnlyNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mrDeploy("shop", "api", "api", "", "", "500m", "512Mi")},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 0 {
		t.Fatalf("limits-only container must not be flagged (limits default to requests), got %d findings: %+v", len(fs), fs)
	}
}

// TestMissingRequests_PartialLimitStillFlagsOtherResource: a container with a
// CPU limit but nothing for memory is flagged ONLY for memory.
func TestMissingRequests_PartialLimitStillFlagsOtherResource(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mrDeploy("shop", "api", "api", "", "", "500m", "")},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	ev := fs[0].Evidence[0]
	if !strings.Contains(ev, "no memory") {
		t.Errorf("evidence should flag memory only, got %q", ev)
	}
	if strings.Contains(ev, "cpu/memory") || strings.Contains(ev, "no cpu") {
		t.Errorf("CPU has a limit and must not be flagged, got %q", ev)
	}
}

// TestMissingRequests_LimitRangeDefaultNotFlagged locks the LimitRange
// defaultRequest path: a request-less container in a namespace whose
// Container-type LimitRange supplies defaultRequest for cpu AND memory is
// effectively governed, so it must NOT be flagged. HIGH false-positive.
func TestMissingRequests_LimitRangeDefaultNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mrDeploy("gov", "api", "api", "", "", "", "")},
		LimitRanges: []corev1.LimitRange{{
			ObjectMeta: metav1.ObjectMeta{Name: "defaults", Namespace: "gov"},
			Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
				Type: corev1.LimitTypeContainer,
				DefaultRequest: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			}}},
		}},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 0 {
		t.Fatalf("LimitRange-governed container must not be flagged, got %d: %+v", len(fs), fs)
	}
}

// TestMissingRequests_LimitRangePartialDefault: LimitRange supplies only a CPU
// default; memory is still genuinely missing and must be flagged (memory only).
func TestMissingRequests_LimitRangePartialDefault(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mrDeploy("gov", "api", "api", "", "", "", "")},
		LimitRanges: []corev1.LimitRange{{
			ObjectMeta: metav1.ObjectMeta{Name: "defaults", Namespace: "gov"},
			Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
				Type:           corev1.LimitTypeContainer,
				DefaultRequest: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
			}}},
		}},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (memory uncovered), got %d", len(fs))
	}
	ev := fs[0].Evidence[0]
	if !strings.Contains(ev, "no memory") || strings.Contains(ev, "no cpu") {
		t.Errorf("only memory should be flagged (CPU has a LimitRange default), got %q", ev)
	}
}

// TestMissingRequests_NonContainerLimitRangeIgnored: a Pod-type LimitRange does
// NOT inject per-container defaultRequest, so it must not suppress the finding.
func TestMissingRequests_NonContainerLimitRangeIgnored(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mrDeploy("gov", "api", "api", "", "", "", "")},
		LimitRanges: []corev1.LimitRange{{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-defaults", Namespace: "gov"},
			Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
				Type: corev1.LimitTypePod,
				DefaultRequest: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			}}},
		}},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("Pod-type LimitRange must not suppress the finding, got %d", len(fs))
	}
}

// TestMissingRequests_UsageSeededPatchSizesMemoryToMax verifies the dangerous-
// remediation fix: with usage present, memory is sized to observed 7d MAX (+5%),
// never p95, so applying the patch can't OOM a bursty workload. CPU uses p95.
func TestMissingRequests_UsageSeededPatchSizesMemoryToMax(t *testing.T) {
	const podName = "api-aaa"
	ctrl := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: "shop",
			Labels:    map[string]string{"app": "api"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "api-7d4f8b9c5d", Controller: &ctrl},
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "api", Image: "img"}}},
	}
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mrDeploy("shop", "api", "api", "", "", "", "")},
		Pods:        []corev1.Pod{pod},
	}
	// p95 mem 300Mi but MAX 480Mi (GC/cache spikes). Memory must size to 480*1.05.
	usage := map[string]prom.ContainerUsage{
		"shop/" + podName + "/api": {
			Namespace: "shop", Pod: podName, Container: "api",
			CPUCoresP95: 0.25,
			MemBytesP95: 300 * 1024 * 1024,
			MemBytesMax: 480 * 1024 * 1024,
		},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{Usage: usage})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	y := fs[0].RemediationYAML
	if strings.Contains(y, "PLACEHOLDER") {
		t.Errorf("with usage present the patch must be measured, not a placeholder:\n%s", y)
	}
	// 480Mi * 1.05 = 504Mi (ceil). Must NOT be the p95-derived 315Mi.
	if !strings.Contains(y, "memory: 504Mi") {
		t.Errorf("memory must size to 7d MAX +5%% (504Mi), got:\n%s", y)
	}
	if strings.Contains(y, "memory: 315Mi") || strings.Contains(y, "memory: 300Mi") {
		t.Errorf("memory must NOT be sized from p95 (OOM risk):\n%s", y)
	}
	// CPU p95 0.25 cores -> 251m.
	if !strings.Contains(y, "cpu: 251m") {
		t.Errorf("cpu should be p95-derived 251m, got:\n%s", y)
	}
	if !strings.Contains(y, "validate against your workload") {
		t.Errorf("measured patch must still carry a validate-before-apply caveat:\n%s", y)
	}
}

// A NATIVE SIDECAR THAT REQUESTS NOTHING IS THE SAME PROBLEM, AND THE BOUNDARY IS THE RESTART POLICY.
//
// KEP-753 made an initContainer with restartPolicy: Always run for the pod's whole life, so the scheduler
// reserves its request for the pod's whole life and the kubelet ranks the pod for eviction using it. A
// request-less one is exactly what this rule exists to find, and it was invisible here — the same blind spot
// as B-102 in node_headroom's arithmetic, one file over.
//
// A PLAIN init container must still be ignored. It runs once, before the app containers, and its request is
// not part of the steady-state footprint; flagging it would be the mirror-image error.
func TestMissingRequests_NativeSidecarIsAssessedAndPlainInitIsNot(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	withInit := func(d *appsv1.Deployment, name string, policy *corev1.ContainerRestartPolicy) {
		d.Spec.Template.Spec.InitContainers = append(d.Spec.Template.Spec.InitContainers, corev1.Container{
			Name:          name,
			Image:         "img",
			RestartPolicy: policy,
			// No requests and no limits at all.
		})
	}

	t.Run("a request-less native sidecar is flagged and named as one", func(t *testing.T) {
		// The app container is fully specified, so the ONLY thing that can produce a finding is the sidecar.
		d := mrDeploy("mesh", "api", "api", "100m", "128Mi", "100m", "128Mi")
		withInit(&d, "istio-proxy", &always)
		fs := MissingRequests{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
		if len(fs) != 1 {
			t.Fatalf("a native sidecar requesting nothing produced %d finding(s); the app container is fully "+
				"specified, so this is the sidecar or nothing", len(fs))
		}
		joined := strings.Join(fs[0].Evidence, " ") + " " + fs[0].Description
		if !strings.Contains(joined, "istio-proxy") {
			t.Errorf("the finding does not name the container it is about: %v", fs[0].Evidence)
		}
		// A reader has to be able to tell why an initContainer is being judged at all.
		if !strings.Contains(strings.ToLower(joined), "sidecar") {
			t.Errorf("the sidecar is named but not identified as one, so a reader sees an initContainer "+
				"flagged with no explanation: %v", fs[0].Evidence)
		}
	})

	t.Run("a plain init container is not", func(t *testing.T) {
		d := mrDeploy("mesh", "api", "api", "100m", "128Mi", "100m", "128Mi")
		withInit(&d, "wait-for-db", nil)
		fs := (MissingRequests{}).Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
		if len(fs) != 0 {
			t.Errorf("a plain init container was flagged; it runs once and its request is not part of the "+
				"steady-state footprint:\n  %v", fs[0].Evidence)
		}
	})

	t.Run("a namespace LimitRange default covers a sidecar too", func(t *testing.T) {
		// A Container-type LimitRange applies to init containers as well, so the existing defaulting logic
		// must carry over rather than being bypassed for the new code path.
		d := mrDeploy("mesh", "api", "api", "100m", "128Mi", "100m", "128Mi")
		withInit(&d, "istio-proxy", &always)
		inv := &collect.Inventory{
			Deployments: []appsv1.Deployment{d},
			LimitRanges: []corev1.LimitRange{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "mesh", Name: "defaults"},
				Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
					Type: corev1.LimitTypeContainer,
					DefaultRequest: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				}}},
			}},
		}
		fs := (MissingRequests{}).Evaluate(inv, Options{})
		if len(fs) != 0 {
			t.Errorf("a sidecar covered by a LimitRange defaultRequest was flagged; admission injects the "+
				"request, so it is not request-less:\n  %v", fs[0].Evidence)
		}
	})
}

// TestMissingRequests_UncappedBranchIsARefinementAndNotASecondRule — the measurement that chose this shape,
// asserted so a later refactor cannot quietly turn it into a rule.
//
// On the reference cluster, of 225 non-system containers: 55 declare neither a request nor a limit, and 4
// declare a request but no limit. A separate "no limits" rule would have put a second card on 46 workloads
// to state 4 genuinely new things. So the branch rides on a finding that already exists and NEVER creates
// one.
func TestMissingRequests_UncappedBranchIsARefinementAndNotASecondRule(t *testing.T) {
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	mk := func(name string, cs ...corev1.Container) appsv1.Deployment {
		one := int32(1)
		return appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name},
			Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: cs}}},
		}
	}
	requested := corev1.Container{Name: "capped", Image: "a:1", Resources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: q("100m"), corev1.ResourceMemory: q("128Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: q("200m"), corev1.ResourceMemory: q("256Mi")}}}
	uncapped := corev1.Container{Name: "uncapped", Image: "a:1", Resources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: q("100m"), corev1.ResourceMemory: q("128Mi")}}}
	bare := corev1.Container{Name: "bare", Image: "a:1"}

	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets", "limitranges"}},
		Deployments: []appsv1.Deployment{
			mk("fully-declared", requested),
			mk("uncapped-only", uncapped),
			mk("mixed", bare, uncapped),
			// THE SAME PAIR IN THE OPPOSITE ORDER. badContainers is filled as the container loop runs, so
			// a branch testing it mid-loop drops the note whenever the uncapped container comes first —
			// which the first version did, and which the fixture above cannot catch because it happens to
			// list them the lucky way round.
			mk("mixed-reversed", uncapped, bare),
		},
	}
	got := (MissingRequests{}).Evaluate(inv, Options{IncludeSystem: true})

	byName := map[string]types.Finding{}
	for _, f := range got {
		for _, r := range f.AffectedResources {
			byName[r.Name] = f
		}
	}
	if _, ok := byName["fully-declared"]; ok {
		t.Error("a fully declared workload was reported")
	}
	// THE LOAD-BEARING ASSERTION: requested-but-uncapped alone creates NO finding. If it ever does, the
	// branch has become the second rule the measurement rejected, and 46 workloads on the reference
	// cluster get a duplicate card.
	if _, ok := byName["uncapped-only"]; ok {
		t.Error("a workload whose containers are all requested-but-uncapped produced a finding — the " +
			"refinement has become a second rule, which is exactly what the measurement rejected")
	}
	f, ok := byName["mixed"]
	if !ok {
		t.Fatal("the workload with an unrequested container produced no finding at all")
	}
	blob := strings.Join(f.Evidence, "\n")
	if !strings.Contains(blob, "uncapped") || !strings.Contains(blob, "never capped") {
		t.Errorf("the uncapped container is not named on a finding that already exists:\n%s", blob)
	}
	if !strings.Contains(blob, "bare") {
		t.Errorf("the branch displaced the rule's own claim:\n%s", blob)
	}

	rev, ok := byName["mixed-reversed"]
	if !ok {
		t.Fatal("the reversed workload produced no finding at all")
	}
	revBlob := strings.Join(rev.Evidence, "\n")
	if !strings.Contains(revBlob, "never capped") {
		t.Errorf("container ORDER decided whether the uncapped note survived — the branch reads state "+
			"that the loop is still filling:\n%s", revBlob)
	}
}
