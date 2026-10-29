package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// bannedFeasibilityPhrases — EVERY ONE ASSERTS A SCHEDULER VERDICT THIS MODEL CANNOT REACH.
//
// The model checks a SUBSET of the scheduler's predicates, which is why its NEGATIVE is sound: a model that
// checks less is more permissive, so "no node satisfies what we check" implies "no node satisfies everything
// the scheduler checks". The POSITIVE is unsound in the same breath and by the same argument, so no phrase may
// promise a placement.
//
// The first three are already in bannedDrainPhrases; the rest are this family's, from the spec's §6.
var bannedFeasibilityPhrases = []string{
	"will schedule", "will not schedule", "cannot be scheduled",
	"has a home", "will be placed", "will fit", "safe to remove", "can be removed",
	"guaranteed to", "is able to run", "would run fine", "no impact",
	// Optimality and cost are the refused half. A phrase that implies either is §4.2 returning under a
	// different name.
	"could be removed", "smaller cluster", "consolidat",
}

func TestFeasibilityRules_NeverAssertASchedulerVerdict(t *testing.T) {
	out := allFeasibilityFindings(t, zoneLossFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing — and this family's normal " +
			"output on a healthy cluster is silence, which makes a planted positive the only thing that " +
			"distinguishes correct from asleep")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters, f.RemediationYAML, f.RemediationCommand,
		}, f.Evidence...), "\n"))
		for _, phrase := range bannedFeasibilityPhrases {
			if strings.Contains(blob, phrase) {
				t.Errorf("finding %s says %q — this model checks a subset of the scheduler's predicates and "+
					"cannot support that:\n%s", f.ID, phrase, blob)
			}
		}
	}
}

// SPEC §7 test 2 — no positive placement, ever. Structural: no text asserts a pod has a home and no field
// carries a proposed assignment.
func TestFeasibility_NeverEmitsAPositivePlacement(t *testing.T) {
	out := allFeasibilityFindings(t, zoneLossFixture())
	if len(out) == 0 {
		t.Fatal("no findings, so the absence of a positive claim proves nothing")
	}
	negatives := 0
	for _, f := range out {
		if f.Confidence > 0 {
			negatives++
		}
		// A proposed assignment would have to travel somewhere. RemediationYAML is the field that could
		// carry one, and this family writes none: choosing where a pod should go is the unsound direction.
		if f.RemediationYAML != "" {
			t.Errorf("finding %s carries remediation YAML, which is where a proposed placement would hide:\n%s",
				f.ID, f.RemediationYAML)
		}
	}
	if negatives == 0 {
		t.Error("every finding is confidence 0, so the fixture produced only abstentions and the structural " +
			"assertion above is vacuous")
	}
}

// SPEC §7 test 3 — an unzoned cluster is not one zone.
//
// This is the precondition the spec calls a hard one rather than a caveat: a cluster whose nodes carry no zone
// label at all would otherwise read as ONE zone containing everything, and losing it as the whole cluster
// having nowhere to go. A spectacular false positive built on a label lookup.
func TestFeasibility_AnUnzonedClusterIsNotOneZone(t *testing.T) {
	inv := zoneLossFixture()
	for i := range inv.Nodes {
		inv.Nodes[i].Labels = map[string]string{"kubernetes.io/hostname": inv.Nodes[i].Name}
	}

	out := (ZoneLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true})
	for _, f := range out {
		if f.Confidence > 0 {
			t.Errorf("an unzoned cluster produced a zone-loss finding: %s", f.Title)
		}
	}
	// ZERO FINDINGS WITH A NAMED REASON, never zero findings in silence.
	if len(out) != 1 {
		t.Fatalf("%d finding(s) on an unzoned cluster, want exactly 1 abstention naming the reason", len(out))
	}
	ab := out[0]
	if ab.Confidence != 0 {
		t.Errorf("the abstention carries confidence %.2f, want 0 — it is a coverage gap, not a problem we are "+
			"certain of", ab.Confidence)
	}
	blob := ab.Title + " " + ab.Description + " " + strings.Join(ab.Evidence, " ")
	for _, want := range []string{"zone", "not assessed"} {
		if !strings.Contains(strings.ToLower(blob), want) {
			t.Errorf("the abstention does not say %q:\n%s", want, blob)
		}
	}

	// NON-VACUITY: the same fixture WITH zone labels must produce at least one real finding, or "no zone-loss
	// findings" is true because the rule never fires.
	if got := realFindings((ZoneLossFeasibility{}).Evaluate(zoneLossFixture(), Options{IncludeSystem: true})); len(got) == 0 {
		t.Error("the zoned fixture produced no zone-loss finding either, so the abstention proves nothing")
	}
}

// SPEC §7 test 4 — a denied node list is silence.
func TestFeasibility_ADeniedNodeListIsSilence(t *testing.T) {
	for _, denied := range []string{"nodes", "pods"} {
		inv := zoneLossFixture()
		var kept []string
		for _, c := range inv.Meta.Collected {
			if c != denied {
				kept = append(kept, c)
			}
		}
		inv.Meta.Collected = kept
		inv.Meta.Denied = []string{denied + ": forbidden"}

		if out := allFeasibilityFindings(t, inv); len(out) != 0 {
			t.Errorf("with %q denied the rules produced %d finding(s) — an absence from a denied read is not "+
				"an absence", denied, len(out))
		}
	}
	// NON-VACUITY: the confirmed-read fixture fires.
	if out := allFeasibilityFindings(t, zoneLossFixture()); len(out) == 0 {
		t.Error("the rules produce nothing even when every kind was collected")
	}
}

// SPEC §7 test 5 — ONE REQUEST WALKER, and the fixture is the B-102/B-103 boundary.
//
// There are already three divergent request walkers in this package and one of them says so in its header. A
// fourth would make the same pod cost different amounts depending on which rule asked.
//
// The fixture carries a NATIVE SIDECAR (an initContainer with restartPolicy: Always, which the scheduler
// reserves for the pod's whole life) and a CLASSIC init container (which runs to completion and releases). A
// walker that counts both, or neither, gives a different answer from podRequests — which is exactly the defect
// B-102 recorded.
func TestFeasibility_ReusesOneRequestWalker(t *testing.T) {
	p := podWithSidecars()
	wantCPU, wantMem := podRequests(p)
	gotCPU, gotMem := feasibilityRequests(p)

	if gotCPU.Cmp(wantCPU) != 0 {
		t.Errorf("cpu = %s, podRequests says %s — the engine walks a different set of containers",
			gotCPU.String(), wantCPU.String())
	}
	if gotMem.Cmp(wantMem) != 0 {
		t.Errorf("memory = %s, podRequests says %s", gotMem.String(), wantMem.String())
	}

	// NON-VACUITY: the fixture must make the two boundaries DIFFER, or any walker agrees. A native sidecar
	// counts and a classic init container does not, so a walker that summed plain containers alone, or every
	// initContainer, would land on a different number.
	plainOnly := resource.NewMilliQuantity(0, resource.DecimalSI)
	for i := range p.Spec.Containers {
		if q, ok := p.Spec.Containers[i].Resources.Requests[corev1.ResourceCPU]; ok {
			plainOnly.Add(q)
		}
	}
	if plainOnly.Cmp(wantCPU) == 0 {
		t.Fatal("the fixture's native sidecar contributes nothing, so this test cannot tell a correct walker " +
			"from one that ignores sidecars")
	}
	everyInit := plainOnly.DeepCopy()
	for i := range p.Spec.InitContainers {
		if q, ok := p.Spec.InitContainers[i].Resources.Requests[corev1.ResourceCPU]; ok {
			everyInit.Add(q)
		}
	}
	if everyInit.Cmp(wantCPU) == 0 {
		t.Fatal("the fixture's classic init container contributes nothing, so this test cannot tell a correct " +
			"walker from one that counts every initContainer")
	}
}

// SPEC §7 test 6 — a pod on a custom scheduler is excluded AND counted. Excluding silently is the defect.
func TestFeasibility_APodOnACustomSchedulerIsExcludedAndCounted(t *testing.T) {
	inv := zoneLossFixture()
	// The homeless pod moves to a custom scheduler. Its feasibility is not ours to model.
	for i := range inv.Pods {
		if inv.Pods[i].Name == "pinned-db-0" {
			inv.Pods[i].Spec.SchedulerName = "karpenter-scheduler"
		}
	}

	out := realFindings((ZoneLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true}))
	blob := ""
	for _, f := range out {
		blob += f.Title + "\n" + f.Description + "\n" + strings.Join(f.Evidence, "\n") + "\n"
	}
	if strings.Contains(blob, "pinned-db-0") {
		t.Error("a pod bound to a custom scheduler was assessed anyway")
	}
	// AND COUNTED. Silence about an exclusion is how a reader concludes the check covered everything.
	if !strings.Contains(strings.ToLower(blob), "custom scheduler") && !strings.Contains(blob, "schedulerName") {
		t.Errorf("the exclusion is not disclosed anywhere:\n%s", blob)
	}
}

// SPEC §7 test 7 — a zone-pinned volume makes a pod immobile, and the existing hostname path is untouched.
func TestFeasibility_ZonePinnedVolumeIsImmobile(t *testing.T) {
	inv := zoneLossFixture()
	out := realFindings((ZonePinnedVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	if len(out) == 0 {
		t.Fatal("a PV with a zone-level nodeAffinity produced no finding")
	}
	blob := ""
	for _, f := range out {
		blob += f.Title + "\n" + f.Description + "\n" + strings.Join(f.Evidence, "\n") + "\n"
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f", f.ID, f.DollarImpactMonthly)
		}
	}
	for _, want := range []string{"eu-central-1a", "pv-pinned-db"} {
		if !strings.Contains(blob, want) {
			t.Errorf("the finding does not name %q:\n%s", want, blob)
		}
	}
	// THE CLAIM IS WEAKER THAN A NODE PIN, AND MUST SAY SO: a zonal disk constrains where a pod may go
	// without naming where it is, so a drain inside the zone is unaffected.
	if !strings.Contains(strings.ToLower(blob), "within the zone") && !strings.Contains(strings.ToLower(blob), "inside the zone") {
		t.Errorf("the finding does not distinguish a zone pin from a node pin:\n%s", blob)
	}

	// NON-VACUITY: a HOSTNAME-pinned PV on a surviving node must produce nothing here, proving the new zone
	// path did not swallow the existing hostname logic.
	hostOnly := zoneLossFixture()
	for i := range hostOnly.PVs {
		hostOnly.PVs[i].Spec.NodeAffinity.Required.NodeSelectorTerms = []corev1.NodeSelectorTerm{{
			MatchExpressions: []corev1.NodeSelectorRequirement{{
				// node-a2, where pinned-db-0 actually runs: NodePinnedVolume fires only when the volume pins
				// to the node the pod is ON, so pinning to a node it is not on would prove nothing.
				Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a2"},
			}},
		}}
	}
	if got := realFindings(ZonePinnedVolume{}.Evaluate(hostOnly, Options{IncludeSystem: true})); len(got) != 0 {
		t.Errorf("a hostname-pinned PV produced %d zone-pin finding(s) — the zone path swallowed the hostname "+
			"case", len(got))
	}
	// And the existing hostname rule must still fire on it, or the "untouched" claim is unverified.
	if got := (NodePinnedVolume{}).Evaluate(hostOnly, Options{IncludeSystem: true}); len(got) == 0 {
		t.Error("NodePinnedVolume stopped firing on a hostname-pinned PV")
	}
}

// THE MODELLED PREDICATE LIST IS PUBLISHED IN THE FINDING, not in documentation. A named partial model is
// true; a fidelity claim is not — and a reader cannot judge the claim without the list.
func TestFeasibility_PublishesWhatItModelsAndWhatItDoesNot(t *testing.T) {
	out := realFindings((ZoneLossFeasibility{}).Evaluate(zoneLossFixture(), Options{IncludeSystem: true}))
	if len(out) == 0 {
		t.Fatal("no findings")
	}
	blob := strings.ToLower(out[0].Description + "\n" + strings.Join(out[0].Evidence, "\n"))
	// Modelled, named.
	for _, want := range []string{"request", "taint", "nodeselector", "affinity"} {
		if !strings.Contains(blob, want) {
			t.Errorf("the finding does not name %q among the modelled predicates:\n%s", want, blob)
		}
	}
	// Unmodelled, named — §4.1's two disclosures are in the SENTENCE, not a footnote.
	for _, want := range []string{"preemption", "autoscal"} {
		if !strings.Contains(blob, want) {
			t.Errorf("the finding does not disclose %q:\n%s", want, blob)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────

func allFeasibilityFindings(t *testing.T, inv *collect.Inventory) []types.Finding {
	t.Helper()
	var out []types.Finding
	out = append(out, realFindings((ZoneLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true}))...)
	out = append(out, realFindings((NodeLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true}))...)
	out = append(out, realFindings(ZonePinnedVolume{}.Evaluate(inv, Options{IncludeSystem: true}))...)
	return out
}

// realFindings drops confidence-0 abstentions, so a test about what the rules CLAIM is not satisfied by a
// disclosure that they claimed nothing.
func realFindings(in []types.Finding) []types.Finding {
	var out []types.Finding
	for _, f := range in {
		if f.Confidence > 0 {
			out = append(out, f)
		}
	}
	return out
}

func qty(s string) resource.Quantity { return resource.MustParse(s) }

func podWithSidecars() corev1.Pod {
	always := corev1.ContainerRestartPolicyAlways
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "sidecar-pod"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{
					Name: "istio-proxy", RestartPolicy: &always,
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU: qty("100m"), corev1.ResourceMemory: qty("128Mi"),
					}},
				},
				{
					Name: "migrate", // classic: runs to completion, then releases
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU: qty("500m"), corev1.ResourceMemory: qty("512Mi"),
					}},
				},
			},
			Containers: []corev1.Container{{
				Name: "app",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU: qty("200m"), corev1.ResourceMemory: qty("256Mi"),
				}},
			}},
		},
	}
}

// zoneLossFixture is a two-zone cluster where losing eu-central-1a leaves work with nowhere modelled to go:
//   - pinned-db-0 holds a PV pinned to eu-central-1a and cannot move at all
//   - big-app-0 requests more cpu than the surviving node can allocate
//   - tainted-app-0 tolerates a taint only node-a1 carries
//
// A healthy pod is included so the rules are not trivially unanimous.
func zoneLossFixture() *collect.Inventory {
	node := func(name, zone string, cpu, mem string, taints []corev1.Taint) corev1.Node {
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
				"topology.kubernetes.io/zone": zone,
				"kubernetes.io/hostname":      name,
			}},
			Spec: corev1.NodeSpec{Taints: taints},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: qty(cpu), corev1.ResourceMemory: qty(mem)},
				Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			},
		}
	}
	// EVERY POD CARRIES AN OWNER, and that is not cosmetic. Drain Preflight's placement index only assesses
	// pods with a Deployment or StatefulSet ancestor (assessableOwner), so a fixture of bare pods cannot
	// exercise NodePinnedVolume at all — and the first version of this file asserted that rule "stopped
	// firing" when what it had actually built was a cluster that rule never looks at. A fixture unable to
	// exercise a neighbouring rule will hide a regression in it later too.
	pod := func(ns, name, nodeName string, cpu string, tol []corev1.Toleration, vols []corev1.Volume) corev1.Pod {
		sts := strings.TrimSuffix(name, "-0")
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "StatefulSet", Name: sts,
			}}},
			Spec: corev1.PodSpec{
				NodeName:    nodeName,
				Tolerations: tol,
				Volumes:     vols,
				Containers: []corev1.Container{{
					Name: "app",
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU: qty(cpu), corev1.ResourceMemory: qty("64Mi"),
					}},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
	}

	one := int32(1)
	sts := func(ns, name string) appsv1.StatefulSet {
		return appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       appsv1.StatefulSetSpec{Replicas: &one},
		}
	}
	dbTaint := corev1.Taint{Key: "workload", Value: "db", Effect: corev1.TaintEffectNoSchedule}
	inv := &collect.Inventory{
		Nodes: []corev1.Node{
			node("node-a1", "eu-central-1a", "4", "16Gi", []corev1.Taint{dbTaint}),
			node("node-a2", "eu-central-1a", "4", "16Gi", nil),
			node("node-b1", "eu-central-1b", "1", "4Gi", nil),
		},
		Pods: []corev1.Pod{
			pod("data", "pinned-db-0", "node-a2", "100m", nil, []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc-db"}},
			}}),
			pod("api", "big-app-0", "node-a2", "3", nil, nil),
			pod("data", "tainted-app-0", "node-a1", "100m",
				[]corev1.Toleration{{Key: "workload", Operator: corev1.TolerationOpEqual, Value: "db", Effect: corev1.TaintEffectNoSchedule}}, nil),
			pod("api", "small-app-0", "node-a2", "50m", nil, nil),
		},
		PVCs: []corev1.PersistentVolumeClaim{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "pvc-db"},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-pinned-db"},
		}},
		StatefulSets: []appsv1.StatefulSet{
			sts("data", "pinned-db"), sts("api", "big-app"), sts("data", "tainted-app"), sts("api", "small-app"),
		},
		PVs: []corev1.PersistentVolume{{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-pinned-db"},
			Spec: corev1.PersistentVolumeSpec{NodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key:      "topology.kubernetes.io/zone",
						Operator: corev1.NodeSelectorOpIn,
						Values:   []string{"eu-central-1a"},
					}},
				}}},
			}},
		}},
	}
	inv.Meta.Collected = []string{"nodes", "pods", "persistentvolumes", "persistentvolumeclaims", "poddisruptionbudgets"}
	return inv
}

// A DAEMONSET POD IS NOT DISPLACED WORK, AND THIS FIRED ON EVERY CLUSTER.
//
// FOUND BY THE INDEPENDENT RECOUNT, not by a test. On the three-node kind testbed the recount said zero pods
// had nowhere to go; Shoalcheck said six findings — and every pod it named was a DaemonSet pod: kindnet, kube-proxy,
// node-exporter.
//
// WHY IT LOOKED LIKE A REFUSAL. Since Kubernetes 1.12 the DaemonSet controller schedules its pods by writing a
// required nodeAffinity of `metadata.name In [thatNode]` onto each one. The predicate model reads that
// faithfully and concludes, correctly, that no other node satisfies it — and then reports a pod that was never
// going to move as a pod with nowhere to go. A DaemonSet pod does not get rescheduled when its node goes away;
// the DaemonSet simply has one fewer node to cover.
//
// buildDrainPlacement had already learned this — `if isDaemonSetPod(p) { pl.daemonPods++; continue }` — which
// is the precedent, in this package, that this rule failed to follow.
func TestFeasibility_ADaemonSetPodIsNotDisplacedWork(t *testing.T) {
	inv := zoneLossFixture()
	// The shape the DaemonSet controller actually produces: an owner reference and a metadata.name affinity.
	inv.Pods = append(inv.Pods, corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "kindnet-abc12",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "kindnet"}},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-a1",
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchFields: []corev1.NodeSelectorRequirement{{
							Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a1"},
						}},
					}},
				},
			}},
			Containers: []corev1.Container{{
				Name: "kindnet",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU: qty("100m"), corev1.ResourceMemory: qty("50Mi"),
				}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})

	for _, f := range allFeasibilityFindings(t, inv) {
		blob := f.Title + "\n" + f.Description + "\n" + strings.Join(f.Evidence, "\n")
		if strings.Contains(blob, "kindnet-abc12") {
			t.Errorf("a DaemonSet pod was reported as having nowhere to go:\n%s", blob)
		}
		for _, ref := range f.AffectedResources {
			if ref.Name == "kindnet-abc12" {
				t.Error("a DaemonSet pod reached AffectedResources")
			}
		}
	}

	// NON-VACUITY: the fixture's real displaced pods must still be reported, or "no DaemonSet pod" is true
	// because the rules stopped reporting anything.
	out := realFindings((ZoneLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true}))
	if len(out) == 0 {
		t.Fatal("excluding DaemonSet pods silenced the rule entirely")
	}
	found := false
	for _, f := range out {
		if strings.Contains(strings.Join(f.Evidence, "\n"), "pinned-db-0") {
			found = true
		}
	}
	if !found {
		t.Error("the zone-pinned database is no longer reported, so the exclusion is too wide")
	}
}

// SPEC §6 — NO DOLLARS, AT ALL. The shape is TestDrainRules_NeverCarryDollars, and the reason is the same: a
// finding that carries a figure carries an implied action, and the action here would be the refused cost half.
func TestFeasibilityRules_NeverCarryDollars(t *testing.T) {
	out := allFeasibilityFindings(t, zoneLossFixture())
	if len(out) == 0 {
		t.Fatal("no findings, so this test scanned nothing")
	}
	for _, f := range out {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f — there is no traffic, revenue or SLA data in a snapshot, and a "+
				"placement constraint has no price", f.ID, f.DollarImpactMonthly)
		}
		if f.PriceBasis != "" && f.PriceBasis != types.PriceNotCost {
			t.Errorf("finding %s declares the price basis %q — this family is not a cost family", f.ID, f.PriceBasis)
		}
	}
}
