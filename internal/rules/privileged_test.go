package rules

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func privilegedContainer(d *appsv1.Deployment) {
	priv := true
	d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &priv}
}

func TestPrivileged_AggregatesAllOffensesIntoOneFinding(t *testing.T) {
	priv := true
	offender := deploy("app", "edge", 2, func(d *appsv1.Deployment) {
		ps := &d.Spec.Template.Spec
		ps.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &priv}
		ps.HostNetwork = true
		ps.HostPID = true
		ps.HostIPC = true
		ps.Volumes = []corev1.Volume{{
			Name:         "docker-sock",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}},
		}}
	})
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		offender,
		deploy("app", "clean", 2, nil),
	}}

	fs := PrivilegedHostAccess{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 aggregated finding for the offender, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "k8s.workload.privileged-host-access" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	// privileged + hostNetwork/PID/IPC are node-takeover primitives → High,
	// regardless of the (unmounted) docker.sock volume.
	if f.Severity != types.SeverityHigh || f.Category != types.CategorySecurity {
		t.Errorf("want security/high, got %s/%s", f.Category, f.Severity)
	}
	if len(f.Evidence) != 5 {
		t.Errorf("want 5 evidence lines (privileged + 3 host flags + hostPath), got %d: %v", len(f.Evidence), f.Evidence)
	}
	ev := strings.Join(f.Evidence, "\n")
	for _, want := range []string{
		"container main in Deployment app/edge: privileged=true",
		"Deployment app/edge: hostNetwork=true",
		"Deployment app/edge: hostPID=true",
		"Deployment app/edge: hostIPC=true",
		// volume is declared but no container mounts it → wording stays literally true.
		"volume docker-sock: hostPath /var/run/docker.sock (declared, not mounted by any container)",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence missing %q in:\n%s", want, ev)
		}
	}
	if f.RemediationYAML != "" {
		t.Errorf("no generic YAML patch for app-specific change, got:\n%s", f.RemediationYAML)
	}
	if !strings.Contains(f.RemediationCommand, "kubectl -n app get deployment edge") ||
		!strings.Contains(f.RemediationCommand, "grep -nE 'privileged|hostNetwork|hostPID|hostIPC|hostPath|hostPort|readOnly'") {
		t.Errorf("remediation command must locate the offending fields, got %q", f.RemediationCommand)
	}
	if f.Confidence != 1.0 {
		t.Errorf("presence facts carry confidence 1.0, got %v", f.Confidence)
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0].Name != "edge" {
		t.Errorf("affected = %+v", f.AffectedResources)
	}
}

func TestPrivileged_EachOffenseTypeAloneTriggers(t *testing.T) {
	cases := map[string]func(*appsv1.Deployment){
		"privileged":  privilegedContainer,
		"hostNetwork": func(d *appsv1.Deployment) { d.Spec.Template.Spec.HostNetwork = true },
		"hostPID":     func(d *appsv1.Deployment) { d.Spec.Template.Spec.HostPID = true },
		"hostIPC":     func(d *appsv1.Deployment) { d.Spec.Template.Spec.HostIPC = true },
		"hostPath": func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Volumes = []corev1.Volume{{
				Name:         "h",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}},
			}}
		},
	}
	for name, mutate := range cases {
		inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("app", "w", 2, mutate)}}
		fs := PrivilegedHostAccess{}.Evaluate(inv, Options{})
		if len(fs) != 1 {
			t.Errorf("%s alone: want 1 finding, got %d", name, len(fs))
			continue
		}
		if !strings.Contains(strings.Join(fs[0].Evidence, " "), name) {
			t.Errorf("%s: evidence must name the offense, got %v", name, fs[0].Evidence)
		}
	}
}

func TestPrivileged_HostPortFlagged(t *testing.T) {
	// PSS-Baseline B5 (CIS v1.9 5.2.13): a hostPort binds the container's port
	// directly on the node. Added in Version 1.1.0.
	d := deploy("app", "exposed", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].Ports = []corev1.ContainerPort{
			{ContainerPort: 8080, HostPort: 8080},
		}
	})
	fs := PrivilegedHostAccess{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
	if len(fs) != 1 {
		t.Fatalf("hostPort alone must produce 1 finding, got %d", len(fs))
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "hostPort=8080") {
		t.Errorf("evidence must name the hostPort, got %v", fs[0].Evidence)
	}
	// 1.2.0 was severity tiering and hostPath enrichment; 1.3.0 is the reach into bare Pods, Jobs and CronJobs.
	if fs[0].RuleVersion != "1.3.0" {
		t.Errorf("RuleVersion must be 1.3.0 (podTemplates), got %q", fs[0].RuleVersion)
	}
	// A lone hostPort is a blast-radius note, NOT a node-takeover primitive →
	// Medium, and the WhyItMatters must not claim full node compromise.
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("lone hostPort must be Medium, got %s", fs[0].Severity)
	}
	if strings.Contains(strings.ToLower(fs[0].WhyItMatters), "full node compromise") {
		t.Errorf("hostPort-only finding must not claim full node compromise: %q", fs[0].WhyItMatters)
	}
}

func TestPrivileged_NoHostPortNoFinding(t *testing.T) {
	// A normal containerPort (no hostPort) must NOT trigger the rule.
	d := deploy("app", "clean", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080}}
	})
	if fs := (PrivilegedHostAccess{}).Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{}); len(fs) != 0 {
		t.Fatalf("containerPort without hostPort must not flag, got %+v", fs)
	}
}

func TestPrivileged_InitContainerCounts(t *testing.T) {
	priv := true
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.InitContainers = []corev1.Container{{
			Name:            "setup",
			Image:           "img",
			SecurityContext: &corev1.SecurityContext{Privileged: &priv},
		}}
	})
	fs := PrivilegedHostAccess{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence[0], "init container setup") {
		t.Fatalf("privileged init container must be flagged, got %+v", fs)
	}
}

func TestPrivileged_CleanWorkloadNoFinding(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("app", "clean", 2, withFullSpec)}}
	if fs := (PrivilegedHostAccess{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("clean workload must produce no findings, got %+v", fs)
	}
}

func TestPrivileged_SystemNamespaceSkippedByDefault(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("kube-system", "kube-proxyish", 2, privilegedContainer)}}
	if fs := (PrivilegedHostAccess{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default, got %+v", fs)
	}
	if fs := (PrivilegedHostAccess{}).Evaluate(inv, Options{IncludeSystem: true}); len(fs) != 1 {
		t.Fatalf("IncludeSystem must opt back in, got %d findings", len(fs))
	}
}

// --- Fixes from 2026-06-16 rule-honesty audit ---

// hostPathVol wires a hostPath volume into the first container with a given
// readOnly flag and optional HostPathType.
func hostPathVol(path string, readOnly bool, t *corev1.HostPathType) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) {
		ps := &d.Spec.Template.Spec
		ps.Volumes = append(ps.Volumes, corev1.Volume{
			Name:         "hp",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path, Type: t}},
		})
		ps.Containers[0].VolumeMounts = append(ps.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name: "hp", MountPath: path, ReadOnly: readOnly,
		})
	}
}

// AUDIT FIX [line 296]: a declared-but-unmounted hostPath must not read as live
// access — it is not wired into any container, so it stays Low and the evidence
// says so literally.
func TestPrivileged_UnmountedHostPath_NotLiveAccess(t *testing.T) {
	d := deploy("app", "leftover", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Volumes = []corev1.Volume{{
			Name:         "orphan",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}},
		}}
		// NB: no VolumeMount references "orphan".
	})
	fs := PrivilegedHostAccess{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityLow {
		t.Errorf("unmounted hostPath (even docker.sock) must not be High; got %s", fs[0].Severity)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "declared, not mounted by any container") {
		t.Errorf("evidence must state the volume is unmounted: %v", fs[0].Evidence)
	}
}

// AUDIT FIX [line 300]: a read-only, type-scoped hostPath is materially lower
// risk than a writable docker.sock — it must be Medium with readOnly + type in
// the evidence, not folded into the same High bucket.
func TestPrivileged_ReadOnlyScopedHostPath_IsMedium(t *testing.T) {
	dir := corev1.HostPathDirectory
	d := deploy("app", "metrics", 2, hostPathVol("/sys", true, &dir))
	fs := PrivilegedHostAccess{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("read-only scoped hostPath must be Medium, got %s", fs[0].Severity)
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "read-only mount") {
		t.Errorf("evidence must surface readOnly: %v", fs[0].Evidence)
	}
	if !strings.Contains(ev, "type=Directory") {
		t.Errorf("evidence must surface HostPathType: %v", fs[0].Evidence)
	}
	if strings.Contains(strings.ToLower(fs[0].WhyItMatters), "full node compromise") {
		t.Errorf("read-only-only finding must not claim full node compromise: %q", fs[0].WhyItMatters)
	}
}

// AUDIT FIX [line 150 + 300]: a WRITABLE mount of a sensitive node path
// (docker.sock) IS a node-takeover primitive → High, and WhyItMatters may claim
// node compromise. This is the case that must stay distinguishable from the
// read-only /sys scrape above.
func TestPrivileged_WritableDockerSock_IsHigh(t *testing.T) {
	d := deploy("app", "danger", 2, hostPathVol("/var/run/docker.sock", false, nil))
	fs := PrivilegedHostAccess{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("writable docker.sock mount must be High, got %s", fs[0].Severity)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "writable mount") {
		t.Errorf("evidence must surface writable: %v", fs[0].Evidence)
	}
	if !strings.Contains(strings.ToLower(fs[0].WhyItMatters), "full node compromise") {
		t.Errorf("writable sensitive mount SHOULD warn of node compromise: %q", fs[0].WhyItMatters)
	}
}

// AUDIT FIX [line 150]: a writable mount on a NON-sensitive path is real but
// scoped → Medium, not High.
func TestPrivileged_WritableNonSensitiveHostPath_IsMedium(t *testing.T) {
	d := deploy("app", "cache", 2, hostPathVol("/mnt/app-cache", false, nil))
	fs := PrivilegedHostAccess{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("writable non-sensitive hostPath must be Medium, got %s", fs[0].Severity)
	}
}

// AUDIT FIX [line 154]: a known node-infrastructure workload (here a Cilium CNI
// DaemonSet with the canonical privileged/hostNetwork access) must be
// down-ranked and tagged, NOT reported as a High misconfiguration on a normal
// production cluster.
func TestPrivileged_KnownNodeInfra_DownRankedAndTagged(t *testing.T) {
	priv := true
	ds := appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium", Namespace: "kube-network"},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": "cilium"}},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{{
						Name:            "cilium-agent",
						Image:           "cilium/cilium",
						SecurityContext: &corev1.SecurityContext{Privileged: &priv},
					}},
				},
			},
		},
	}
	fs := PrivilegedHostAccess{}.Evaluate(&collect.Inventory{DaemonSets: []appsv1.DaemonSet{ds}}, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity == types.SeverityHigh {
		t.Errorf("known node-infra (cilium) must be down-ranked below High, got %s", f.Severity)
	}
	if f.Confidence >= 0.5 {
		t.Errorf("node-infra grant is expected, not a problem — confidence must be low, got %v", f.Confidence)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "node-infrastructure pattern") {
		t.Errorf("evidence must carry a structured node-infra NOTE: %v", f.Evidence)
	}
	if !strings.Contains(strings.ToLower(f.Title), "confirm") {
		t.Errorf("title should ask to confirm, not 'remove', for node infra: %q", f.Title)
	}
}

func TestPrivileged_StableDistinctIDs(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "a", 2, privilegedContainer),
		deploy("app", "b", 2, privilegedContainer),
	}}
	first := PrivilegedHostAccess{}.Evaluate(inv, Options{})
	second := PrivilegedHostAccess{}.Evaluate(inv, Options{})
	if len(first) != 2 || first[0].ID == first[1].ID {
		t.Fatalf("two workloads must get distinct IDs: %+v", first)
	}
	if first[0].ID != second[0].ID || !strings.HasPrefix(first[0].ID, "f-") {
		t.Fatalf("IDs must be stable f-prefixed hashes across runs: %q vs %q", first[0].ID, second[0].ID)
	}
}
