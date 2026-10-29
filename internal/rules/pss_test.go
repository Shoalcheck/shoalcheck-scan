package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ptrBool / ptrInt64 build the pointer fields the K8s securityContext uses.
func ptrBool(b bool) *bool    { return &b }
func ptrInt64(i int64) *int64 { return &i }

// ruleByID fetches a PSS table rule by its RuleID for focused per-control tests.
func ruleByID(t *testing.T, id string) Rule {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	t.Helper()
	for _, r := range All() {
		if r.ID() == id {
			return r
		}
	}
	t.Fatalf("rule %q not registered", id)
	return nil
}

func single(t *testing.T, id string, d appsv1.Deployment) []types.Finding {
	t.Helper()
	return ruleByID(t, id).Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
}

// --- dangerous-capabilities -------------------------------------------------

func TestDangerousCapabilities_FlagsAddedCaps(t *testing.T) {
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN", "NET_BIND_SERVICE"}},
		}
	})
	fs := single(t, "k8s.workload.dangerous-capabilities", d)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "SYS_ADMIN") {
		t.Errorf("must name the dangerous cap, got %v", fs[0].Evidence)
	}
	// NET_BIND_SERVICE is the only allowed add and must NOT be flagged.
	if strings.Contains(ev, "NET_BIND_SERVICE") {
		t.Errorf("NET_BIND_SERVICE is PSS-baseline-allowed and must not be flagged: %v", fs[0].Evidence)
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("dangerous-capabilities is High, got %s", fs[0].Severity)
	}
}

func TestDangerousCapabilities_OnlyAllowedCapNoFinding(t *testing.T) {
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE"}},
		}
	})
	if fs := single(t, "k8s.workload.dangerous-capabilities", d); len(fs) != 0 {
		t.Fatalf("only NET_BIND_SERVICE added must not flag, got %+v", fs)
	}
}

// TestDangerousCapabilities_BenignDefaultCapsNoFinding: a benign default-set cap a
// container legitimately adds back (CHOWN on an init-chown helper, etc.) must NOT
// fire the High "dangerous capabilities" finding — founder QA caught grafana's
// init-chown-data add=[CHOWN] firing as a false positive at High severity.
func TestDangerousCapabilities_BenignDefaultCapsNoFinding(t *testing.T) {
	for _, capName := range []string{"CHOWN", "DAC_OVERRIDE", "SETUID", "SETGID", "FOWNER", "KILL", "SETPCAP"} {
		d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Add: []corev1.Capability{corev1.Capability(capName)}},
			}
		})
		if fs := single(t, "k8s.workload.dangerous-capabilities", d); len(fs) != 0 {
			t.Errorf("benign default-set cap %s must not flag dangerous-capabilities, got %d: %+v", capName, len(fs), fs)
		}
	}
}

func TestDangerousCapabilities_AddAllFlagged(t *testing.T) {
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"ALL"}},
		}
	})
	fs := single(t, "k8s.workload.dangerous-capabilities", d)
	if len(fs) != 1 || !strings.Contains(strings.Join(fs[0].Evidence, " "), "ALL") {
		t.Fatalf("adding ALL must flag, got %+v", fs)
	}
}

// --- capabilities-not-dropped (high-fanout: Medium, not High) ---------------

func TestCapabilitiesNotDropped_FiresWhenAllNotDropped(t *testing.T) {
	d := deploy("app", "w", 2, nil) // no securityContext at all
	fs := single(t, "k8s.workload.capabilities-not-dropped", d)
	if len(fs) != 1 {
		t.Fatalf("missing drop:[ALL] must flag, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("high-fanout check must be Medium not High, got %s", fs[0].Severity)
	}
}

func TestCapabilitiesNotDropped_DropAllCaseInsensitiveNoFinding(t *testing.T) {
	for _, drop := range []string{"ALL", "all", "All"} {
		d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{corev1.Capability(drop)}},
			}
		})
		if fs := single(t, "k8s.workload.capabilities-not-dropped", d); len(fs) != 0 {
			t.Errorf("drop:[%s] must be honored case-insensitively, got %+v", drop, fs)
		}
	}
}

// --- runs-as-root + inheritance --------------------------------------------

func TestRunsAsRoot_NoSecurityContextUnconfirmed(t *testing.T) {
	// Image "img" is not a known root-by-default base, so with no securityContext
	// at all this is UNCONFIRMED non-root — Medium, matching the sibling
	// PSS-field-unset checks (we cannot confirm root, so we don't rate it High).
	d := deploy("app", "w", 2, nil)
	fs := single(t, "k8s.workload.runs-as-root", d)
	if len(fs) != 1 {
		t.Fatalf("workload with no non-root assertion must flag, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "unconfirmed non-root") {
		t.Errorf("must say UNCONFIRMED, never 'runs as root', got %v", fs[0].Evidence)
	}
	if strings.Contains(strings.ToLower(ev), "runs as root") {
		t.Errorf("honesty: must NOT assert 'runs as root' without runAsUser:0, got %v", fs[0].Evidence)
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("unconfirmed non-root must be Medium (matches sibling PSS-field-unset checks), got %s", fs[0].Severity)
	}
	// The headline must match the (honest) evidence: it is about API enforcement,
	// not a confirmed root-execution defect.
	if !strings.Contains(fs[0].Title, "runAsNonRoot unset") {
		t.Errorf("title must frame this as runAsNonRoot unset / API enforcement, got %q", fs[0].Title)
	}
}

func TestRunsAsRoot_PodLevelRunAsNonRootSuppresses(t *testing.T) {
	// Pod-level runAsNonRoot:true must be INHERITED — a container with no
	// securityContext must NOT false-positive. This is the §4.3 inheritance bug.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: ptrBool(true)}
	})
	if fs := single(t, "k8s.workload.runs-as-root", d); len(fs) != 0 {
		t.Fatalf("pod-level runAsNonRoot:true must suppress the finding, got %+v", fs)
	}
}

func TestRunsAsRoot_PodLevelNonZeroUserSuppresses(t *testing.T) {
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptrInt64(1000)}
	})
	if fs := single(t, "k8s.workload.runs-as-root", d); len(fs) != 0 {
		t.Fatalf("pod-level runAsUser:1000 must suppress the finding, got %+v", fs)
	}
}

func TestRunsAsRoot_ContainerOverridesPodHardening(t *testing.T) {
	// Pod hardens to non-root, but ONE container overrides with runAsNonRoot:false
	// AND no non-zero uid → that container must still flag (effective value is the
	// container's). An explicit runAsNonRoot:false OPTS IN to root, so this is
	// confirmed-class → High.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: ptrBool(true)}
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{RunAsNonRoot: ptrBool(false)}
	})
	fs := single(t, "k8s.workload.runs-as-root", d)
	if len(fs) != 1 {
		t.Fatalf("container override of pod hardening must flag, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("explicit runAsNonRoot:false opts in to root → confirmed → High, got %s", fs[0].Severity)
	}
}

func TestRunsAsRoot_ExplicitRootStatedPlainly(t *testing.T) {
	// runAsUser:0 explicit is the ONLY case we may say "runs as UID 0", and the
	// only one besides runAsNonRoot:false / known-root base where root is
	// confirmed → High.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{RunAsUser: ptrInt64(0)}
	})
	fs := single(t, "k8s.workload.runs-as-root", d)
	if len(fs) != 1 {
		t.Fatalf("explicit runAsUser:0 must flag, got %d", len(fs))
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "runs as UID 0") {
		t.Errorf("explicit root must be stated as UID 0, got %v", fs[0].Evidence)
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("explicit runAsUser:0 is confirmed root → High, got %s", fs[0].Severity)
	}
}

func TestRunsAsRoot_KnownRootBaseImageConfirmedHigh(t *testing.T) {
	// No non-root assertion, but the image is a known root-by-default base
	// (alpine). The image USER directive is not API-observable, but the NAME
	// heuristic makes root near-certain → confirmed-class → High. Evidence must
	// still NOT claim "runs as root" outright, and must disclose it matched on
	// the image name.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].Image = "alpine:3.19"
	})
	fs := single(t, "k8s.workload.runs-as-root", d)
	if len(fs) != 1 {
		t.Fatalf("known-root base with no non-root assertion must flag, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("known-root base image (no non-root set) → root near-certain → High, got %s", fs[0].Severity)
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "known root-by-default base") || !strings.Contains(ev, "matched on image name") {
		t.Errorf("evidence must disclose the image-name heuristic, got %v", fs[0].Evidence)
	}
	if strings.Contains(strings.ToLower(ev), "runs as root") {
		t.Errorf("honesty: even a known-root base must not assert 'runs as root' outright, got %v", fs[0].Evidence)
	}
}

func TestRunsAsRoot_RegistryQualifiedRootBaseImageConfirmed(t *testing.T) {
	// The heuristic must strip a registry host + repository path so a
	// fully-qualified ref still matches the bare base name.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].Image = "docker.io/library/ubuntu:22.04"
	})
	fs := single(t, "k8s.workload.runs-as-root", d)
	if len(fs) != 1 || fs[0].Severity != types.SeverityHigh {
		t.Fatalf("registry-qualified ubuntu must classify as known-root → High, got %+v", fs)
	}
}

func TestRunsAsRoot_NonRootBaseImageStaysUnconfirmedMedium(t *testing.T) {
	// An app image whose NAME is not a known root base (here a repo that merely
	// contains the substring "alpine") must NOT be promoted to High — the
	// heuristic matches the bare repository name exactly, not a substring.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].Image = "myco/alpine-based-app:1.0"
	})
	fs := single(t, "k8s.workload.runs-as-root", d)
	if len(fs) != 1 {
		t.Fatalf("no non-root assertion must still flag, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("a non-base app image must stay UNCONFIRMED → Medium, got %s", fs[0].Severity)
	}
}

// --- allow-privilege-escalation --------------------------------------------

func TestAllowPrivilegeEscalation_NilDefaultsTrue(t *testing.T) {
	d := deploy("app", "w", 2, nil)
	fs := single(t, "k8s.workload.allow-privilege-escalation", d)
	if len(fs) != 1 {
		t.Fatalf("unset allowPrivilegeEscalation defaults true and must flag, got %d", len(fs))
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "defaults to true") {
		t.Errorf("evidence must explain the default, got %v", fs[0].Evidence)
	}
}

func TestAllowPrivilegeEscalation_FalseNoFinding(t *testing.T) {
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{AllowPrivilegeEscalation: ptrBool(false)}
	})
	if fs := single(t, "k8s.workload.allow-privilege-escalation", d); len(fs) != 0 {
		t.Fatalf("allowPrivilegeEscalation:false must not flag, got %+v", fs)
	}
}

// --- seccomp-not-enforced + inheritance ------------------------------------

func TestSeccompNotEnforced_UnsetFlagged(t *testing.T) {
	d := deploy("app", "w", 2, nil)
	fs := single(t, "k8s.workload.seccomp-not-enforced", d)
	if len(fs) != 1 || !strings.Contains(strings.Join(fs[0].Evidence, " "), "unset") {
		t.Fatalf("unset seccomp must flag with 'unset' evidence, got %+v", fs)
	}
}

func TestSeccompNotEnforced_PodLevelRuntimeDefaultSuppresses(t *testing.T) {
	// Pod-level RuntimeDefault must be INHERITED by containers — no finding.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		}
	})
	if fs := single(t, "k8s.workload.seccomp-not-enforced", d); len(fs) != 0 {
		t.Fatalf("pod-level RuntimeDefault must suppress (inheritance), got %+v", fs)
	}
}

func TestSeccompNotEnforced_UnconfinedDistinctEvidence(t *testing.T) {
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
		}
	})
	fs := single(t, "k8s.workload.seccomp-not-enforced", d)
	if len(fs) != 1 || !strings.Contains(strings.Join(fs[0].Evidence, " "), "Unconfined") {
		t.Fatalf("Unconfined must be a distinct evidence line, got %+v", fs)
	}
}

// --- writable-root-filesystem (high-fanout: Low, never High) ----------------

func TestWritableRootFilesystem_UnsetFlaggedLow(t *testing.T) {
	d := deploy("app", "w", 2, nil)
	fs := single(t, "k8s.workload.writable-root-filesystem", d)
	if len(fs) != 1 {
		t.Fatalf("unset readOnlyRootFilesystem must flag, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityLow {
		t.Errorf("writable-root-filesystem must be Low (PSS does not require it), got %s", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Description, "PSS does NOT require") {
		t.Errorf("description must disclaim that PSS does not require this, got %q", fs[0].Description)
	}
}

func TestWritableRootFilesystem_ReadOnlyTrueNoFinding(t *testing.T) {
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{ReadOnlyRootFilesystem: ptrBool(true)}
	})
	if fs := single(t, "k8s.workload.writable-root-filesystem", d); len(fs) != 0 {
		t.Fatalf("readOnlyRootFilesystem:true must not flag, got %+v", fs)
	}
}

// --- seccomp empty-string Type (defensive hardening) ------------------------

func TestSeccompNotEnforced_EmptyTypeTreatedAsUnset(t *testing.T) {
	// An empty SeccompProfile.Type must be treated as "not enforced" (same as
	// nil/unset), even though the API normally rejects it.
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: ""},
		}
	})
	fs := single(t, "k8s.workload.seccomp-not-enforced", d)
	if len(fs) != 1 || !strings.Contains(strings.Join(fs[0].Evidence, " "), "unset") {
		t.Fatalf("empty-string seccompProfile.type must flag as unset, got %+v", fs)
	}
}

// --- default-namespace-in-use (CIS 5.7.4) -----------------------------------

func TestDefaultNamespaceInUse_WorkloadInDefaultFlagged(t *testing.T) {
	d := deploy("default", "api", 2, nil)
	fs := single(t, "k8s.namespace.default-namespace-in-use", d)
	if len(fs) != 1 {
		t.Fatalf("workload in default namespace must flag, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "default namespace") || !strings.Contains(ev, "api") {
		t.Errorf("evidence must name the workload and the default namespace, got %v", fs[0].Evidence)
	}
	if fs[0].Severity != types.SeverityLow {
		t.Errorf("default-namespace-in-use is a hygiene signal: must be Low, got %s", fs[0].Severity)
	}
}

func TestDefaultNamespaceInUse_NamedNamespaceNotFlagged(t *testing.T) {
	d := deploy("payments", "api", 2, nil)
	if fs := single(t, "k8s.namespace.default-namespace-in-use", d); len(fs) != 0 {
		t.Fatalf("workload in a named namespace must NOT flag, got %+v", fs)
	}
}

func TestDefaultNamespaceInUse_SystemNamespaceSkipped(t *testing.T) {
	// kube-system is filtered by workloads() (it is not the default namespace
	// anyway, but this confirms the system-ns filter still applies).
	d := deploy("kube-system", "sys", 2, nil)
	if fs := single(t, "k8s.namespace.default-namespace-in-use", d); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default, got %+v", fs)
	}
}

// --- cross-cutting: one finding per workload, system-ns filter, x-ref -------

func TestPSS_OneFindingPerWorkloadAggregatesContainers(t *testing.T) {
	// Two offending containers in one workload → exactly one finding with two
	// evidence lines (the PrivilegedHostAccess aggregation shape).
	d := deploy("app", "w", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers = []corev1.Container{
			{Name: "a", Image: "img"},
			{Name: "b", Image: "img"},
		}
	})
	fs := single(t, "k8s.workload.capabilities-not-dropped", d)
	if len(fs) != 1 {
		t.Fatalf("two bad containers must aggregate into ONE finding, got %d", len(fs))
	}
	if len(fs[0].Evidence) != 2 {
		t.Errorf("both containers must appear as evidence lines, got %v", fs[0].Evidence)
	}
}

func TestPSS_SystemNamespaceSkippedByDefault(t *testing.T) {
	d := deploy("kube-system", "sys", 2, nil)
	if fs := single(t, "k8s.workload.runs-as-root", d); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default, got %+v", fs)
	}
}

func TestPSS_DescriptionsCrossReferenceAdmission(t *testing.T) {
	// Every per-container PSS check must point the reader at the admission rule.
	d := deploy("app", "w", 2, nil)
	for _, c := range pssChecks {
		fs := single(t, c.id, d)
		if len(fs) == 0 {
			continue
		}
		if !strings.Contains(fs[0].Description, "pss-admission-not-enforced") {
			t.Errorf("rule %q description must cross-reference the admission check, got %q", c.id, fs[0].Description)
		}
	}
}

// --- PodSecurityAdmissionNotEnforced (§4.4) ---------------------------------

func nsWithLabels(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func TestPSAdmission_AbsentEnforceFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  []corev1.Namespace{nsWithLabels("payments", map[string]string{"pod-security.kubernetes.io/warn": "baseline"})},
	}
	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("namespace without enforce label must flag, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "enforce=<unset>") || !strings.Contains(ev, "warn=baseline") {
		t.Errorf("evidence must report what IS present, got %v", fs[0].Evidence)
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("admission gap is Medium, got %s", fs[0].Severity)
	}
}

func TestPSAdmission_PrivilegedEnforceFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  []corev1.Namespace{nsWithLabels("payments", map[string]string{"pod-security.kubernetes.io/enforce": "privileged"})},
	}
	if fs := (PodSecurityAdmissionNotEnforced{}).Evaluate(inv, Options{}); len(fs) != 1 {
		t.Fatalf("enforce=privileged must flag (does not block), got %d", len(fs))
	}
}

func TestPSAdmission_BaselineAndRestrictedSuppress(t *testing.T) {
	for _, profile := range []string{"baseline", "restricted"} {
		inv := &collect.Inventory{
			Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
			Namespaces:  []corev1.Namespace{nsWithLabels("payments", map[string]string{"pod-security.kubernetes.io/enforce": profile})},
		}
		if fs := (PodSecurityAdmissionNotEnforced{}).Evaluate(inv, Options{}); len(fs) != 0 {
			t.Errorf("enforce=%s must suppress the finding, got %+v", profile, fs)
		}
	}
}

func TestPSAdmission_OnlyNamespacesWithWorkloads(t *testing.T) {
	// A namespace with NO workloads (just present in inv.Namespaces) must not flag.
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces: []corev1.Namespace{
			nsWithLabels("payments", nil),
			nsWithLabels("empty", nil), // no workloads → must not appear
		},
	}
	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("only the workload-bearing namespace must flag, got %d: %+v", len(fs), fs)
	}
	if fs[0].AffectedResources[0].Name != "payments" {
		t.Errorf("flagged %q, want payments", fs[0].AffectedResources[0].Name)
	}
}

func TestPSAdmission_SystemNamespaceSkipped(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("kube-system", "sys", 2, nil)},
		Namespaces:  []corev1.Namespace{nsWithLabels("kube-system", nil)},
	}
	if fs := (PodSecurityAdmissionNotEnforced{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default, got %+v", fs)
	}
}

func TestPSAdmission_RemediationStagesEnforcement(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  []corev1.Namespace{nsWithLabels("payments", nil)},
	}
	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	cmd := fs[0].RemediationCommand
	if !strings.Contains(cmd, "warn=baseline") || !strings.Contains(cmd, "enforce=baseline") {
		t.Errorf("remediation must stage warn/audit before enforce, got %q", cmd)
	}
}

// --- denial guard + not-observed honesty (audit findings #1, #3) ------------

// Audit finding #1: when the namespaces LIST was denied/timed out, Collect()
// records "namespaces: <err>" in Meta.Denied and leaves inv.Namespaces empty.
// The rule must NOT emit a confident "admission does not block any pod" gap; it
// must emit an UNKNOWN finding with Confidence < 1.0 that does not assert absence.
func TestPSAdmission_NamespacesDenied_EmitsUnknownNotConfidentGap(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  nil, // list denied → empty
	}
	inv.Meta.Denied = []string{"namespaces: namespaces is forbidden: User cannot list resource \"namespaces\""}
	inv.Meta.Collected = []string{"deployments"}

	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("workload-bearing ns with denied namespace list must emit one UNKNOWN finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Confidence >= 1.0 {
		t.Errorf("denied namespaces must NOT be reported at Confidence 1.0, got %v", f.Confidence)
	}
	if f.Confidence > 0.5 {
		t.Errorf("UNKNOWN finding should be low confidence (<=0.5), got %v", f.Confidence)
	}
	ev := strings.Join(f.Evidence, " ")
	if strings.Contains(ev, "admission does not block any pod") {
		t.Errorf("must NOT assert observed-absence when namespaces were not collected, got %q", ev)
	}
	if !strings.Contains(ev, "UNKNOWN") {
		t.Errorf("evidence must state enforcement is UNKNOWN, got %q", ev)
	}
	if f.RemediationCommand != "" {
		t.Errorf("UNKNOWN finding must not emit a kubectl patch as if there were a confirmed gap, got %q", f.RemediationCommand)
	}
	if f.Severity != types.SeverityLow {
		t.Errorf("UNKNOWN (not-assessed) finding should be Low, got %s", f.Severity)
	}
}

// Audit finding #1 fallback: an inventory with no Meta but empty Namespaces and
// live workloads (e.g. a partial snapshot built without Meta) must also be
// treated as not-collected, never as confirmed-absent.
func TestPSAdmission_EmptyNamespacesNoMeta_TreatedAsUnknown(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  nil, // no namespaces collected, Meta silent
	}
	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 UNKNOWN finding, got %d", len(fs))
	}
	if fs[0].Confidence >= 1.0 {
		t.Errorf("empty namespaces + live workloads must not be a confident gap, got Confidence %v", fs[0].Confidence)
	}
	if strings.Contains(strings.Join(fs[0].Evidence, " "), "admission does not block any pod") {
		t.Errorf("must not assert absence, got %v", fs[0].Evidence)
	}
}

// Audit finding #3: namespaces WERE collected, but a specific workload-bearing
// namespace object is missing from the snapshot (map miss, not key miss). The
// evidence must distinguish "object not collected" from a confirmed "<unset>"
// label, and the finding must be UNKNOWN, not a confident gap.
func TestPSAdmission_WorkloadNSMissingFromSnapshot_NotCollectedNotUnset(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  []corev1.Namespace{nsWithLabels("other", nil)}, // payments NOT present
	}
	inv.Meta.Collected = []string{"namespaces", "deployments"}

	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("the missing workload namespace must emit one finding, got %d", len(fs))
	}
	f := fs[0]
	if f.AffectedResources[0].Name != "payments" {
		t.Fatalf("flagged %q, want payments", f.AffectedResources[0].Name)
	}
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "namespace object not collected") {
		t.Errorf("evidence must say the object was not collected, not <unset>, got %q", ev)
	}
	if strings.Contains(ev, "enforce=<unset>") {
		t.Errorf("must NOT collapse a missing namespace object into enforce=<unset>, got %q", ev)
	}
	if f.Confidence >= 1.0 {
		t.Errorf("a not-observed namespace must not be Confidence 1.0, got %v", f.Confidence)
	}
}

// A namespace that WAS observed with a genuinely absent enforce label is still a
// confident gap (Confidence 1.0) — the denial guard must not over-suppress.
func TestPSAdmission_ObservedNSWithAbsentLabel_StaysConfidentGap(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  []corev1.Namespace{nsWithLabels("payments", nil)},
	}
	inv.Meta.Collected = []string{"namespaces", "deployments"}

	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Confidence != 1.0 {
		t.Errorf("an OBSERVED namespace with absent enforce is a certain gap, want Confidence 1.0, got %v", fs[0].Confidence)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "admission does not block any pod") {
		t.Errorf("observed gap should keep the confident wording, got %v", fs[0].Evidence)
	}
}

// Audit finding #2 (miscalibration): the confirmed-gap finding must note that
// baseline is the conservative first step and restricted is required to satisfy
// the per-container Restricted-profile findings — not silently pin baseline.
func TestPSAdmission_GapDescriptionRequiresRestricted(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("payments", "api", 2, nil)},
		Namespaces:  []corev1.Namespace{nsWithLabels("payments", nil)},
	}
	inv.Meta.Collected = []string{"namespaces", "deployments"}

	fs := PodSecurityAdmissionNotEnforced{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	desc := fs[0].Description
	if !strings.Contains(desc, "restricted") || !strings.Contains(desc, "baseline") {
		t.Errorf("description must mention both baseline (first step) and restricted (required to close), got %q", desc)
	}
	if !strings.Contains(strings.ToLower(desc), "required to fully close") &&
		!strings.Contains(strings.ToLower(desc), "restricted is required") {
		t.Errorf("description must state restricted is required to fully close the per-container findings, got %q", desc)
	}
}

// --- cross-control no-collision (mirror rules_test.go:138-162) --------------

func TestPSS_NoFindingIDCollisionAcrossControls(t *testing.T) {
	// One workload that trips EVERY per-container PSS check at once. Each control
	// has a DISTINCT RuleID, so the per-workload findingIDs must all differ —
	// duplicate IDs would abort the audit at Validate(). This is the linchpin
	// invariant for the table-driven family.
	priv := true
	d := deploy("app", "kitchen-sink", 2, func(d *appsv1.Deployment) {
		c := &d.Spec.Template.Spec.Containers[0]
		c.SecurityContext = &corev1.SecurityContext{
			Privileged:               &priv,
			Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}},
			AllowPrivilegeEscalation: ptrBool(true),
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
		}
	})
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{d},
		Namespaces:  []corev1.Namespace{nsWithLabels("app", nil)},
	}

	seen := map[string]string{} // findingID -> ruleID that produced it
	var total int
	for _, r := range All() {
		for _, f := range r.Evaluate(inv, Options{}) {
			total++
			if prev, ok := seen[f.ID]; ok {
				t.Fatalf("findingID collision %q produced by both %q and %q", f.ID, prev, f.RuleID)
			}
			seen[f.ID] = f.RuleID
		}
	}
	if total == 0 {
		t.Fatal("kitchen-sink workload produced no findings — test is not exercising the rules")
	}
	if len(seen) != total {
		t.Fatalf("expected %d distinct finding IDs, got %d", total, len(seen))
	}
}
