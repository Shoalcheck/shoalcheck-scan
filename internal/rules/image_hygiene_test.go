package rules

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// imgDeploy builds a deployment whose single container runs image with policy.
// NOTE: the shared deploy() helper defaults to image "img" (no tag), which this
// rule rightly flags — clean fixtures here always pin a tag.
func imgDeploy(ns, name, image string, policy corev1.PullPolicy) appsv1.Deployment {
	return deploy(ns, name, 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].Image = image
		d.Spec.Template.Spec.Containers[0].ImagePullPolicy = policy
	})
}

func TestMutableImageTags_LatestTag(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("app", "w", "nginx:latest", corev1.PullIfNotPresent)}}
	fs := MutableImageTags{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.RuleID != "k8s.workload.mutable-image-tags" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if f.Severity != types.SeverityMedium || f.Category != types.CategoryConfig {
		t.Errorf("want config/medium, got %s/%s", f.Category, f.Severity)
	}
	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "container main: image nginx:latest (mutable :latest tag)") {
		t.Errorf("evidence = %v", f.Evidence)
	}
	if !strings.Contains(f.RemediationCommand, "kubectl -n app get deployment w") ||
		!strings.Contains(f.RemediationCommand, "jsonpath='{.spec.template.spec.containers[*].image}'") {
		t.Errorf("remediation command must show where images live, got %q", f.RemediationCommand)
	}
	// A literally-mutable reference is a verified defect, but the "non-reproducible
	// deploys" consequence is still an inference, so confidence is high (0.9) not 1.0.
	if f.Confidence != 0.9 {
		t.Errorf("verified mutable reference carries confidence 0.9, got %v", f.Confidence)
	}
	// The remediation must NOT hand the reader a blanket "switch to IfNotPresent":
	// that is only safe once a fixed tag is pinned.
	if !strings.Contains(f.Description, "Pin a specific version tag") {
		t.Errorf("description must recommend pinning, got %q", f.Description)
	}
}

func TestMutableImageTags_NoTagDefaultsToLatest(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("app", "w", "nginx", corev1.PullIfNotPresent)}}
	fs := MutableImageTags{}.Evaluate(inv, Options{})
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence[0], "no tag") {
		t.Fatalf("untagged image must be flagged as implicit :latest, got %+v", fs)
	}
}

// A version-pinned tag (semver) with Always is just redundant churn, not a
// defect: the bytes behind 1.25.3 / v2.1 don't move. It must NOT be flagged.
func TestMutableImageTags_AlwaysOnSemverTagIsClean(t *testing.T) {
	for _, tag := range []string{"nginx:1.25.3", "nginx:v2.1", "nginx:1.25", "nginx:3.0.0-rc1"} {
		inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("app", "w", tag, corev1.PullAlways)}}
		if fs := (MutableImageTags{}).Evaluate(inv, Options{}); len(fs) != 0 {
			t.Errorf("Always on immutable-looking tag %q must not be flagged, got %+v", tag, fs)
		}
	}
}

// A floating/release-channel tag pulled with Always is the intentional update
// path many teams use. It is reported only as a LOW-severity, reduced-confidence
// hint to "verify it is immutable" — never asserted as a defect, and the
// remediation must NOT tell the operator to switch to IfNotPresent (that would
// freeze stale bytes on nodes that already cached the tag).
func TestMutableImageTags_AlwaysOnFloatingTagIsHint(t *testing.T) {
	for _, tag := range []string{"api:stable", "api:main", "api:prod", "api:1", "api:nightly"} {
		inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("app", "w", tag, corev1.PullAlways)}}
		fs := MutableImageTags{}.Evaluate(inv, Options{})
		if len(fs) != 1 {
			t.Fatalf("floating tag %q + Always must produce 1 finding, got %d", tag, len(fs))
		}
		f := fs[0]
		if f.Severity != types.SeverityLow {
			t.Errorf("tag %q: floating-tag-Always is an inference → Low severity, got %s", tag, f.Severity)
		}
		if f.Confidence != 0.4 {
			t.Errorf("tag %q: inferred race → confidence 0.4, got %v", tag, f.Confidence)
		}
		if !strings.Contains(f.Evidence[0], "verify it is immutable") {
			t.Errorf("tag %q: evidence must hedge to 'verify', got %v", tag, f.Evidence)
		}
		// The only mention of IfNotPresent for a floating tag must be the explicit
		// warning against it — never an unqualified "switch to IfNotPresent".
		if !strings.Contains(f.Description, "do NOT switch to IfNotPresent") {
			t.Errorf("tag %q: must warn against IfNotPresent on a floating tag, got %q", tag, f.Description)
		}
		if !strings.Contains(f.Description, "pin a digest instead") {
			t.Errorf("tag %q: floating-tag remediation must offer 'pin a digest', got %q", tag, f.Description)
		}
	}
}

func TestMutableImageTags_LatestPlusAlwaysIsOneOffense(t *testing.T) {
	// :latest with Always is one root cause (mutable tag), not two findings' worth.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("app", "w", "nginx:latest", corev1.PullAlways)}}
	fs := MutableImageTags{}.Evaluate(inv, Options{})
	if len(fs) != 1 || len(fs[0].Evidence) != 1 {
		t.Fatalf("want 1 finding with 1 evidence line, got %+v", fs)
	}
	if !strings.Contains(fs[0].Evidence[0], "mutable :latest tag") {
		t.Errorf("the mutable :latest tag is the root cause, got %v", fs[0].Evidence)
	}
}

// A digest-pinned image is immutable EVEN with an accompanying :latest tag —
// the digest fixes the bytes. It must pass, and the rendered finding's caveat
// must make clear that "no finding" means "immutable by digest", not "tag-safe".
func TestMutableImageTags_DigestWithLatestTagPasses(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		imgDeploy("app", "w", "nginx:latest@sha256:0123456789abcdef0123", corev1.PullAlways),
	}}
	if fs := (MutableImageTags{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("digest-pinned image must pass even with a :latest tag, got %+v", fs)
	}
}

// The WhyItMatters caveat surfaces the digest-vs-tag distinction on any emitted
// finding, so a reader never mistakes a digest pass for a tag being safe.
func TestMutableImageTags_DigestCaveatSurfaced(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("app", "w", "nginx:latest", corev1.PullIfNotPresent)}}
	fs := MutableImageTags{}.Evaluate(inv, Options{})
	if len(fs) != 1 || !strings.Contains(fs[0].WhyItMatters, "digest-pinned image passes here even if it also carries a :latest tag") {
		t.Fatalf("WhyItMatters must carry the digest-not-tag caveat, got %+v", fs)
	}
}

func TestMutableImageTags_CleanCases(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		imgDeploy("app", "digest", "nginx@sha256:0123456789abcdef", corev1.PullAlways),          // digest-pinned: Always is harmless
		imgDeploy("app", "pinned", "nginx:1.25", corev1.PullIfNotPresent),                       // pinned, sane policy
		imgDeploy("app", "port-pinned", "registry.local:5000/app:1.2", corev1.PullIfNotPresent), // registry port must not read as tag
	}}
	if fs := (MutableImageTags{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("clean workloads must produce no findings, got %+v", fs)
	}
}

func TestMutableImageTags_RegistryPortWithoutTag(t *testing.T) {
	// The colon belongs to the registry port, not a tag — image is untagged.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("app", "w", "registry.local:5000/app", corev1.PullIfNotPresent)}}
	fs := MutableImageTags{}.Evaluate(inv, Options{})
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence[0], "no tag") {
		t.Fatalf("registry:port without tag must be flagged untagged, got %+v", fs)
	}
}

func TestMutableImageTags_InitContainerCounts(t *testing.T) {
	d := imgDeploy("app", "w", "nginx:1.25", corev1.PullIfNotPresent)
	d.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox:latest"}}
	fs := MutableImageTags{}.Evaluate(&collect.Inventory{Deployments: []appsv1.Deployment{d}}, Options{})
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence[0], "init container setup") {
		t.Fatalf("mutable tag on init container must be flagged, got %+v", fs)
	}
}

func TestMutableImageTags_SystemNamespaceSkippedByDefault(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{imgDeploy("kube-system", "sysd", "nginx:latest", corev1.PullIfNotPresent)}}
	if fs := (MutableImageTags{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default, got %+v", fs)
	}
	if fs := (MutableImageTags{}).Evaluate(inv, Options{IncludeSystem: true}); len(fs) != 1 {
		t.Fatalf("IncludeSystem must opt back in, got %d findings", len(fs))
	}
}

func TestMutableImageTags_StableDistinctIDs(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		imgDeploy("app", "a", "nginx:latest", corev1.PullIfNotPresent),
		imgDeploy("app", "b", "nginx:latest", corev1.PullIfNotPresent),
	}}
	first := MutableImageTags{}.Evaluate(inv, Options{})
	second := MutableImageTags{}.Evaluate(inv, Options{})
	if len(first) != 2 || first[0].ID == first[1].ID {
		t.Fatalf("two workloads must get distinct IDs: %+v", first)
	}
	if first[0].ID != second[0].ID || !strings.HasPrefix(first[0].ID, "f-") {
		t.Fatalf("IDs must be stable f-prefixed hashes across runs: %q vs %q", first[0].ID, second[0].ID)
	}
}
