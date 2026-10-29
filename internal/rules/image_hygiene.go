package rules

import (
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// MutableImageTags flags container images whose bytes can silently change
// between pulls. Two distinct strengths of evidence are reported, and they are
// NOT treated the same:
//
//   - A literally-mutable reference — a ":latest" tag or an untagged image
//     (implicit ":latest"). This is a verified defect: the bytes WILL drift.
//   - A floating tag pulled with imagePullPolicy=Always — a tag like :stable,
//     :main, :prod, or a bare major (:1) that re-resolves on every pod start.
//     This is an inference: a re-tag during a rollout CAN race, but the rule
//     cannot prove the tag is re-pushed, so it is reported at lower severity
//     and confidence and worded as "verify", not "this is broken".
//
// Digest-pinned images (@sha256:...) are immutable and always pass, EVEN when
// an accompanying tag reads as :latest — the digest, not the tag, fixes the
// bytes. "No finding" on such a workload means "immutable by digest", not
// "the tag is safe": dropping the digest later silently re-mutates it.
//
// Tags that look like an immutable version pin (a dotted semver such as 1.25.3
// or v2.1, or a hex/sha-like string) are treated as pinned and pass under any
// pull policy. One finding per workload; the workload's strongest offense sets
// its severity, confidence, and remediation.
type MutableImageTags struct{}

func (MutableImageTags) ID() string { return "k8s.workload.mutable-image-tags" }

// 1.2.0 (2026-10-21): judges every pod spec the cluster runs — bare Pods, Jobs and CronJobs too (podTemplates).
func (MutableImageTags) Version() string { return "1.2.0" }

// offenseKind ranks image-hygiene problems by how certain the defect is.
type offenseKind int

const (
	offenseNone           offenseKind = iota
	offenseFloatingAlways             // pinned-looking-but-floating tag + Always: an INFERENCE
	offenseMutableRef                 // :latest or untagged: a VERIFIED mutable reference
)

func (r MutableImageTags) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, w := range podTemplates(inv, opts) {
		var evidence []string
		worst := offenseNone
		check := func(label string, cs []corev1.Container) {
			for _, c := range cs {
				if kind, line := imageOffense(c); kind != offenseNone {
					evidence = append(evidence, fmt.Sprintf("%s %s: %s", label, c.Name, line))
					if kind > worst {
						worst = kind
					}
				}
			}
		}
		check("container", w.PodSpec.Containers)
		check("init container", w.PodSpec.InitContainers)
		if len(evidence) == 0 {
			continue
		}

		severity, confidence := calibrateImageOffense(worst)
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Pin mutable image references on %s/%s", w.Namespace, w.Name),
			Description: fmt.Sprintf(
				"%s %s/%s has %s that can resolve to different bytes on different pulls. The same manifest may then run different code across nodes or after a restart, which breaks rollbacks and makes incident forensics guesswork. %s",
				w.Kind, w.Namespace, w.Name, nWord(len(evidence), "image reference", "image references"), imageRemediationGuidance(worst)),
			WhyItMatters:       "Mutable image references make deploys non-reproducible — during an incident, 'what exactly is running' becomes harder to answer. (A digest-pinned image passes here even if it also carries a :latest tag; the digest, not the tag, fixes the bytes.)",
			Evidence:           evidence,
			Severity:           severity,
			Category:           types.CategoryConfig,
			AffectedResources:  []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:    types.EffortLow,
			RemediationCommand: imagesCommand(w),
			Confidence:         confidence,
			Provenance:         provenance(),
		})
	}
	return out
}

// calibrate sets severity/confidence from the workload's strongest offense.
// A literally-mutable reference (:latest/untagged) is a verified defect; an
// Always-on-floating-tag is only an inference that a race CAN occur, so it is
// reported at Low severity and reduced confidence.
func calibrateImageOffense(k offenseKind) (types.Severity, float64) {
	switch k {
	case offenseMutableRef:
		// The reference is mutable by construction — :latest/untagged WILL drift.
		return types.SeverityMedium, 0.9
	case offenseFloatingAlways:
		// Whether a race ever occurs depends on facts the read-only API cannot
		// see (is the tag actually re-pushed? mid-rollout?). Report as a hint.
		return types.SeverityLow, 0.4
	default:
		return types.SeverityLow, 0.4
	}
}

// remediationGuidance returns advice matched to the offense, never a blanket
// "switch to IfNotPresent" — that instruction is unsafe for a floating tag
// (nodes that already cached the tag keep stale bytes forever, and new pushes
// never roll out), which is the very non-reproducibility this rule warns about.
func imageRemediationGuidance(k offenseKind) string {
	switch k {
	case offenseMutableRef:
		return "Pin a specific version tag or, for true immutability, a digest (@sha256:…). On a genuinely fixed tag, imagePullPolicy=IfNotPresent is then safe."
	case offenseFloatingAlways:
		return "Verify each flagged tag is actually immutable. If it is a fixed version, IfNotPresent is safe and Always is unnecessary churn; if it is a floating/release-channel tag, do NOT switch to IfNotPresent (nodes would keep stale bytes) — pin a digest instead, or keep Always and accept the re-pull."
	default:
		return "Pin a specific version tag or a digest."
	}
}

// imageOffense classifies a container's image hygiene problem and returns one
// evidence clause, or (offenseNone, "") when the reference is safe. Exactly one
// root cause is reported per container: a mutable reference subsumes any
// pull-policy concern.
func imageOffense(c corev1.Container) (offenseKind, string) {
	if strings.Contains(c.Image, "@") {
		return offenseNone, "" // digest-pinned — immutable regardless of tag or pull policy
	}
	tag, ok := imageTag(c.Image)
	switch {
	case !ok:
		return offenseMutableRef, fmt.Sprintf("image %s (no tag — resolves to mutable :latest)", c.Image)
	case tag == "latest":
		return offenseMutableRef, fmt.Sprintf("image %s (mutable :latest tag)", c.Image)
	case c.ImagePullPolicy != corev1.PullAlways:
		return offenseNone, "" // pinned-looking tag, sane policy — nothing to flag
	case imageTagLooksImmutable(tag):
		// A version-pinned tag (1.25.3, v2.1, a sha-like digest string) is
		// treated as immutable; Always is just redundant churn, not a defect.
		return offenseNone, ""
	default:
		// Floating/release-channel tag (stable, main, prod, bare major, …)
		// re-pulled on every start. A re-tag mid-rollout CAN race — but we
		// have not proven the tag is mutable, so this is a hint, not a verdict.
		return offenseFloatingAlways, fmt.Sprintf(
			"imagePullPolicy=Always on tag %s — if %q is a floating/re-pushed tag, a re-tag during a rollout can run mixed bytes; verify it is immutable", c.Image, tag)
	}
}

// semverishTag matches tags that look like an immutable version pin:
// an optional leading v, then a dotted numeric version (1, 1.2, 1.2.3),
// optionally followed by a pre-release/build suffix (-rc1, +build, _suffix).
// A BARE major like "1" is intentionally NOT matched as immutable here — bare
// majors are commonly floating ("track the latest 1.x"), so they fall through
// to the floating-tag path and earn a "verify it is immutable" hint.
var semverishTag = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?([.\-+_].+)?$`)

// shaLikeTag matches a long lower-hex string sometimes used as an immutable
// content/commit tag (e.g. a git SHA or build hash baked into the tag).
var shaLikeTag = regexp.MustCompile(`^[0-9a-f]{12,}$`)

// imageTagLooksImmutable reports whether a tag is shaped like a fixed version pin
// rather than a moving release channel. Known floating tokens are explicitly
// rejected even if some future pattern would otherwise admit them.
func imageTagLooksImmutable(tag string) bool {
	switch strings.ToLower(tag) {
	case "latest", "stable", "edge", "main", "master", "prod", "production",
		"dev", "develop", "nightly", "release", "current", "canary", "beta", "alpha":
		return false
	}
	return semverishTag.MatchString(tag) || shaLikeTag.MatchString(tag)
}

// imageTag extracts the tag from an image reference, treating a colon inside
// the registry host (e.g. registry.local:5000/app) as NOT a tag: only a colon
// after the last path slash separates the tag.
func imageTag(image string) (tag string, ok bool) {
	colon := strings.LastIndex(image, ":")
	if colon <= strings.LastIndex(image, "/") {
		return "", false
	}
	return image[colon+1:], true
}

// RequiredKinds — Image references come from the pod templates.
// See deps.go for what belongs in this list.
func (r MutableImageTags) RequiredKinds() []string { return podTemplateKinds() }

// imagesCommand prints the object's image references from where its pod spec lives.
func imagesCommand(w workload) string {
	return fmt.Sprintf("kubectl -n %s get %s %s -o jsonpath='{%s.containers[*].image}'",
		w.Namespace, strings.ToLower(w.Kind), w.Name, w.templatePath())
}
