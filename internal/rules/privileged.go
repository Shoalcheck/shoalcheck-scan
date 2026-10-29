package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// PrivilegedHostAccess flags workloads that request privileged containers,
// host namespaces (network/PID/IPC), hostPath volumes, or hostPorts — most of
// these are a bridge from "compromised container" to "compromised node". One
// finding per workload, aggregating every offense as its own evidence line.
//
// Severity is NOT flat: it is driven by the most dangerous offense observed
// (see offenseTier). A lone hostPort or a read-only/scoped hostPath is a
// hardening note (Medium), not the node-takeover primitive that privileged=true
// or a writable docker.sock mount is (High).
type PrivilegedHostAccess struct{}

func (PrivilegedHostAccess) ID() string { return "k8s.workload.privileged-host-access" }

// Version 1.2.0: severity now tiered by offense type (was flat High);
// hostPath evidence cross-checks container VolumeMounts and surfaces
// readOnly + HostPathType; well-known node-infrastructure workloads are
// down-ranked and tagged rather than reported as misconfigurations.
//
// Version 1.1.0 (P2): added PSS-Baseline B5 detection — c.Ports[].HostPort != 0
// binds a port directly on the node, bypassing Service abstraction and exposing
// the workload on every node it lands on.
// 1.3.0 (2026-10-21): judges every pod spec the cluster runs — bare Pods, Jobs and CronJobs too (podTemplates).
func (PrivilegedHostAccess) Version() string { return "1.3.0" }

// offenseTier ranks how dangerous an individual offense is. High = a real
// container-escape-to-node primitive; Medium = a hardening / blast-radius note
// that does not by itself grant node compromise.
type offenseTier int

const (
	tierNone offenseTier = iota
	tierMedium
	tierHigh
)

// sensitiveHostPaths are mount targets where a hostPath (especially writable)
// is a node-root primitive rather than a benign metrics scrape. Prefix match.
var sensitiveHostPaths = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/crio/crio.sock",
	"/run/containerd/containerd.sock",
	"/var/run/containerd",
	"/var/lib/kubelet",
	"/var/lib/docker",
	"/etc/kubernetes",
	"/etc",
	"/root",
	"/", // bare-root mount
}

func isSensitiveHostPath(p string) bool {
	clean := strings.TrimRight(p, "/")
	if clean == "" {
		// "/" trims to "" — a bare-root mount is the most sensitive of all.
		return true
	}
	for _, s := range sensitiveHostPaths {
		st := strings.TrimRight(s, "/")
		if st == "" {
			continue
		}
		if clean == st || strings.HasPrefix(clean+"/", st+"/") {
			return true
		}
	}
	return false
}

// hostPathMountInfo locates the container VolumeMount(s) that reference a volume
// by name, returning whether it is mounted at all and whether read-only.
// readOnly is true only when the volume is mounted AND every mount is read-only;
// a single writable mount makes the effective access writable.
func hostPathMountInfo(spec corev1.PodSpec, volName string) (mounted, readOnly bool) {
	first := true
	scan := func(cs []corev1.Container) {
		for _, c := range cs {
			for _, m := range c.VolumeMounts {
				if m.Name != volName {
					continue
				}
				mounted = true
				if first {
					readOnly = m.ReadOnly
					first = false
				} else if !m.ReadOnly {
					readOnly = false
				}
			}
		}
	}
	scan(spec.Containers)
	scan(spec.InitContainers)
	return mounted, readOnly
}

// infraSignal returns a non-empty human label when the workload matches a
// well-known node-infrastructure pattern (CNI/CSI/node agents) that LEGITIMATELY
// requires privileged/host access. Used to down-rank and tag, never to suppress —
// the operator still sees the grant, just not as a "fix this" High.
func infraSignal(w workload) string {
	labels := w.PodLabels
	get := func(k string) string { return strings.ToLower(labels[k]) }
	name := strings.ToLower(get("app.kubernetes.io/name") + " " + get("app.kubernetes.io/managed-by") +
		" " + get("app") + " " + get("k8s-app") + " " + strings.ToLower(w.Name))

	infraKeywords := []string{
		"calico", "cilium", "flannel", "weave", "kube-proxy", "aws-node",
		"csi", "ebs", "efs", "node-exporter", "nvidia", "device-plugin",
		"longhorn", "rook", "ceph", "fluent", "fluentbit", "fluent-bit",
		"datadog-agent", "newrelic", "falco",
	}
	for _, kw := range infraKeywords {
		if strings.Contains(name, kw) {
			return kw
		}
	}
	// A DaemonSet is the canonical node-agent shape: one pod pinned per node.
	// On its own this is a weaker signal, but combined with host access it is a
	// strong hint the workload IS node infrastructure.
	if w.Kind == "DaemonSet" {
		return "DaemonSet (node-agent shape)"
	}
	return ""
}

func (r PrivilegedHostAccess) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, w := range podTemplates(inv, opts) {
		ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
		var evidence []string

		// tier tracks the most dangerous offense seen so severity reflects the
		// real escape primitive, not the mere presence of any host access.
		tier := tierNone
		bump := func(t offenseTier) {
			if t > tier {
				tier = t
			}
		}
		// hasNodeTakeover stays true only if a genuine node-compromise primitive
		// fired — used to keep the "full node compromise" wording honest.
		hasNodeTakeover := false

		addPrivileged := func(label string, cs []corev1.Container) {
			for _, c := range cs {
				if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					evidence = append(evidence, fmt.Sprintf("%s %s in %s: privileged=true", label, c.Name, ref))
					bump(tierHigh)
					hasNodeTakeover = true
				}
			}
		}
		addPrivileged("container", w.PodSpec.Containers)
		addPrivileged("init container", w.PodSpec.InitContainers)

		// PSS-Baseline B5: a hostPort binds the container's port directly on the
		// node, bypassing the Service layer and exposing the workload on every
		// node it schedules onto. This is a blast-radius / exposure note, NOT a
		// node-takeover primitive — it stays Medium on its own.
		addHostPorts := func(label string, cs []corev1.Container) {
			for _, c := range cs {
				for _, p := range c.Ports {
					if p.HostPort != 0 {
						evidence = append(evidence, fmt.Sprintf("%s %s in %s: hostPort=%d (binds port on the node, bypasses Service)", label, c.Name, ref, p.HostPort))
						bump(tierMedium)
					}
				}
			}
		}
		addHostPorts("container", w.PodSpec.Containers)
		addHostPorts("init container", w.PodSpec.InitContainers)

		if w.PodSpec.HostNetwork {
			evidence = append(evidence, fmt.Sprintf("%s: hostNetwork=true", ref))
			bump(tierHigh)
			hasNodeTakeover = true
		}
		if w.PodSpec.HostPID {
			evidence = append(evidence, fmt.Sprintf("%s: hostPID=true", ref))
			bump(tierHigh)
			hasNodeTakeover = true
		}
		if w.PodSpec.HostIPC {
			evidence = append(evidence, fmt.Sprintf("%s: hostIPC=true", ref))
			bump(tierHigh)
			hasNodeTakeover = true
		}

		// hostPath: only a wired-in mount is an actual attack surface. Cross-check
		// container VolumeMounts so a declared-but-unmounted volume (refactor
		// leftover, disabled Helm path) is not presented as live access. Surface
		// readOnly + HostPathType so a read-only /sys scrape isn't rated like a
		// writable docker.sock. Severity is driven by writability + path
		// sensitivity, not by the bare presence of a hostPath.
		for _, v := range w.PodSpec.Volumes {
			if v.HostPath == nil {
				continue
			}
			mounted, readOnly := hostPathMountInfo(w.PodSpec, v.Name)
			hpType := ""
			if v.HostPath.Type != nil {
				hpType = string(*v.HostPath.Type)
			}

			var qual []string
			if !mounted {
				qual = append(qual, "declared, not mounted by any container")
			} else if readOnly {
				qual = append(qual, "read-only mount")
			} else {
				qual = append(qual, "writable mount")
			}
			if hpType != "" {
				qual = append(qual, "type="+hpType)
			}
			evidence = append(evidence, fmt.Sprintf("volume %s: hostPath %s (%s)", v.Name, v.HostPath.Path, strings.Join(qual, ", ")))

			switch {
			case !mounted:
				// Not wired into any container — informational only, no tier bump.
			case !readOnly && isSensitiveHostPath(v.HostPath.Path):
				// Writable mount of a node-root path (docker.sock, /, /etc, kubelet).
				bump(tierHigh)
				hasNodeTakeover = true
			case !readOnly:
				// Writable but on a non-sensitive path: real but scoped.
				bump(tierMedium)
			default:
				// Read-only mount: materially lower risk regardless of path.
				bump(tierMedium)
			}
		}

		if len(evidence) == 0 {
			continue
		}

		// Node-infrastructure down-rank: CNI/CSI/node-exporter/etc legitimately
		// need this access. Tag it as expected and cap severity so a normal prod
		// cluster doesn't drown in High findings for correctly-configured agents.
		infra := infraSignal(w)
		severity := tierSeverity(tier)
		confidence := 1.0 // presence of the field is certain; see comment below.
		if infra != "" {
			evidence = append([]string{fmt.Sprintf(
				"NOTE: matches a well-known node-infrastructure pattern (%s) — host/privileged access is expected for this class of workload; verify it is the agent it appears to be before treating as a misconfiguration.",
				infra)}, evidence...)
			if severity == types.SeverityHigh {
				severity = types.SeverityLow
			} else {
				severity = types.SeverityInfo
			}
			// We are confident the GRANT exists (1.0) but NOT that it is a
			// problem — the workload looks like legitimate node infra.
			confidence = 0.3
		}

		out = append(out, types.Finding{
			ID:                 findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:            &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:             r.ID(),
			RuleVersion:        r.Version(),
			Title:              privTitle(w, infra),
			Description:        privDescription(ref, len(evidence), infra),
			WhyItMatters:       privWhyItMatters(hasNodeTakeover, infra),
			Evidence:           evidence,
			Severity:           severity,
			Category:           types.CategorySecurity,
			AffectedResources:  []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:    types.EffortMedium,
			RemediationCommand: privRemediationCommand(w),
			// Confidence here is "certainty THIS IS A PROBLEM", not "I read the
			// field". The grant is a literal spec fact, but for a node-infra
			// match the grant is expected, so confidence drops to 0.3.
			Confidence: confidence,
			Provenance: provenance(),
		})
	}
	return out
}

func tierSeverity(t offenseTier) types.Severity {
	switch t {
	case tierHigh:
		return types.SeverityHigh
	case tierMedium:
		return types.SeverityMedium
	default:
		// Reached only when the sole offense was an unmounted hostPath.
		return types.SeverityLow
	}
}

func privTitle(w workload, infra string) string {
	if infra != "" {
		return fmt.Sprintf("Confirm host access is expected for %s/%s", w.Namespace, w.Name)
	}
	return fmt.Sprintf("Remove privileged host access from %s/%s", w.Namespace, w.Name)
}

func privDescription(ref string, n int, infra string) string {
	base := fmt.Sprintf(
		"%s requests privileged or host-level access (%s: see evidence). Unless this workload IS node infrastructure (CNI, runtime agent, node exporter, CSI driver), drop privileged:true from container securityContexts, set hostNetwork/hostPID/hostIPC to false, and replace hostPath volumes with PVCs, ConfigMaps, or the downward API. The fix is app-specific, so no generic patch is offered — the command below pinpoints each offending line. Read-only and type-scoped hostPath mounts are materially lower risk than writable mounts of sensitive paths (e.g. docker.sock, /, /etc) — see the per-volume evidence for which kind each is.",
		ref, nWord(n, "item", "items"))
	if infra != "" {
		base += fmt.Sprintf(" This workload matches a known node-infrastructure pattern (%s); for those, host/privileged access is by design and removing it will break the agent — this finding is informational, confirm rather than remediate.", infra)
	}
	return base
}

func privWhyItMatters(hasNodeTakeover bool, infra string) string {
	if infra != "" {
		return "Node agents (CNI, CSI, metrics/log collectors) need host access to do their job; the risk is only if this is NOT actually such an agent. Confirm identity rather than stripping access blindly."
	}
	if hasNodeTakeover {
		return "Privileged containers, host namespaces, and writable mounts of sensitive host paths turn any container escape into full node compromise — one breached pod then owns every workload and credential on that node."
	}
	// Only Medium-tier offenses (lone hostPort, scoped/read-only hostPath) fired.
	return "Binding a port on the node or mounting host paths widens the workload's blast radius and node coupling; it is worth tightening, but on its own it does not grant node compromise."
}

func privRemediationCommand(w workload) string {
	return fmt.Sprintf(
		"kubectl -n %s get %s %s -o yaml | grep -nE 'privileged|hostNetwork|hostPID|hostIPC|hostPath|hostPort|readOnly'",
		w.Namespace, strings.ToLower(w.Kind), w.Name)
}

// RequiredKinds — Reads pod templates and nothing else.
// See deps.go for what belongs in this list.
func (r PrivilegedHostAccess) RequiredKinds() []string { return podTemplateKinds() }
