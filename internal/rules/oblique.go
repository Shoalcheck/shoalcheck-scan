package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// oblique.go — §3 OF THE EXHAUSTIVE-COVERAGE SPEC: WHEN SOMETHING LOOKS UNREACHABLE, ASK WHAT A CONTROLLER
// WROTE DOWN ABOUT IT.
//
// The instruction for that section was to invent a way out rather than record a limit, and it has one shape,
// with four worked precedents already in this tree: EndpointSlices instead of packet visibility,
// `PDB.status.disruptionsAllowed` instead of a trial eviction, node zone labels instead of a cloud API,
// `generation` vs `observedGeneration` instead of an event history.
//
// Two walls, two routes:
//
//	IMAGE CONTENTS. Direct: needs a scanner, and this product has no scanner and refuses to grow one.
//	Oblique: `status.containerStatuses[].imageID` is the digest the kubelet ACTUALLY PULLED. Two pods of
//	one workload, one tag, two digests means the tag moved and only some pods restarted since. That is
//	entirely internal to the snapshot — no registry call, no network, nothing to be wrong about.
//
//	KUBELET AND NODE OS POSTURE. Direct: /configz and the node filesystem, out of reach forever.
//	Oblique: `Node.status.nodeInfo` carries kubelet version, kube-proxy version, container runtime, OS
//	image and kernel version, on every node, already collected and — until this file — entirely unread.
//	Sweep 0 confirmed neither Popeye nor KubeLinter nor kube-score checks version skew.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT NEITHER RULE CLAIMS
//
//	NOT THE ORIGINAL QUESTION. An oblique route answers a WEAKER question, and the value of the route is
//	entirely in being honest about which one. Nothing here says an image is vulnerable, a version is
//	unsupported, or a kubelet is unsafe — oblique_test.go bans those words outright, because a family
//	that quietly upgraded its own claim back to the unreachable one would be worse than the wall.
//
//	NO DOLLARS.

// ── Rule: replicas of one workload running different digests of one tag ──────────────────────────

// ImageDigestDrift reports a workload whose pods report more than one image digest for the same
// spec.image string.
type ImageDigestDrift struct{}

func (ImageDigestDrift) ID() string      { return "k8s.workload.image-digest-drift" }
func (ImageDigestDrift) Version() string { return "1.0.0" }

// RequiredKinds — `pods` carries both halves of the comparison. The workload kinds are load-bearing for
// the GROUPING only: without them a pod's ReplicaSet cannot be resolved to its Deployment, and the finding
// is named after a hash-suffixed ReplicaSet instead. The claim survives; the label degrades.
func (ImageDigestDrift) RequiredKinds() []string { return withWorkloads("pods") }

func (r ImageDigestDrift) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "pods") {
		return nil
	}
	type key struct{ group, container, image string }
	type obs struct {
		label   string
		ns      string
		digests map[string][]string // digest -> pod names
	}
	seen := map[key]*obs{}

	owners := newOwnerIndex(inv) // one lookup per pod, not a walk of every Deployment per pod
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		// A POD WITH NO CONTROLLER IS ITS OWN WORKLOAD. Two bare pods on two digests of one tag say
		// nothing about a workload, because there is no workload — they are two independent decisions.
		ref := controllerRef(*p)
		if ref == nil {
			continue
		}
		gk, label := podGroup(owners, inv, p)
		for _, cs := range p.Status.ContainerStatuses {
			d := digestOf(cs.ImageID)
			if d == "" {
				// AN EMPTY OR DIGESTLESS imageID IS UNKNOWN, NOT A DIFFERENT DIGEST. A container still
				// pulling has not reported one, and treating "" as a value would report drift on every
				// workload with a pod mid-start.
				continue
			}
			spec := specImageFor(p, cs.Name)
			if spec == "" || strings.Contains(spec, "@sha256:") {
				// A digest-pinned spec image cannot drift by definition, and a container status with no
				// matching spec entry is not something to reason about.
				continue
			}
			k := key{gk, cs.Name, spec}
			o := seen[k]
			if o == nil {
				o = &obs{label: label, ns: p.Namespace, digests: map[string][]string{}}
				seen[k] = o
			}
			o.digests[d] = append(o.digests[d], p.Name)
		}
	}

	var out []types.Finding
	for k, o := range seen {
		if len(o.digests) < 2 {
			continue
		}
		digests := make([]string, 0, len(o.digests))
		for d := range o.digests {
			digests = append(digests, d)
		}
		sort.Strings(digests)

		refs := []types.ResourceRef{}
		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("%s, container %q: spec image is %q, and its running pods report %d distinct "+
				"digests", o.label, k.container, k.image, len(digests)),
		}
		for _, d := range digests {
			pods := o.digests[d]
			sort.Strings(pods)
			for _, name := range pods {
				refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: o.ns, Name: name})
			}
			evidence = append(evidence, fmt.Sprintf("%s — %s: %s",
				shortDigest(d), nWord(len(pods), "pod", "pods"), strings.Join(pods, ", ")))
		}
		evidence = append(evidence,
			"the digest is what the kubelet recorded pulling; what the tag points at now is a registry "+
				"question and this reading did not ask it",
			"which digest is the newer one is not readable here either — a digest carries no ordering")

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Pod", o.ns, o.label+"|"+k.container+"|"+k.image),
			IDBasis:     &types.ResourceRef{Kind: "Pod", Namespace: o.ns, Name: o.label + "|" + k.container + "|" + k.image},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s runs %d different builds of %s",
				o.label, len(digests), k.image),
			Description: fmt.Sprintf("The pods of %s report %d distinct image digests for container %q, "+
				"whose spec image is the single tag %q. A tag is a moving pointer, so this is what a tag "+
				"looks like after it moved and only some pods restarted: the manifest says one thing, and "+
				"two different builds are running under it.",
				o.label, len(digests), k.container, k.image),
			WhyItMatters: "Every replica reads as identical in every manifest and in every dashboard that " +
				"shows the tag, so the difference is invisible from everywhere except the pod status. It " +
				"also means a restart is not a no-op: whichever pod restarts next moves to whatever the " +
				"tag points at then.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// digestOf extracts the sha256 digest from an imageID.
//
// RUNTIMES SPELL THIS DIFFERENTLY AND THE DIFFERENCE IS NOT A DIFFERENT IMAGE. containerd reports
// "repo@sha256:abc", the old dockershim reported "docker-pullable://repo@sha256:abc", and some report a
// bare digest. Comparing raw strings would report drift on any cluster mid-runtime-migration, which is the
// opposite of what this rule is for. An imageID with no digest at all returns "" and is treated as unknown.
func digestOf(imageID string) string {
	i := strings.Index(imageID, "sha256:")
	if i < 0 {
		return ""
	}
	d := imageID[i:]
	if j := strings.IndexAny(d, " \t"); j >= 0 {
		d = d[:j]
	}
	if len(d) <= len("sha256:") {
		return ""
	}
	return d
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

// specImageFor returns the pod spec's image for a container status name, checking init and ephemeral
// containers too so a status is never matched against the wrong spec entry.
func specImageFor(p *corev1.Pod, name string) string {
	for _, c := range p.Spec.Containers {
		if c.Name == name {
			return c.Image
		}
	}
	for _, c := range p.Spec.InitContainers {
		if c.Name == name {
			return c.Image
		}
	}
	return ""
}

// ── Rule: kubelets at different minor versions, and how far from the API server ──────────────────

// NodeVersionSkew reports more than one kubelet minor version across the node set, and — when the API
// server's version is readable — nodes outside the published skew window.
type NodeVersionSkew struct{}

func (NodeVersionSkew) ID() string      { return "k8s.reliability.node-version-skew" }
func (NodeVersionSkew) Version() string { return "1.0.0" }

func (NodeVersionSkew) RequiredKinds() []string { return sortedKinds([]string{"nodes"}) }

// minorVersion parses the major.minor out of a Kubernetes version string.
//
// A DISTRIBUTION SUFFIX IS NOT A DIFFERENT VERSION. "v1.31.2", "v1.31.2+k3s1" and "v1.31.2-eks-1a2b3c" are
// one minor version wearing three vendors' labels, and every managed provider ships one of these — so the
// parse stops at the minor component and never compares the rest. A PATCH DIFFERENCE IS NOT A SKEW EITHER:
// v1.31.2 beside v1.31.7 is an ordinary rolling node replacement, and a rule comparing whole strings would
// fire on every cluster that has ever replaced a node.
var versionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)`)

func minorVersion(s string) (major, minor int, ok bool) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(m[1])
	min, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	// A KUBERNETES VERSION HAS A MAJOR OF AT LEAST 1, and "0.0.0-master+$Format:%H$" is the placeholder a
	// binary built without version stamping reports — the fake clientset returns exactly that, and so does
	// anything behind a proxy that rewrites the discovery response. Parsing it as major 0 would make every
	// real kubelet "newer than the API server", which is a confident sentence built on a placeholder.
	if maj < 1 {
		return 0, 0, false
	}
	return maj, min, true
}

func (r NodeVersionSkew) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "nodes") {
		return nil
	}
	type nodeVer struct {
		name         string
		raw          string
		major, minor int
	}
	var parsed []nodeVer
	var unparsed []string
	byMinor := map[string][]string{}
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		raw := n.Status.NodeInfo.KubeletVersion
		maj, min, ok := minorVersion(raw)
		if !ok {
			// A VERSION STRING THIS RULE CANNOT PARSE IS COUNTED, NOT JUDGED. It is somebody's build, and
			// guessing at it would be inventing a fact about their cluster.
			unparsed = append(unparsed, n.Name)
			continue
		}
		parsed = append(parsed, nodeVer{n.Name, raw, maj, min})
		k := fmt.Sprintf("%d.%d", maj, min)
		byMinor[k] = append(byMinor[k], n.Name)
	}
	if len(byMinor) < 2 {
		// One minor version across every node it could read is the ordinary state, and it stays the
		// ordinary state whether or not some node's version string was unreadable.
		return nil
	}

	minors := make([]string, 0, len(byMinor))
	for k := range byMinor {
		minors = append(minors, k)
	}
	sort.Strings(minors)

	evidence := []string{
		snapshotNote(inv),
		fmt.Sprintf("%s report %d distinct kubelet minor versions: %s", nWord(len(parsed), "node", "nodes"), len(minors), strings.Join(minors, ", ")),
	}
	refs := []types.ResourceRef{}
	for _, m := range minors {
		names := byMinor[m]
		sort.Strings(names)
		for _, n := range names {
			refs = append(refs, types.ResourceRef{Kind: "Node", Name: n})
		}
		evidence = append(evidence, fmt.Sprintf("v%s — %s: %s", m, nWord(len(names), "node", "nodes"), strings.Join(names, ", ")))
	}
	if len(unparsed) > 0 {
		sort.Strings(unparsed)
		evidence = append(evidence, fmt.Sprintf("%s report a kubelet version this reading could "+
			"not parse and which is therefore not counted above: %s", nWord(len(unparsed), "node", "nodes"), strings.Join(unparsed, ", ")))
	}

	severity := types.SeverityLow
	windowNote := ""
	if smaj, smin, ok := minorVersion(inv.Meta.ServerVersion); ok {
		// THE PUBLISHED WINDOW, AND IT WIDENED AT 1.28. kubelet may be up to three minor versions older
		// than kube-apiserver from 1.28 onward, and two before that; a kubelet NEWER than the API server
		// has never been supported at any version. Both numbers are stated in the evidence rather than
		// applied silently, because the reader has to be able to check the arithmetic.
		allowed := 2
		if smaj > 1 || (smaj == 1 && smin >= 28) {
			allowed = 3
		}
		var behind, ahead []string
		for _, nv := range parsed {
			switch {
			case nv.major > smaj || (nv.major == smaj && nv.minor > smin):
				ahead = append(ahead, fmt.Sprintf("%s (%s)", nv.name, nv.raw))
			case nv.major == smaj && smin-nv.minor > allowed:
				behind = append(behind, fmt.Sprintf("%s (%s)", nv.name, nv.raw))
			}
		}
		sort.Strings(behind)
		sort.Strings(ahead)
		evidence = append(evidence, fmt.Sprintf("the API server reports %s, and the published skew window "+
			"for this server version allows a kubelet up to %s older; a kubelet newer "+
			"than the API server is outside the window at every version",
			inv.Meta.ServerVersion, nWord(allowed, "minor version", "minor versions")))
		if len(behind) > 0 {
			severity = types.SeverityMedium
			windowNote = fmt.Sprintf(", and %d of them are further behind the API server than that window allows", len(behind))
			evidence = append(evidence, fmt.Sprintf("outside the window, older: %s", strings.Join(behind, ", ")))
		}
		if len(ahead) > 0 {
			severity = types.SeverityMedium
			evidence = append(evidence, fmt.Sprintf("outside the window, newer than the API server: %s",
				strings.Join(ahead, ", ")))
		}
	} else {
		// WITHHOLD THE WINDOW CLAIM, NOT THE SPREAD. The spread is readable from the nodes alone; only the
		// comparison against the control plane needs a number this reading did not get.
		evidence = append(evidence, "the API server version was not readable in this run, so how far any "+
			"node sits from the published skew window is not stated here; the spread above is read from "+
			"the nodes alone")
	}

	// A runtime or OS spread is a fact about the same nodes and belongs in the same finding rather than in
	// a second rule that would fire on exactly the same clusters.
	if s := spreadOf(inv, func(n corev1.NodeSystemInfo) string { return n.ContainerRuntimeVersion }); len(s) > 1 {
		evidence = append(evidence, fmt.Sprintf("container runtimes across the same nodes: %s",
			strings.Join(s, ", ")))
	}
	if s := spreadOf(inv, func(n corev1.NodeSystemInfo) string { return n.OSImage }); len(s) > 1 {
		evidence = append(evidence, fmt.Sprintf("node OS images across the same nodes: %s", strings.Join(s, ", ")))
	}

	return []types.Finding{{
		ID:          findingID(r.ID(), "Node", "", strings.Join(minors, ",")),
		IDBasis:     &types.ResourceRef{Kind: "Node", Namespace: "", Name: strings.Join(minors, ",")},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("Nodes report %d different kubelet minor versions (%s)",
			len(minors), strings.Join(minors, ", ")),
		Description: fmt.Sprintf("The %s whose kubelet version this reading could parse report %d "+
			"distinct minor versions — %s%s. This is read from Node.status.nodeInfo, which is what each "+
			"kubelet published about itself; it says nothing about how those nodes are configured, which "+
			"is not readable without reaching the node.", nWord(len(parsed), "node", "nodes"), len(minors), strings.Join(minors, ", "), windowNote),
		WhyItMatters: "A mixed node fleet means a workload's behaviour depends on which node it lands " +
			"on, and the difference is invisible in every manifest. It is also the state a half-finished " +
			"node upgrade leaves behind, which tends to be discovered by the next upgrade rather than by " +
			"anyone looking.",
		Evidence:          evidence,
		Severity:          severity,
		Category:          types.CategoryReliability,
		AffectedResources: refs,
		EstimatedEffort:   types.EffortHigh,
		Confidence:        1.0,
		Provenance:        provenance(),
	}}
}

// spreadOf returns the sorted distinct values of one nodeInfo field across the node set.
func spreadOf(inv *collect.Inventory, f func(corev1.NodeSystemInfo) string) []string {
	set := map[string]bool{}
	for i := range inv.Nodes {
		if v := strings.TrimSpace(f(inv.Nodes[i].Status.NodeInfo)); v != "" {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
