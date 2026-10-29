package redact

import (
	"regexp"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// shapes.go — THE NAMES NO STRUCTURED FIELD CARRIES, scrubbed by the position the product writes them in.
//
// The replacer in redact.go tokenizes the identifiers the report's structured fields name, and that is the
// reliable source: a name a field carries is a name the replacer knows. Five kinds of name reach the prose and the
// patches without ever being in such a field, and a live redacted reading of the mesh testbed carried all five:
//
//   - a container's name — `- name: kube-state-metrics` in a remediation patch, "container sleeper in …";
//   - a ServiceAccount's name in a binding's evidence — "names ServiceAccount ns-e10f34/local-path-…-account";
//   - a pod's label map — "map[app.kubernetes.io/instance:shoalcheck-prom …]": a Helm release name is
//     usually the application's, and a label key's domain is the organisation's;
//   - a Prometheus job label — `job="…"`, which a Helm chart builds from the release name;
//   - an image reference — harmless for `busybox:1.36`, and the AWS account id itself for a private ECR image.
//
// So each is recognised by its SHAPE and replaced with a token from the same hash the names use, which keeps two
// redacted readings of one cluster comparable. Public vocabulary survives on purpose: a label KEY Kubernetes
// defines, a job Kubernetes ships, an official single-name image, an environment variable's name in a patch. The
// bias is the redactor's own: a shape this does not recognise passes through, so a new rule that writes a name
// in a new position must come with a shape here — TestReport_ScrubsTheNamesNoStructuredFieldCarries is where.

var (
	// "container sleeper in Deployment …", "pod x/y container app: …".
	containerBare = regexp.MustCompile(`\bcontainer ([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)( in |:)`)
	// `container "app"`, the %q form.
	containerQuoted = regexp.MustCompile(`\bcontainer "([^"]+)"`)
	// "ServiceAccount <ns>/<name>" in a binding's evidence or a finding's title.
	serviceAccount = regexp.MustCompile(`\bServiceAccount ([^\s/]+)/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)
	// "map[k:v k:v]", the %v of a label selector.
	labelMap = regexp.MustCompile(`map\[([^\]]*)\]`)
	// job="…", the Prometheus scrape job a down target belongs to.
	promJob = regexp.MustCompile(`\bjob="([^"]+)"`)
	// image "…", image is "…", and the unquoted "image foo/bar:1 (…)".
	imageQuoted = regexp.MustCompile(`\bimage (is )?"([^"]+)"`)
	imageBare   = regexp.MustCompile(`\bimage ([^\s"(]+) \(`)
	// "containers with no explicit requests: <workload>/<container>, …" — the governance rule's list.
	containerList = regexp.MustCompile(`(containers with no explicit requests: )([^"\n]*)`)
	// An already-minted token: re-tokenizing one would give one name two tokens in one document.
	alreadyToken = regexp.MustCompile(`^[a-z]+-[0-9a-f]{6}$`)
)

// notContainerNames are words a sentence can put after "container" that are not names.
var notContainerNames = map[string]bool{"image": true, "runtime": true, "escape": true, "that": true, "which": true,
	"is": true, "has": true, "spec": true, "level": true}

// kubernetesJobs are the scrape jobs a stock control plane and kubelet answer as. Like kubernetesOwnGroup, a closed
// set present on every cluster — it identifies nobody, and the job names a reader needs to act on are these.
var kubernetesJobs = map[string]bool{"apiserver": true, "kube-apiserver": true, "kubelet": true, "kube-proxy": true,
	"kube-controller-manager": true, "kube-scheduler": true, "kube-etcd": true, "etcd": true, "coredns": true,
	"kube-dns": true}

func shapeToken(prefix, val string) string {
	if alreadyToken.MatchString(val) {
		return val
	}
	return token(prefix, val)
}

// scrubShapes replaces the five shapes in one string.
func scrubShapes(s string) string {
	if s == "" {
		return s
	}
	// EACH PATTERN IS GUARDED BY THE LITERAL IT CANNOT MATCH WITHOUT. Most of them begin with \b, which turns off
	// package regexp's literal-prefix scan, so every pattern ran its backtracker over every string of every
	// finding — on a 2,000-node cluster's reading, 1.7 of the 3.5 seconds --redact took. The guard reads the string
	// as it stands at that step, so a replacement made by an earlier pattern is seen exactly as before.
	if strings.Contains(s, "container ") {
		s = containerBare.ReplaceAllStringFunc(s, func(m string) string {
			sub := containerBare.FindStringSubmatch(m)
			if notContainerNames[sub[1]] {
				return m
			}
			return "container " + shapeToken("ctr", sub[1]) + sub[2]
		})
	}
	if strings.Contains(s, "containers with no explicit requests: ") {
		s = containerList.ReplaceAllStringFunc(s, func(m string) string {
			sub := containerList.FindStringSubmatch(m)
			items := strings.Split(sub[2], ", ")
			for i, it := range items {
				if w, c, ok := strings.Cut(it, "/"); ok {
					// The cap's "(+3 more)" rides on the last item and is the product's own words.
					c, more, _ := strings.Cut(c, " ")
					if more != "" {
						more = " " + more
					}
					items[i] = w + "/" + shapeToken("ctr", c) + more
				}
			}
			return sub[1] + strings.Join(items, ", ")
		})
	}
	if strings.Contains(s, `container "`) {
		s = containerQuoted.ReplaceAllStringFunc(s, func(m string) string {
			return `container "` + shapeToken("ctr", containerQuoted.FindStringSubmatch(m)[1]) + `"`
		})
	}
	if strings.Contains(s, "ServiceAccount ") {
		s = serviceAccount.ReplaceAllStringFunc(s, func(m string) string {
			sub := serviceAccount.FindStringSubmatch(m)
			ns, name := sub[1], sub[2]
			// The ServiceAccounts Kubernetes ships live in the namespaces it reserves, and identify nobody — the same
			// guard bareSubjectName makes for an RBAC subject.
			if types.KubernetesOwnNamespace(ns) || name == "default" {
				return m
			}
			return "ServiceAccount " + ns + "/" + shapeToken("sa", name)
		})
	}
	if strings.Contains(s, "map[") {
		s = labelMap.ReplaceAllStringFunc(s, func(m string) string {
			inner := labelMap.FindStringSubmatch(m)[1]
			pairs := strings.Fields(inner)
			for i, kv := range pairs {
				k, v, ok := strings.Cut(kv, ":")
				if !ok {
					pairs[i] = shapeToken("lbl", kv)
					continue
				}
				pairs[i] = labelKey(k) + ":" + shapeToken("lbl", v)
			}
			return "map[" + strings.Join(pairs, " ") + "]"
		})
	}
	if strings.Contains(s, `job="`) {
		s = promJob.ReplaceAllStringFunc(s, func(m string) string {
			job := promJob.FindStringSubmatch(m)[1]
			if kubernetesJobs[job] {
				return m
			}
			return `job="` + shapeToken("job", job) + `"`
		})
	}
	if strings.Contains(s, "image ") {
		s = imageQuoted.ReplaceAllStringFunc(s, func(m string) string {
			sub := imageQuoted.FindStringSubmatch(m)
			return "image " + sub[1] + `"` + imageRef(sub[2]) + `"`
		})
	}
	if strings.Contains(s, "image ") {
		s = imageBare.ReplaceAllStringFunc(s, func(m string) string {
			return "image " + imageRef(imageBare.FindStringSubmatch(m)[1]) + " ("
		})
	}
	return s
}

// labelKey keeps a key Kubernetes defines and a bare key, and tokenizes the domain of any other: a key's prefix
// is a DNS name its author owns, and "acme.example/team" names the organisation.
func labelKey(k string) string {
	prefix, name, ok := strings.Cut(k, "/")
	if !ok {
		return k
	}
	if prefix == "kubernetes.io" || prefix == "k8s.io" || strings.HasSuffix(prefix, ".kubernetes.io") ||
		strings.HasSuffix(prefix, ".k8s.io") {
		return k
	}
	return shapeToken("lbl", prefix) + "/" + name
}

// imageRef keeps an official single-name image ("busybox:1.36", "nginx") and tokenizes the repository of any other,
// keeping its tag or digest: the repository names a registry and an organisation — for a private ECR image, the AWS
// account id — while the tag is a version that names nobody.
func imageRef(ref string) string {
	repo, suffix := ref, ""
	if i := strings.Index(repo, "@"); i >= 0 {
		repo, suffix = repo[:i], repo[i:]
	}
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo, suffix = repo[:i], repo[i:]+suffix
	}
	if !strings.Contains(repo, "/") || strings.HasPrefix(repo, "library/") {
		return ref
	}
	return shapeToken("img", repo) + suffix
}

// scrubPatchContainers tokenizes the container names in a remediation patch: the `- name:` items directly under a
// `containers:` or `initContainers:` key, and nothing else — an environment variable's `- name:` is the patch's own
// content, and tokenizing it would make the patch wrong.
func scrubPatchContainers(y string) string {
	if y == "" {
		return y
	}
	lines := strings.Split(y, "\n")
	listIndent := -1 // the indentation of the container items, while inside a containers list
	for i, l := range lines {
		trimmed := strings.TrimLeft(l, " ")
		indent := len(l) - len(trimmed)
		if trimmed == "containers:" || trimmed == "initContainers:" {
			listIndent = -2 // the next "- " line sets it
			continue
		}
		if listIndent == -2 && strings.HasPrefix(trimmed, "- ") {
			listIndent = indent
		}
		if listIndent >= 0 && trimmed != "" && indent < listIndent {
			listIndent = -1 // left the list
		}
		if listIndent >= 0 && indent == listIndent && strings.HasPrefix(trimmed, "- name: ") {
			name := strings.TrimSpace(strings.TrimPrefix(trimmed, "- name: "))
			lines[i] = l[:indent] + "- name: " + shapeToken("ctr", name)
		}
	}
	return strings.Join(lines, "\n")
}
