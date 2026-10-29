package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// secret_env.go — A SECRET REACHING A CONTAINER THROUGH THE ENVIRONMENT.
//
// WHY THIS RULE CAN EXIST AT ALL, and it is the whole reason it was worth building: it needs no Secret.
// `env[].valueFrom.secretKeyRef` and `envFrom[].secretRef` are references BY NAME, written in the workload's
// own pod template. No Secret is listed, no key is read, no value is seen — which matters because
// internal/collect never lists Secrets and never will. The rule works identically on a cluster that refuses
// them, because it never asked.
//
// It is a control in the generic benchmark (5.4.1) and in all three provider ones, and
// docs/qa/2026-08-31-provider-benchmark-measurement.md named it "the single best unbuilt row in the whole
// exercise" for exactly that reason.
//
// WHAT THE CLAIM IS. An environment variable is inherited by every child process the container starts,
// appears in `kubectl describe pod` to anybody with pod read, and is copied into crash dumps, core files and
// process listings. A mounted file is readable by the container too — the difference is not secrecy from the
// process, it is the blast radius of a read nobody intended: a debug endpoint that prints its environment, a
// log line, a shell in a sidecar.
//
// WHAT IT IS NOT.
//
//	NOT A CLAIM THAT ANYTHING LEAKED. Nothing was observed; this is a declaration in a spec.
//
//	NOT A CLAIM ABOUT THE VALUE. The value is not read here, so nothing is said about whether it is
//	sensitive at all. A Secret holding a feature flag is the same shape as one holding a database password.
//
//	NOT A CLAIM THAT THE SECRET EXISTS. A reference to a Secret that is absent produces a pod that will not
//	start, which is a different finding this rule does not make: Secrets are not collected.
//
//	NOT A CLAIM THAT A MOUNT IS SAFE. A file mounted world-readable into a shared volume is worse than an
//	environment variable. The control asks for a shape, and the shape is where the evidence stops.
//
// NO REMEDIATION. Moving a secret from the environment to a file changes how the process reads it — a code
// change, not a manifest change — and a generated patch that mounts a volume the program does not read would
// leave a workload that starts and cannot authenticate.
type SecretInEnvVar struct{}

func (SecretInEnvVar) ID() string { return "k8s.workload.secret-in-env-var" }

// 1.1.0 (2026-10-21): judges every pod spec the cluster runs — bare Pods, Jobs and CronJobs too (podTemplates).
func (SecretInEnvVar) Version() string { return "1.1.0" }

// RequiredKinds — the workload lists, and nothing else. Secrets are deliberately absent: this rule reads
// references and never their targets, which is what lets it run on every cluster. See deps.go.
func (SecretInEnvVar) RequiredKinds() []string { return podTemplateKinds() }

// secretEnvRef is one place a Secret reaches the environment of one container.
type secretEnvRef struct {
	container string
	variable  string // "" for an envFrom, which names no single variable
	secret    string
	key       string // "" for an envFrom, which takes every key
}

func (r SecretInEnvVar) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// THE DENIAL GUARD. A workload list that was refused is not a workload list with nothing in it. It is held on
	// the three workload lists as before: a refused pod or Job list leaves those specs unjudged (podTemplates reads
	// what was collected), and silencing the whole rule for it would hide what WAS read.
	for _, kind := range workloadKinds() {
		if !metaCollected(inv, kind) {
			return nil
		}
	}

	var out []types.Finding
	for _, w := range podTemplates(inv, opts) {
		refs := secretEnvRefs(w.PodSpec)
		if len(refs) == 0 {
			continue
		}
		out = append(out, r.finding(w, refs))
	}
	return out
}

// secretEnvRefs walks every container in the pod — init and ephemeral containers included, because a secret
// in an init container's environment is in a process's environment exactly as much as one in the app's.
func secretEnvRefs(spec corev1.PodSpec) []secretEnvRef {
	var out []secretEnvRef
	scan := func(c corev1.Container, label string) {
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				out = append(out, secretEnvRef{container: label, variable: e.Name,
					secret: e.ValueFrom.SecretKeyRef.Name, key: e.ValueFrom.SecretKeyRef.Key})
			}
		}
		for _, f := range c.EnvFrom {
			if f.SecretRef != nil {
				out = append(out, secretEnvRef{container: label, secret: f.SecretRef.Name})
			}
		}
	}
	for _, c := range spec.InitContainers {
		scan(c, c.Name+" (init)")
	}
	for _, c := range spec.Containers {
		scan(c, c.Name)
	}
	for _, c := range spec.EphemeralContainers {
		scan(corev1.Container(c.EphemeralContainerCommon), c.Name+" (ephemeral)")
	}
	return out
}

func (r SecretInEnvVar) finding(w workload, refs []secretEnvRef) types.Finding {
	secrets := map[string]bool{}
	whole := 0
	for _, ref := range refs {
		secrets[ref.secret] = true
		if ref.key == "" {
			whole++
		}
	}
	names := make([]string, 0, len(secrets))
	for s := range secrets {
		names = append(names, s)
	}
	sort.Strings(names)

	var ev []string
	for _, ref := range refs {
		if ref.key == "" {
			ev = append(ev, fmt.Sprintf("%s/%s container %s: envFrom.secretRef %s — every key of that "+
				"Secret becomes an environment variable, and this reading cannot say how many that is",
				w.Namespace, w.Name, ref.container, ref.secret))
			continue
		}
		ev = append(ev, fmt.Sprintf("%s/%s container %s: env %s takes secretKeyRef %s/%s (the reference is read, "+
			"the value is not)", w.Namespace, w.Name, ref.container, ref.variable, ref.secret, ref.key))
	}

	sev := types.SeverityLow
	if whole > 0 {
		// Every key of a Secret, rather than one named variable: a larger surface and a weaker statement
		// about what the workload actually needs.
		sev = types.SeverityMedium
	}

	return types.Finding{
		ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
		IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("Secret material reaches %s/%s through the environment",
			w.Namespace, w.Name),
		Description: fmt.Sprintf("%s %s/%s takes %s from %s (%s) as environment "+
			"variables. The pod template names the Secret; no Secret was read and no value was seen.",
			w.Kind, w.Namespace, w.Name, nWord(len(refs), "value", "values"), nWord(len(names), "Secret", "Secrets"), strings.Join(names, ", ")),
		WhyItMatters: "An environment variable is inherited by every child process the container starts, is " +
			"printed by `kubectl describe pod` to anybody with pod read, and is copied into crash dumps and " +
			"process listings. A file mounted from the same Secret is readable by the container and by " +
			"nothing else that was not already looking.",
		Evidence:          ev,
		Severity:          sev,
		Category:          types.CategorySecurity,
		AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}
}
