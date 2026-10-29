package rules

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

func TestSafeRemediationCommand_Allowlisted(t *testing.T) {
	safeCmds := []string{
		"kubectl -n app get deployment web -o yaml",
		"kubectl describe pod foo",
		`kubectl -n app patch pdb p --type merge -p '{"spec":{"maxUnavailable":1}}'`,
		"kubectl apply -f patch.yaml",
		"kubectl -n app scale deployment/web --replicas=2",
		"kubectl annotate ns app team=payments",
		"kubectl label node n1 role=worker",
		"kubectl set image deployment/web web=img:1.2.3",
		"kubectl rollout restart deployment/web",
		"kubectl explain deployment.spec",
		"kubectl top nodes",
		"kubectl -n app edit deployment web", // interactive → safe-ish
		"kubectl -n app get svc x -o jsonpath='{.spec}'",
		"kubectl -n app get deploy x -o yaml | grep -nE 'privileged'", // pipe to grep
	}
	for _, cmd := range safeCmds {
		safe, reason := SafeRemediationCommand(cmd)
		if !safe {
			t.Errorf("SafeRemediationCommand(%q) = false (%s), want safe", cmd, reason)
		}
	}
}

func TestSafeRemediationCommand_DestructiveDenied(t *testing.T) {
	unsafeCmds := []string{
		"kubectl -n app delete service x",
		"kubectl delete deployment web",
		"kubectl drain node1 --ignore-daemonsets",
		"kubectl cordon node1",
		"kubectl uncordon node1",
		"kubectl exec -it pod -- sh",
		"kubectl cp pod:/etc/passwd ./out",
		"kubectl replace --force -f x.yaml",
		"kubectl taint nodes n1 key=value:NoSchedule",
	}
	for _, cmd := range unsafeCmds {
		safe, reason := SafeRemediationCommand(cmd)
		if safe {
			t.Errorf("SafeRemediationCommand(%q) = true, want unsafe (destructive)", cmd)
		}
		if reason == "" {
			t.Errorf("SafeRemediationCommand(%q): unsafe result must carry a reason", cmd)
		}
	}
}

func TestSafeRemediationCommand_CommentIsDocumentation(t *testing.T) {
	// A leading-# line is documentation, not a one-click command — safe.
	cmds := []string{
		"# verify unused, then: kubectl -n app delete service x",
		"# reduce the foo node group's desired count by 2 (cloud-managed); then `kubectl drain` the freed nodes",
		"# verify the app supports >1 replica before scaling\nkubectl -n app scale sts/db --replicas=2",
	}
	for _, cmd := range cmds {
		safe, reason := SafeRemediationCommand(cmd)
		if !safe {
			t.Errorf("SafeRemediationCommand(%q) = false (%s), want safe (commented/manual)", cmd, reason)
		}
	}
}

func TestSafeRemediationCommand_MultilineEachLineChecked(t *testing.T) {
	// A non-comment destructive line anywhere in a multi-line block is unsafe.
	cmd := "# fine comment\nkubectl -n app delete service x"
	if safe, _ := SafeRemediationCommand(cmd); safe {
		t.Errorf("a bare destructive line under a comment must be unsafe: %q", cmd)
	}
	// Empty / blank-only lines are ignored.
	if safe, reason := SafeRemediationCommand("\n\nkubectl get pods\n"); !safe {
		t.Errorf("blank lines + a get should be safe, got unsafe: %s", reason)
	}
}

// TestAllRulesEmitSafeRemediationCommands is the load-bearing cross-rule gate:
// it runs every rule against a synthetic inventory crafted to trigger as many
// as possible, then asserts every emitted RemediationCommand is
// SafeRemediationCommand-safe. A bare `kubectl delete` (or any destructive verb
// without a comment prefix) fails this — forcing rules to comment-prefix
// destructive suggestions instead of putting a one-click copy button on them.
func TestAllRulesEmitSafeRemediationCommands(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	inv := triggerAllInventory()
	emitted := 0
	for _, rule := range All() {
		fs := rule.Evaluate(inv, Options{})
		for _, f := range fs {
			if f.RemediationCommand == "" {
				continue
			}
			emitted++
			safe, reason := SafeRemediationCommand(f.RemediationCommand)
			if !safe {
				t.Errorf("rule %s emitted an unsafe RemediationCommand: %q (%s)",
					rule.ID(), f.RemediationCommand, reason)
			}
		}
	}
	if emitted == 0 {
		t.Fatal("synthetic inventory triggered no RemediationCommand-bearing findings — the gate would be vacuous")
	}
	t.Logf("checked %d RemediationCommand strings across %d rules", emitted, len(All()))
}

// triggerAllInventory builds one inventory designed to fire as many rules as
// possible — in particular the RemediationCommand-bearing ones: idle LB
// (delete), image hygiene (get), pdb-blocks-drains (patch), node headroom
// (commented drain), privileged (get), single-replica (scale).
func triggerAllInventory() *collect.Inventory {
	replicas1 := int32(1)
	replicas3 := int32(3)

	// A privileged, probe-less, request-less, mutable-tag deployment with a
	// single replica and no PDB — trips a stack of rules at once.
	priv := true
	badDeploy := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "app"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas1,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "bad"}},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{{
						Name:            "main",
						Image:           "nginx:latest", // mutable tag
						SecurityContext: &corev1.SecurityContext{Privileged: &priv},
					}},
				},
			},
		},
	}

	// A PDB with maxUnavailable=0 (blocks drains) selecting some workload.
	zero := intstr.FromInt32(0)
	blockingPDB := policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "blocker", Namespace: "app"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &zero,
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "covered"}},
		},
	}
	covered := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "covered", Namespace: "app"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas3,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "covered"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img:1.0"}}},
			},
		},
	}

	// An idle LoadBalancer Service whose selector matches no pods → delete cmd.
	idleSvc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-lb", Namespace: "app"},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: map[string]string{"app": "nobody-here"},
		},
	}

	// Over-provisioned node pool (2 idle nodes, same type → 1 removable) to
	// fire node-headroom, which emits the commented `kubectl drain` command.
	nodeLabels := map[string]string{
		"topology.kubernetes.io/region":    "eu-central-1",
		"node.kubernetes.io/instance-type": "m6i.4xlarge",
	}
	mkNode := func(name string) corev1.Node {
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: nodeLabels},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("16"),
					corev1.ResourceMemory: resource.MustParse("64Gi"),
				},
			},
		}
	}

	return &collect.Inventory{
		Nodes:       []corev1.Node{mkNode("node-1"), mkNode("node-2")},
		Deployments: []appsv1.Deployment{badDeploy, covered},
		Services:    []corev1.Service{idleSvc},
		PDBs:        []policyv1.PodDisruptionBudget{blockingPDB},
	}
}
