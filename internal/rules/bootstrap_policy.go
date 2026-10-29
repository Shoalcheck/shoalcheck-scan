package rules

import (
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// bootstrap_policy.go — the bindings the Kubernetes API server writes for itself, as exact tuples.
//
// WHY A TABLE, AFTER THIS PACKAGE ARGUED AGAINST ONE. rbac_subjects.go trusted the kubernetes.io/bootstrapping
// label alone because a name list "would go stale with each Kubernetes release". The label is an ordinary label,
// and anybody who can create a binding can set it: trusted alone — and then trusted with a system:-shaped name —
// it let a labelled binding of cluster-admin, or of a role named system:evil to system:authenticated, vanish from
// every RBAC rule. Two automated security reviews of the 2026-10-16 push found the two holes in turn.
//
// A stale table fails SAFE: a bootstrap binding a newer release adds and this table lacks is REPORTED, which is
// noise. A trusted marker fails OPEN, which is an attacker's persistence nobody sees. For a security reading that
// is the whole trade.
//
// SOURCE: read from a kind cluster running Kubernetes 1.36.1 (`kubectl get clusterrolebindings,rolebindings -A
// -l kubernetes.io/bootstrapping=rbac-defaults`), 2026-10-16 — the upstream bootstrap policy as the API server
// writes it.

// upstreamTuple is what one bootstrap binding points at and names.
type upstreamTuple struct {
	refKind, refName string
	subjects         []string // subjectKey form, sorted
}

// upstreamControllers are the system:controller:X ClusterRoleBindings: ClusterRole of the same name, and exactly
// the ServiceAccount kube-system/X.
var upstreamControllers = []string{
	"attachdetach-controller", "certificate-controller", "clusterrole-aggregation-controller", "cronjob-controller",
	"daemon-set-controller", "deployment-controller", "device-taint-eviction-controller", "disruption-controller",
	"endpoint-controller", "endpointslice-controller", "endpointslicemirroring-controller",
	"ephemeral-volume-controller", "expand-controller", "generic-garbage-collector", "horizontal-pod-autoscaler",
	"job-controller", "legacy-service-account-token-cleaner", "namespace-controller", "node-controller",
	"persistent-volume-binder", "pod-garbage-collector", "pv-protection-controller", "pvc-protection-controller",
	"replicaset-controller", "replication-controller", "resource-claim-controller", "resourcequota-controller",
	"root-ca-cert-publisher", "route-controller", "selinux-warning-controller", "service-account-controller",
	"service-cidrs-controller", "service-controller", "statefulset-controller", "ttl-after-finished-controller",
	"ttl-controller", "validatingadmissionpolicy-status-controller", "volumeattributesclass-protection-controller",
}

func cr(name string, subjects ...string) upstreamTuple {
	sort.Strings(subjects)
	return upstreamTuple{refKind: "ClusterRole", refName: name, subjects: subjects}
}

func role(name string, subjects ...string) upstreamTuple {
	sort.Strings(subjects)
	return upstreamTuple{refKind: "Role", refName: name, subjects: subjects}
}

// upstreamClusterRoleBindings, keyed by binding name.
var upstreamClusterRoleBindings = func() map[string]upstreamTuple {
	m := map[string]upstreamTuple{
		"cluster-admin":                           cr("cluster-admin", "Group:system:masters"),
		"system:basic-user":                       cr("system:basic-user", "Group:system:authenticated"),
		"system:discovery":                        cr("system:discovery", "Group:system:authenticated"),
		"system:public-info-viewer":               cr("system:public-info-viewer", "Group:system:authenticated", "Group:system:unauthenticated"),
		"system:service-account-issuer-discovery": cr("system:service-account-issuer-discovery", "Group:system:serviceaccounts"),
		"system:kube-controller-manager":          cr("system:kube-controller-manager", "User:system:kube-controller-manager"),
		"system:kube-dns":                         cr("system:kube-dns", "ServiceAccount:kube-system/kube-dns"),
		"system:kube-scheduler":                   cr("system:kube-scheduler", "User:system:kube-scheduler"),
		"system:volume-scheduler":                 cr("system:volume-scheduler", "User:system:kube-scheduler"),
		"system:monitoring":                       cr("system:monitoring", "Group:system:monitoring"),
		"system:node":                             cr("system:node"),
		"system:node-proxier":                     cr("system:node-proxier", "User:system:kube-proxy"),
	}
	for _, c := range upstreamControllers {
		m["system:controller:"+c] = cr("system:controller:"+c, "ServiceAccount:kube-system/"+c)
	}
	return m
}()

// upstreamRoleBindings, keyed by "namespace/name".
var upstreamRoleBindings = map[string]upstreamTuple{
	"kube-public/system:controller:bootstrap-signer": role("system:controller:bootstrap-signer", "ServiceAccount:kube-system/bootstrap-signer"),
	"kube-system/system:controller:bootstrap-signer": role("system:controller:bootstrap-signer", "ServiceAccount:kube-system/bootstrap-signer"),
	"kube-system/system:controller:cloud-provider":   role("system:controller:cloud-provider", "ServiceAccount:kube-system/cloud-provider"),
	"kube-system/system:controller:token-cleaner":    role("system:controller:token-cleaner", "ServiceAccount:kube-system/token-cleaner"),
	"kube-system/system::extension-apiserver-authentication-reader": role("extension-apiserver-authentication-reader",
		"User:system:kube-controller-manager", "User:system:kube-scheduler"),
	"kube-system/system::leader-locking-kube-controller-manager": role("system::leader-locking-kube-controller-manager",
		"User:system:kube-controller-manager", "ServiceAccount:kube-system/kube-controller-manager",
		"ServiceAccount:kube-system/leader-election-controller"),
	"kube-system/system::leader-locking-kube-scheduler": role("system::leader-locking-kube-scheduler",
		"User:system:kube-scheduler", "ServiceAccount:kube-system/kube-scheduler"),
}

func subjectKey(s rbacv1.Subject) string {
	if s.Kind == rbacv1.ServiceAccountKind {
		return s.Kind + ":" + s.Namespace + "/" + s.Name
	}
	return s.Kind + ":" + s.Name
}

// kubernetesOwnBinding is whether the API server wrote this binding itself: the bootstrap label AND the exact
// upstream tuple — the binding's kind, namespace and name, its roleRef kind and name, and its subjects, no more
// and no fewer. Anything else, labelled or not, is reported like any binding.
func kubernetesOwnBinding(kind, ns, name string, labels map[string]string, ref rbacv1.RoleRef, subjects []rbacv1.Subject) bool {
	if !bootstrapDefault(labels) {
		return false
	}
	var want upstreamTuple
	var ok bool
	switch kind {
	case "ClusterRoleBinding":
		want, ok = upstreamClusterRoleBindings[name]
	case "RoleBinding":
		want, ok = upstreamRoleBindings[ns+"/"+name]
	}
	if !ok || ref.Kind != want.refKind || ref.Name != want.refName {
		return false
	}
	got := make([]string, 0, len(subjects))
	for _, s := range subjects {
		got = append(got, subjectKey(s))
	}
	sort.Strings(got)
	return strings.Join(got, "\n") == strings.Join(want.subjects, "\n")
}

// platformClusterRoleBindings are the cluster-admin bindings an installer writes on every cluster it creates, as
// exact tuples keyed by binding name — the role it points at and its subjects, no more and no fewer, and the labels it
// carries — each with the installer whose clusters it belongs to. k8s.rbac.cluster-admin-user-or-group skips one only
// where the reading itself shows that installer built the cluster, because a high finding on every such cluster is
// noise about nobody's choices.
//
// EVIDENCE ONLY, NEVER RECALL. A row is here because a reading in this repository shows it or its installer
// documents it, and for no other reason:
//
//	kubeadm:cluster-admins — kubeadm 1.29 and later binds cluster-admin to the group its admin.conf certificate
//	carries. Read in testdata/bench/live/capture.json.gz (kind 1.36, which installs with kubeadm): no labels, one
//	subject, Group kubeadm:cluster-admins.
//
// The repository holds no captured AKS, EKS or GKE reading, so no provider's admin binding is listed: one that
// exists is reported, and the rule's boundary says so. Adding a row needs a reading that shows it.
//
// MATCHED WHOLE, as the bootstrap tuples are, AND ONLY ON THE INSTALLER'S OWN CLUSTERS. The name alone is anybody's
// to reuse: a binding called kubeadm:cluster-admins that names one more subject, or another subject, is a customer's
// grant and is reported. And the whole tuple is anybody's too where the installer did not build the cluster — on a
// managed cluster whose groups come from an identity provider, kubeadm:cluster-admins is a group name like any other
// (security review of 8b430348) — so the exclusion also needs the installer's own mark in the reading.
var platformClusterRoleBindings = map[string]struct {
	tuple     upstreamTuple
	labels    map[string]string
	installer string
	built     func(*collect.Inventory) bool // whether the reading shows the installer built this cluster
}{
	"kubeadm:cluster-admins": {tuple: cr("cluster-admin", "Group:kubeadm:cluster-admins"),
		installer: "kubeadm", built: kubeadmControlPlane},
}

// platformBinding names the installer whose own binding this ClusterRoleBinding is, by the whole tuple (see
// platformClusterRoleBindings), and says whether the reading shows that installer built the cluster. installer is ""
// when the binding is nobody's own.
func platformBinding(inv *collect.Inventory, name string, labels map[string]string, ref rbacv1.RoleRef,
	subjects []rbacv1.Subject) (installer string, built bool) {

	want, ok := platformClusterRoleBindings[name]
	if !ok || ref.Kind != want.tuple.refKind || ref.Name != want.tuple.refName {
		return "", false
	}
	for k, v := range want.labels {
		if labels[k] != v {
			return "", false
		}
	}
	got := make([]string, 0, len(subjects))
	for _, s := range subjects {
		got = append(got, subjectKey(s))
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want.tuple.subjects, "\n") {
		return "", false
	}
	return want.installer, want.built(inv)
}

// kubeadmControlPlane reads the mark a live collection set (collect.Inventory.KubeadmControlPlane) and nothing else.
// It used to read the inventory's pods, which a gate reads AFTER laying a pull request's objects over them — so a
// change could carry a forged API server pod and pass its own copy of kubeadm's binding (security review of
// c7a9423b). A reading without the mark — a managed cluster, a refused pod list, an empty cluster, a capture taken
// before the mark existed — reports the binding, which is the safe side.
func kubeadmControlPlane(inv *collect.Inventory) bool { return inv.KubeadmControlPlane }

// broadSubject is a group or user that names everybody of a kind. A bootstrap binding to one of these binds a
// role that grants nothing a dangerous-grant pattern matches — so if that rule ever sees one, the role was
// edited, and API-server reconciliation, which only adds permissions, will not have undone it.
func broadSubject(s rbacv1.Subject) bool {
	switch s.Name {
	case "system:authenticated", "system:unauthenticated", "system:anonymous":
		return true
	}
	return strings.HasPrefix(s.Name, "system:serviceaccounts")
}

// upstreamClusterRoleBodies are the built-in ClusterRoles whose rules no cluster can differ on, as the bootstrap
// policy writes them. A run with no cluster (gate --manifests-only) lays a change over an empty inventory, and a
// binding to cluster-admin there named a role "not found" — a role every conformant cluster has — so the binding
// was judged by a low-severity dangling reference instead of by what it grants.
//
// ONLY CLUSTER-ADMIN, AND THAT IS THE POINT. Its body is `*` on every group, resource and verb and on every
// non-resource URL: nothing a later release adds can widen it and reconciliation restores it if edited, so it is the
// same object on every cluster. The other bootstrap roles change between releases, and admin, edit and view are
// aggregated by a controller from whatever the cluster has installed, so a body written here for any of them would be
// a guess about somebody's cluster. A binding to one of those still reads as not found over an empty cluster, and the
// verdict says so (gating.NotReadLine).
//
// SOURCE: `kubectl get clusterrole cluster-admin -o json` on the kind cluster running Kubernetes 1.36 that the e2e
// suite uses, 2026-10-27 — the same body this table's bindings were read beside.
var upstreamClusterRoleBodies = map[string][]rbacv1.PolicyRule{
	"cluster-admin": {
		{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
		{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}},
	},
}

// BuiltinClusterRoles returns a fresh copy of the built-in ClusterRoles a run with no cluster stands in for, labelled
// as the API server labels them, sorted by name.
func BuiltinClusterRoles() []rbacv1.ClusterRole {
	names := make([]string, 0, len(upstreamClusterRoleBodies))
	for n := range upstreamClusterRoleBodies {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]rbacv1.ClusterRole, 0, len(names))
	for _, n := range names {
		var rules []rbacv1.PolicyRule
		for _, r := range upstreamClusterRoleBodies[n] {
			rules = append(rules, *r.DeepCopy())
		}
		out = append(out, rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: n, Labels: map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}},
			Rules:      rules,
		})
	}
	return out
}
