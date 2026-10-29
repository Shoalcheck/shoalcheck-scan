package rules

import (
	"sort"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A SHAPE IS NOT A GRANT. Measured on the engine bench (docs/engine/benchmark.md): a role that only READS webhook
// configurations was reported as "writing admission webhook configurations"; a role that may do anything to
// ConfigMaps was reported as holding `impersonate`; a role that reads Deployments in every API group was reported
// as writing webhooks; and kubeadm's own system:kubelet-api-admin — every verb on nodes/proxy, nodes/stats and
// nodes/log — was reported as an impersonator on every kubeadm cluster.
//
// Each case below is one bound role and the exact set of patterns it must match. The patterns that must NOT match
// are the point: every one of them was a finding a reviewer would have had to argue with.
func TestRBACGrantRules_AShapeIsNotAGrant(t *testing.T) {
	cases := []struct {
		name  string
		rules []rbacv1.PolicyRule
		want  []string
	}{
		{
			// Reading everything includes Secrets, and GET on nodes/proxy reaches the kubelet API. It does not
			// include approving a CSR or writing a webhook, whose verbs are update and create.
			name:  "read-everything",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch"}}},
			want:  []string{"nodes-proxy", "secrets-read"},
		},
		{
			name: "webhook-viewer",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}, Verbs: []string{"get", "list", "watch"}}},
			want: nil,
		},
		{
			// `impersonate` means something only on users, groups, ServiceAccounts, uids and userextras.
			name:  "configmap-admin",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"*"}}},
			want:  nil,
		},
		{
			// admissionregistration.k8s.io serves no `deployments`; nor does rbac.authorization.k8s.io.
			name:  "deployment-reader-any-group",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"deployments"}, Verbs: []string{"*"}}},
			want:  nil,
		},
		{
			// kubeadm's system:kubelet-api-admin, verbatim from a 1.36 cluster.
			name: "kubelet-api-admin",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get", "list", "watch", "proxy"}},
				{APIGroups: []string{""}, Resources: []string{"nodes/log", "nodes/metrics", "nodes/proxy", "nodes/stats"}, Verbs: []string{"*"}},
			},
			want: []string{"nodes-proxy"},
		},
		// The real grants still match.
		{
			name: "webhook-writer",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{"mutatingwebhookconfigurations"}, Verbs: []string{"create", "update", "patch"}}},
			want: []string{"webhooks"},
		},
		{
			name:  "webhook-everything",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			want:  []string{"webhooks"},
		},
		{
			name: "csr-approver",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}}},
			want: []string{"csr-approve"},
		},
		{
			name:  "impersonator",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"users", "groups", "serviceaccounts"}, Verbs: []string{"impersonate"}}},
			want:  []string{"impersonate"},
		},
		{
			name:  "impersonate-extras",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"userextras/scopes"}, Verbs: []string{"impersonate"}}},
			want:  []string{"impersonate"},
		},
		{
			name:  "everything-on-roles",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"*"}}},
			want:  []string{"bind", "escalate"},
		},
		{
			name:  "everything-on-pods-any-group",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
			want:  []string{"pods-create"},
		},
		// Admission policies are admission configuration too: a mutating policy rewrites what it matches and a
		// validating one refuses it, cluster-wide, with no webhook server at all.
		{
			name: "admission-policy-writer",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{"mutatingadmissionpolicies", "mutatingadmissionpolicybindings"}, Verbs: []string{"create", "update"}}},
			want: []string{"webhooks"},
		},
		{
			name: "validating-policy-binder",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{"validatingadmissionpolicybindings"}, Verbs: []string{"create"}}},
			want: []string{"webhooks"},
		},
		// `*/sub` is how RBAC grants one subresource of every resource — the spelling a reviewer skimming for
		// "nodes/proxy" or "serviceaccounts/token" does not see.
		{
			name:  "star-slash-proxy",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*/proxy"}, Verbs: []string{"get"}}},
			want:  []string{"nodes-proxy"},
		},
		{
			name:  "star-slash-token",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*/token"}, Verbs: []string{"create"}}},
			want:  []string{"sa-token"},
		},
		{
			name:  "star-slash-approval",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"*/approval"}, Verbs: []string{"update"}}},
			want:  []string{"csr-approve"},
		},
		{
			// Literal strings to the authorizer: they grant no request at all.
			name:  "literal-star-forms",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*/*", "nodes/*", "serviceaccounts/*"}, Verbs: []string{"*"}}},
			want:  nil,
		},
		// exec and attach run a process in somebody else's container, with its ServiceAccount token, its mounted
		// Secrets and its network identity — the same reach as creating the pod, without creating anything.
		{
			name:  "pod-exec",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}},
			want:  []string{"pods-exec"},
		},
		{
			name:  "pod-attach-via-star-slash",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*/attach"}, Verbs: []string{"create"}}},
			want:  []string{"pods-exec"},
		},
		{
			// On 1.31 and later a websocket exec needs create too (AuthorizePodWebsocketUpgradeCreatePermission), so
			// GET on pods/exec is not reported; read-everything above stays secrets-read and nodes-proxy only.
			name:  "pod-exec-get-only",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec", "pods/log"}, Verbs: []string{"get"}}},
			want:  nil,
		},
		{
			name:  "node-proxy-get",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"nodes/proxy"}, Verbs: []string{"get"}}},
			want:  []string{"nodes-proxy"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := &collect.Inventory{
				ClusterRoles: []rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: c.name}, Rules: c.rules}},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: c.name},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: c.name},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "tool", Namespace: "ops"}},
				}},
			}
			inv.Meta.Collected = []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"}
			var got []string
			for _, f := range (RBACDangerousGrant{}).Evaluate(inv, Options{}) {
				_, key, _ := strings.Cut(f.IDBasis.Kind, "/")
				got = append(got, key)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("matched %v, want %v", got, c.want)
			}
		})
	}
}
