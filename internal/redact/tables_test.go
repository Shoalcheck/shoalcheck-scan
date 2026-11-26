package redact

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A SUBJECT TOO SHORT FOR THE SENTENCE REPLACER IS STILL TOKENIZED IN THE GRAPH, where it stands alone; Kubernetes'
// own subjects keep their names.
func TestRedactTables_EveryGraphNameIsTokenizedWhole(t *testing.T) {
	ar := &types.AuditReport{SchemaVersion: "v1", RBACGraph: &types.RBACGraph{Total: 4, Edges: []types.RBACEdge{
		{SubjectKind: "Group", SubjectName: "ops", BindingKind: "ClusterRoleBinding", BindingName: "ops-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin"},
		{SubjectKind: "User", SubjectName: "qa", BindingKind: "RoleBinding", BindingNamespace: "acme-shop", BindingName: "qa", RoleKind: "Role", RoleName: "qa"},
		{SubjectKind: "Group", SubjectName: "system:masters", BindingKind: "ClusterRoleBinding", BindingName: "cluster-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin"},
		{SubjectKind: "ServiceAccount", SubjectNamespace: "kube-system", SubjectName: "coredns", BindingKind: "ClusterRoleBinding", BindingName: "system:coredns", RoleKind: "ClusterRole", RoleName: "system:coredns"},
	}}}
	out := Report(ar).RBACGraph.Edges
	for _, e := range out[:2] {
		for _, v := range []string{e.SubjectName, e.BindingName} {
			if !strings.Contains(v, "-") || (v != "" && !strings.HasPrefix(v, "subj-") && !strings.HasPrefix(v, "res-")) {
				t.Errorf("a customer name reached the redacted graph: %q", v)
			}
		}
	}
	if out[1].RoleName == "qa" || out[1].BindingNamespace == "acme-shop" {
		t.Errorf("the second edge kept a name: %+v", out[1])
	}
	if out[0].RoleName != "cluster-admin" || out[2].SubjectName != "system:masters" || out[3].SubjectName != "coredns" || out[3].RoleName != "system:coredns" {
		t.Errorf("Kubernetes' own names were tokenized: %+v / %+v", out[2], out[3])
	}
}
