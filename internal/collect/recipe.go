package collect

import (
	"fmt"
	"io"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/buildinfo"
)

// RoleURL is the published role at this release's tag in the open scanner's repository. The operator applies it
// with an admin kubeconfig, so it must be the role this binary was tested with: a branch can move under a printed
// command, and a release tag does not (releases are immutable). Every release tags the scanner repository with its
// own version, so the tag exists. A local build has no release, so it names main; only a build of ours prints that.
func RoleURL() string {
	ref := "main"
	if v := strings.TrimPrefix(buildinfo.Version, "v"); v != "" {
		ref = "v" + v
	}
	return "https://raw.githubusercontent.com/Shoalcheck/shoalcheck-scan/" + ref + "/deploy/rbac.yaml"
}

// WriteNeverAndRecipe ends a permission preview: what is never read and never written, and how to run with the
// published role and nothing else. Shared by `shoalcheck audit --show-permissions` and `shoalcheck-scan
// --show-permissions` so the two never drift.
//
// The recipe is commands the OPERATOR runs. Creating a ServiceAccount and a binding is a write, and this
// product writes nothing, so the recipe stays printed text and never becomes a flag. Its kubeconfig is a new
// file holding only the ServiceAccount's short-lived token, so the operator's own credentials are not copied
// into it. run is the command that reads the cluster, e.g. "shoalcheck audit".
func WriteNeverAndRecipe(w io.Writer, run string) {
	lines := []string{
		"Never read: Secret values, ConfigMap data, logs, exec, attach, ServiceAccount tokens. These are refused",
		"inside the binary by the never-read guard before a request is sent, even under a cluster-admin",
		"kubeconfig (internal/trace/guard.go). Pod environment values arrive inside pod specs and are dropped on",
		"arrival; only variable names are kept. Operator objects (Argo CD, Flux, ...) are kept only to the fields",
		"a rule reads; Helm values and annotations are dropped on arrival.",
		"Never written: no create/update/patch/delete, no watch.",
		"",
		"Run it with this role and nothing else. You run these commands; shoalcheck makes none of these changes:",
		"",
		"  kubectl apply -f " + RoleURL(),
		"  kubectl -n kube-system create serviceaccount shoalcheck-auditor",
		"  kubectl create clusterrolebinding shoalcheck-auditor --clusterrole=shoalcheck-auditor \\",
		"    --serviceaccount=kube-system:shoalcheck-auditor",
		"  K=shoalcheck-readonly.kubeconfig",
		`  kubectl config --kubeconfig="$K" set-cluster target \`,
		`    --server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"`,
		`  kubectl config --kubeconfig="$K" set clusters.target.certificate-authority-data \`,
		`    "$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"`,
		`  kubectl config --kubeconfig="$K" set-credentials shoalcheck-auditor \`,
		`    --token="$(kubectl -n kube-system create token shoalcheck-auditor --duration=1h)"`,
		`  kubectl config --kubeconfig="$K" set-context target --cluster=target --user=shoalcheck-auditor`,
		`  kubectl config --kubeconfig="$K" use-context target`,
		fmt.Sprintf(`  %s --kubeconfig "$K"`, run),
	}
	// THE LAST COMMAND HAS TWO SHAPES FOR THE AUDIT. Run on kind on 2026-11-11, the recipe worked to its last line
	// on a machine with a licence, which then stopped at "--output is required": a licensed audit writes the
	// reading to a file, and the free one prints its size and refuses a file. Both shapes are printed, so the
	// recipe ends in a reading whichever machine runs it.
	if run == "shoalcheck audit" {
		lines = append(lines, `  # with a licence, the full reading is a file: add --output report.html`)
	}
	lines = append(lines, []string{
		"",
		"Your API server then refuses anything outside the role. The token expires in an hour. Afterwards:",
		"",
		"  kubectl delete clusterrolebinding shoalcheck-auditor",
		"  kubectl -n kube-system delete serviceaccount shoalcheck-auditor",
		`  rm "$K"`,
		"",
		"If your kubeconfig names a CA file instead of embedding it, use set-cluster --certificate-authority=<file>",
		"--embed-certs in place of the certificate-authority-data line.",
	}...)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}
