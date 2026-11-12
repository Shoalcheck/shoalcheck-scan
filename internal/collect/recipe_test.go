package collect

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/buildinfo"
)

// The recipe's role is applied with an admin kubeconfig, so a release must name its own tag and never a branch.
func TestRoleURL_ARelease_NamesItsTagNotABranch(t *testing.T) {
	defer func(v string) { buildinfo.Version = v }(buildinfo.Version)
	for _, c := range []struct{ stamped, want string }{
		{"0.2.0", "/v0.2.0/deploy/rbac.yaml"},
		{"v0.2.0", "/v0.2.0/deploy/rbac.yaml"},
		{"0.3.0-beta.1", "/v0.3.0-beta.1/deploy/rbac.yaml"},
		{"", "/main/deploy/rbac.yaml"},
	} {
		buildinfo.Version = c.stamped
		if got := RoleURL(); !strings.HasSuffix(got, c.want) {
			t.Errorf("Version %q: RoleURL() = %q, want suffix %q", c.stamped, got, c.want)
		}
	}
	buildinfo.Version = "0.2.0"
	var b bytes.Buffer
	WriteNeverAndRecipe(&b, "shoalcheck audit")
	if !strings.Contains(b.String(), "kubectl apply -f "+RoleURL()+"\n") {
		t.Errorf("the recipe does not apply the release's role:\n%s", b.String())
	}
	if strings.Contains(b.String(), "/main/") {
		t.Errorf("a release's recipe names a branch:\n%s", b.String())
	}
}
