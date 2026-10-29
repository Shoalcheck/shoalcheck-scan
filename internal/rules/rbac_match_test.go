package rules

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

// THE MATCHER IS THE AUTHORIZER'S, CASE FOR CASE. A grant is dangerous only if the API server would authorise the
// request it names, so the question rbacAllows answers is the one the RBAC authorizer answers — APIGroupMatches,
// ResourceMatches and VerbMatches in Kubernetes' rbac package — and these cases are its semantics:
//
//   - `*` in apiGroups, resources or verbs matches anything;
//   - a resource entry matches the requested resource exactly, subresource included ("pods" does not grant
//     "pods/log");
//   - `*/sub` matches that subresource of ANY resource ("*/proxy" grants nodes/proxy);
//   - nothing else is a wildcard: "pods/*" and "*/*" are literal strings that no request is named, so they grant
//     nothing (verified with `kubectl auth can-i` on the bench cluster — docs/engine/benchmark.md);
//   - verbs and groups compare exactly; "Get" is not "get".
func TestRBACMatch_IsTheAuthorizersMatch(t *testing.T) {
	rule := func(groups, resources, verbs []string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: groups, Resources: resources, Verbs: verbs}
	}
	core := []string{""}
	cases := []struct {
		name                  string
		rule                  rbacv1.PolicyRule
		group, res, sub, verb string
		want                  bool
	}{
		{"star resource", rule(core, []string{"*"}, []string{"get"}), "", "pods", "", "get", true},
		{"star resource covers subresources", rule(core, []string{"*"}, []string{"get"}), "", "nodes", "proxy", "get", true},
		{"exact resource", rule(core, []string{"pods"}, []string{"get"}), "", "pods", "", "get", true},
		{"resource does not grant its subresource", rule(core, []string{"pods"}, []string{"get"}), "", "pods", "log", "get", false},
		{"exact subresource", rule(core, []string{"pods/log"}, []string{"get"}), "", "pods", "log", "get", true},
		{"subresource does not grant the resource", rule(core, []string{"pods/log"}, []string{"get"}), "", "pods", "", "get", false},
		{"star-slash-sub grants that subresource of any resource", rule(core, []string{"*/proxy"}, []string{"get"}), "", "nodes", "proxy", "get", true},
		{"star-slash-sub grants it on services too", rule(core, []string{"*/proxy"}, []string{"get"}), "", "services", "proxy", "get", true},
		{"star-slash-sub does not grant another subresource", rule(core, []string{"*/proxy"}, []string{"get"}), "", "nodes", "log", "get", false},
		{"star-slash-sub does not grant the resource", rule(core, []string{"*/proxy"}, []string{"get"}), "", "nodes", "", "get", false},
		{"res-slash-star is literal", rule(core, []string{"nodes/*"}, []string{"get"}), "", "nodes", "proxy", "get", false},
		{"star-slash-star is literal", rule(core, []string{"*/*"}, []string{"get"}), "", "nodes", "proxy", "get", false},
		{"star group", rule([]string{"*"}, []string{"secrets"}, []string{"get"}), "", "secrets", "", "get", true},
		{"other group", rule([]string{"apps"}, []string{"secrets"}, []string{"get"}), "", "secrets", "", "get", false},
		{"star verb", rule(core, []string{"secrets"}, []string{"*"}), "", "secrets", "", "list", true},
		{"other verb", rule(core, []string{"secrets"}, []string{"create"}), "", "secrets", "", "get", false},
		{"verbs compare exactly", rule(core, []string{"secrets"}, []string{"Get"}), "", "secrets", "", "get", false},
	}
	for _, c := range cases {
		if got := rbacAllows(c.rule, c.group, c.res, c.sub, c.verb); got != c.want {
			t.Errorf("%s: rule %v allows %s %q %s/%s = %v, want %v", c.name, c.rule, c.verb, c.group, c.res, c.sub, got, c.want)
		}
	}
}
