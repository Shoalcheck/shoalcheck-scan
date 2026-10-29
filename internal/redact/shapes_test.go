package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE NAMES NO STRUCTURED FIELD CARRIES.
//
// The replacer tokenizes what the report's structured fields name — namespaces, workloads, nodes, RBAC subjects —
// and a live redacted reading of the mesh testbed still carried, in its evidence and its patches:
//
//   - container names: `- name: kube-state-metrics` in a remediation patch, "container sleeper in Deployment …";
//   - ServiceAccount names: "names ServiceAccount ns-e10f34/local-path-provisioner-service-account";
//   - pod label maps: "map[app.kubernetes.io/instance:shoalcheck-prom … release:shoalcheck-prom]" — a Helm
//     release name is usually the application's;
//   - Prometheus job labels: `job="…"`;
//   - image references — harmless for `busybox:1.36`, and the AWS account id itself for a private ECR image.
//
// None of these is in a field the replacer harvests, so each is scrubbed by its SHAPE: the syntactic position the
// product writes it in. Public vocabulary survives — a public image, a job Kubernetes ships, a label key.
func TestReport_ScrubsTheNamesNoStructuredFieldCarries(t *testing.T) {
	ar := sampleReport()
	ar.Findings[0].Evidence = append(ar.Findings[0].Evidence,
		`container ledger-sidecar in Deployment payments/payments-gateway: requests 900m CPU`,
		`RoleBinding cicd/deployer-rb names ServiceAccount cicd/acme-release-bot, and reaches within namespace cicd.`,
		`No PodDisruptionBudget in namespace payments selects pod labels map[app:acme-ledger app.kubernetes.io/instance:acme-ledger-prod acme.example/team:ledger-core-team]`,
		`job="acme-ledger-metrics" — 2 targets reporting up=0`,
		`job="kube-proxy" — 3 targets reporting up=0`,
		`containers with no explicit requests: payments-gateway/ledger-sidecar, payments-gateway/acme-ledger (+2 more)`,
		`no non-root assertion and image "123456789012.dkr.ecr.eu-central-1.amazonaws.com/acme/ledger:1.4.2" is used`,
		`no non-root assertion and image "busybox:1.36" is a known root-by-default base`,
	)
	ar.Findings[0].RemediationYAML = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments-gateway\n" +
		"spec:\n  template:\n    spec:\n      containers:\n        - name: ledger-sidecar\n          env:\n            - name: LOG_LEVEL\n          resources: {}\n"
	ar.Summary = types.DeriveSummary(ar.Findings)
	data, err := json.Marshal(Report(ar))
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, leak := range []string{"ledger-sidecar", "acme-release-bot", "acme-ledger", "acme-ledger-prod",
		"acme.example", "ledger-core-team", "acme-ledger-metrics", "123456789012", "dkr.ecr", "acme/ledger"} {
		if strings.Contains(out, leak) {
			t.Errorf("the redacted report still carries %q", leak)
		}
	}
	// An environment variable's name in a patch is the patch's own content, not an identifier of the cluster.
	for _, keep := range []string{`job=\"kube-proxy\"`, "busybox:1.36", "app.kubernetes.io/instance:", ":1.4.2", "name: LOG_LEVEL", "(+2 more)"} {
		if !strings.Contains(out, keep) {
			t.Errorf("public vocabulary %q was scrubbed with the names", keep)
		}
	}
}
