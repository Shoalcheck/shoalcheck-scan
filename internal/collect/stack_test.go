package collect

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// mkDS builds a minimal DaemonSet for testing.
func mkDS(ns, name string, labels map[string]string) appsv1.DaemonSet {
	return appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
	}
}

// mkDeploy builds a minimal Deployment for testing.
func mkDeploy(ns, name string, labels map[string]string) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
	}
}

// mkNS builds a minimal Namespace for testing.
func mkNS(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
}

func TestDetectStack_FullScenario(t *testing.T) {
	// (a) cilium daemonset + argocd ns + prometheus & grafana deployments + karpenter
	// Expected: 4 entries with right layers/names; Observability = "Prometheus + Grafana"
	inv := &Inventory{
		DaemonSets: []appsv1.DaemonSet{
			mkDS("kube-system", "cilium", nil),
			mkDS("kube-system", "karpenter", nil),
		},
		Deployments: []appsv1.Deployment{
			mkDeploy("monitoring", "prometheus-server", nil),
			mkDeploy("monitoring", "grafana", nil),
		},
		Namespaces: []corev1.Namespace{
			mkNS("argocd", nil),
			mkNS("monitoring", nil),
			mkNS("kube-system", nil),
		},
	}

	got := detectStack(inv)

	// Must have exactly 4 entries (CNI, GitOps, Observability, Autoscaling)
	if len(got) != 4 {
		t.Fatalf("want 4 entries, got %d: %+v", len(got), got)
	}

	layerMap := map[string]types.StackEntry{}
	for _, e := range got {
		layerMap[e.Layer] = e
	}

	assertEntry := func(layer, wantName string) {
		t.Helper()
		e, ok := layerMap[layer]
		if !ok {
			t.Errorf("layer %q missing from results", layer)
			return
		}
		if e.Name != wantName {
			t.Errorf("layer %q: name = %q, want %q", layer, e.Name, wantName)
		}
		if e.Note == "" {
			t.Errorf("layer %q: note must not be empty", layer)
		}
	}

	assertEntry("CNI", "Cilium")
	assertEntry("GitOps", "Argo CD")
	assertEntry("Observability", "Prometheus + Grafana")
	assertEntry("Autoscaling", "Karpenter")

	// Verify deterministic order (CNI, GitOps, Observability, Autoscaling)
	wantLayers := []string{"CNI", "GitOps", "Observability", "Autoscaling"}
	for i, e := range got {
		if e.Layer != wantLayers[i] {
			t.Errorf("position %d: layer = %q, want %q", i, e.Layer, wantLayers[i])
		}
	}
}

func TestDetectStack_EmptyInventory(t *testing.T) {
	// (b) empty inventory → nil
	inv := &Inventory{}
	got := detectStack(inv)
	if got != nil {
		t.Errorf("empty inventory: want nil, got %+v", got)
	}
}

func TestDetectStack_LabelOnlyMatch(t *testing.T) {
	// (c) label-only match: app.kubernetes.io/name: cert-manager on a deployment
	inv := &Inventory{
		Deployments: []appsv1.Deployment{
			mkDeploy("cert-manager", "webhook", map[string]string{
				"app.kubernetes.io/name": "cert-manager",
			}),
		},
		Namespaces: []corev1.Namespace{
			// Use a namespace name that won't accidentally match
			mkNS("not-cert", nil),
		},
	}

	got := detectStack(inv)

	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d: %+v", len(got), got)
	}
	if got[0].Layer != "Certificates" {
		t.Errorf("layer = %q, want Certificates", got[0].Layer)
	}
	if got[0].Name != "cert-manager" {
		t.Errorf("name = %q, want cert-manager", got[0].Name)
	}
	if got[0].Note == "" {
		t.Error("note must not be empty for label-only match")
	}
}

func TestDetectStack_Determinism(t *testing.T) {
	// (d) same input twice → identical slice
	inv := &Inventory{
		DaemonSets: []appsv1.DaemonSet{
			mkDS("kube-system", "cilium", nil),
			mkDS("kube-system", "datadog-agent", nil),
		},
		Deployments: []appsv1.Deployment{
			mkDeploy("gitops", "argocd-server", nil),
			mkDeploy("karpenter", "karpenter", nil),
			mkDeploy("ingress", "ingress-nginx-controller", nil),
			mkDeploy("mesh", "istiod", nil),
			mkDeploy("certs", "cert-manager", nil),
			mkDeploy("secrets", "external-secrets", nil),
		},
		Namespaces: []corev1.Namespace{
			mkNS("argocd", nil),
		},
	}

	first := detectStack(inv)
	second := detectStack(inv)

	if !reflect.DeepEqual(first, second) {
		t.Errorf("detectStack not deterministic:\nfirst  = %+v\nsecond = %+v", first, second)
	}
}

func TestDetectStack_ObservabilityJoin(t *testing.T) {
	// Observability: up to 3 tools joined with " + "
	inv := &Inventory{
		Deployments: []appsv1.Deployment{
			mkDeploy("monitoring", "prometheus-operator", nil),
			mkDeploy("monitoring", "grafana-deployment", nil),
			mkDeploy("monitoring", "loki-0", nil),
			// A 4th tool that should NOT appear (cap at 3)
			mkDeploy("monitoring", "victoria-metrics", nil),
		},
	}

	got := detectStack(inv)
	if len(got) != 1 || got[0].Layer != "Observability" {
		t.Fatalf("want 1 Observability entry, got %+v", got)
	}
	// Expect exactly 3 tools joined
	wantName := "Prometheus + Grafana + Loki"
	if got[0].Name != wantName {
		t.Errorf("Observability name = %q, want %q", got[0].Name, wantName)
	}
}

func TestDetectStack_LayerOrder(t *testing.T) {
	// Verify that results always appear in the canonical layer order:
	// CNI, GitOps, Observability, Autoscaling, Ingress, Service mesh, Certificates, Secrets
	inv := &Inventory{
		DaemonSets: []appsv1.DaemonSet{
			mkDS("kube-system", "aws-node", nil), // CNI
		},
		Deployments: []appsv1.Deployment{
			mkDeploy("flux-system", "flux-source-controller", nil), // GitOps
			mkDeploy("monitoring", "prometheus", nil),              // Observability
			mkDeploy("karpenter", "karpenter", nil),                // Autoscaling
			mkDeploy("ingress", "ingress-nginx", nil),              // Ingress
			mkDeploy("istio-system", "istiod", nil),                // Service mesh
			mkDeploy("certs", "cert-manager-webhook", nil),         // Certificates
			mkDeploy("secrets", "vault-agent", nil),                // Secrets
		},
		Namespaces: []corev1.Namespace{
			mkNS("flux-system", nil),
		},
	}

	got := detectStack(inv)
	wantLayers := []string{"CNI", "GitOps", "Observability", "Autoscaling", "Ingress", "Service mesh", "Certificates", "Secrets"}
	if len(got) != len(wantLayers) {
		t.Fatalf("want %d entries, got %d: %+v", len(wantLayers), len(got), got)
	}
	for i, e := range got {
		if e.Layer != wantLayers[i] {
			t.Errorf("position %d: layer = %q, want %q", i, e.Layer, wantLayers[i])
		}
	}
}

func TestDetectStack_AWSVpcCNI(t *testing.T) {
	// aws-node maps to "AWS VPC CNI"
	inv := &Inventory{
		DaemonSets: []appsv1.DaemonSet{
			mkDS("kube-system", "aws-node", nil),
		},
	}
	got := detectStack(inv)
	if len(got) != 1 || got[0].Layer != "CNI" || got[0].Name != "AWS VPC CNI" {
		t.Errorf("aws-node detection: got %+v", got)
	}
}

func TestDetectStack_NoteContainsLocation(t *testing.T) {
	// Note must mention the resource kind and namespace/name so it's readable
	// on the dashboard (e.g., "detected: daemonset kube-system/cilium").
	inv := &Inventory{
		DaemonSets: []appsv1.DaemonSet{
			mkDS("kube-system", "cilium", nil),
		},
	}
	got := detectStack(inv)
	if len(got) == 0 {
		t.Fatal("want at least one entry")
	}
	note := got[0].Note
	if note == "" {
		t.Error("note must not be empty")
	}
	// Note should contain the resource kind indicator
	if !contains(note, "daemonset") && !contains(note, "deployment") && !contains(note, "namespace") {
		t.Errorf("note %q should describe where the tool was detected", note)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
