package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE FIRST FAILURE A STRANGER MEETS IS A KUBECONFIG ONE, AND IT WAS CLIENT-GO'S SENTENCE. With no kubeconfig
// the audit said "invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER
// environment variable" — advice about a variable this product never reads. With a context that is not there
// it named the context and not the ones that are, so the next attempt was a guess too.
func TestNew_NoKubeconfigSaysWhereItLookedAndWhatToPass(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope", "config")
	t.Setenv("KUBECONFIG", missing)
	_, err := New("", "")
	if err == nil {
		t.Fatal("no kubeconfig anywhere and New succeeded")
	}
	msg := err.Error()
	if strings.Contains(msg, "KUBERNETES_MASTER") {
		t.Errorf("the message still recommends KUBERNETES_MASTER: %s", msg)
	}
	for _, want := range []string{missing, "--kubeconfig"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not name %q: %s", want, msg)
		}
	}
}

func TestNew_AnUnknownContextNamesTheOnesThatExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	cfg := `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster: {server: "https://127.0.0.1:1"}
users:
- name: u
  user: {token: t}
contexts:
- name: prod-eu
  context: {cluster: c, user: u}
- name: staging
  context: {cluster: c, user: u}
current-context: staging
`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(path, "prod")
	if err == nil {
		t.Fatal("an unknown context was accepted")
	}
	msg := err.Error()
	for _, want := range []string{`"prod"`, "prod-eu", "staging"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not name %s: %s", want, msg)
		}
	}
}
