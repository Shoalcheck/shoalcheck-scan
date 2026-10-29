package collect

import (
	"context"
	"testing"
)

// A READING TAKEN THROUGH THE CURRENT CONTEXT IS NAMED AFTER IT.
//
// `shoalcheck audit --output r.html --save-history`, with no --context, named the cluster "cluster": the collector
// kept the --context FLAG as the context name, and the flag was empty. The report's title said "cluster", every
// cluster read that way shared history/cluster/, and `shoalcheck findings` — which resolves the current context's
// name, as it should — then said "no saved reading" for the reading just taken.
func TestNew_TheCurrentContextIsTheContextName(t *testing.T) {
	srv, _ := fakeAPIServer(t)
	defer srv.Close()
	c, err := New(kubeconfigFor(t, srv.URL), "")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Meta.Context != "c" {
		t.Errorf("a reading through the current context is named %q; the kubeconfig's current-context is \"c\"", inv.Meta.Context)
	}
}
