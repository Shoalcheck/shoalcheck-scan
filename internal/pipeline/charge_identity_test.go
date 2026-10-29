package pipeline

import (
	"context"
	"io"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A REDACTED READING IS STILL A READING OF THE SAME CLUSTER, and the licence has to be able to tell.
//
// Redaction tokenizes the kube-system UID inside Run, and the CLI charged the cap afterwards from the document:
// `audit --redact` of a cluster already read cost a second slot (the ledger held the real UID and uid-5e4227), and
// on a key bound to the cluster's fingerprint the redacted reading was refused outright, because the fingerprint
// of a token matches nothing a shop issued. The identity the cap counts is recorded before redaction, in a field
// that is never serialized, so the document stays redacted and the count stays true.
func TestRun_RedactionKeepsTheChargeIdentity(t *testing.T) {
	col := collect.NewWithClient(fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: k8stypes.UID("real-uid-0001")}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}},
	))
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "prod-eu", Redact: true, Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ar.Methodology.RunBasis == nil || ar.Methodology.RunBasis.ClusterUID == "real-uid-0001" {
		t.Fatalf("precondition: the redacted document must not carry the real UID: %+v", ar.Methodology.RunBasis)
	}
	uid, name := ar.ChargeIdentity()
	if uid != "real-uid-0001" || name != "prod-eu" {
		t.Errorf("the charge identity of a redacted reading is (%q, %q); want the cluster's own (real-uid-0001, prod-eu)", uid, name)
	}
}
