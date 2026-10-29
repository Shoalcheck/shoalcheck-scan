package collect

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// replay_test.go — an inventory that is not read from an API server, and a copy of one that is.
//
// `shoalcheck gate --with` judges a pull request by evaluating the cluster twice: as read, and with the request's
// manifests laid over a COPY of what was read. If the copy shares anything with the original, the change leaks
// into the reading it is being compared against and the comparison measures nothing. And a gate run from a capture,
// or from manifests alone, has no API server to read at all — the same pipeline has to run over an inventory it
// is handed.

func TestClone_IsIndependentOfTheOriginal(t *testing.T) {
	in := sampleCapture()
	in.volume = volumeOf(in)
	cp, err := in.Clone()
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if !cp.Meta.StartedAt.Equal(in.Meta.StartedAt) || cp.Meta.Context != in.Meta.Context {
		t.Fatalf("the reading clock or the context did not travel: %s %q", cp.Meta.StartedAt, cp.Meta.Context)
	}
	if len(cp.StackObjects) != len(in.StackObjects) || len(cp.PresentGVRs) != len(in.PresentGVRs) {
		t.Fatalf("the struct-keyed maps did not travel: %d/%d stack keys, %d/%d GVRs",
			len(cp.StackObjects), len(in.StackObjects), len(cp.PresentGVRs), len(in.PresentGVRs))
	}
	// THE MEASURED VOLUME TRAVELS TOO, though a capture file does not carry it: a copy of a reading read exactly
	// what the reading read, and a change laid over the copy was not read from anywhere.
	if cp.volume == nil || cp.volume.Objects != in.volume.Objects {
		t.Fatalf("the read volume did not travel: %+v", cp.volume)
	}
	cp.ClusterRoleBindings = append(cp.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "added-to-the-copy"}})
	cp.Namespaces[0].Name = "renamed-in-the-copy"
	cp.Meta.Collected = append(cp.Meta.Collected, "clusterrolebindings")
	cp.volume.Objects++
	if len(in.ClusterRoleBindings) != 0 || in.Namespaces[0].Name != "prod" || len(in.Meta.Collected) != 2 ||
		in.volume.Objects == cp.volume.Objects {
		t.Fatal("a change to the copy reached the original")
	}
}

// A collector over an inventory it was handed returns that inventory — every kind it records as read, every
// kind it records as unread, and the reading clock it was taken at — and never the same memory twice.
func TestFromInventory_ReplaysWhatItWasHanded(t *testing.T) {
	in := sampleCapture()
	in.Meta.Denied = []string{"clusterroles: forbidden"}
	c := FromInventory(in)

	var steps []string
	c.SetOnStep(func(kind string, n int, cause string) { steps = append(steps, kind+"/"+cause) })
	got, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !got.Meta.StartedAt.Equal(in.Meta.StartedAt) {
		t.Errorf("the replayed reading is dated %s; it was taken at %s", got.Meta.StartedAt, in.Meta.StartedAt)
	}
	if got.Meta.HasCollected("clusterroles") || !got.Meta.HasCollected("nodes") {
		t.Errorf("the replay changed what was read: collected %v, denied %v", got.Meta.Collected, got.Meta.Denied)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "node-a" {
		t.Errorf("the replay lost the objects: %+v", got.Nodes)
	}
	if len(steps) != 3 {
		t.Errorf("the live stream saw %v; it should see each read and unread kind once", steps)
	}
	got.Nodes[0].Name = "changed"
	again, _ := c.Collect(context.Background(), nil)
	if again.Nodes[0].Name != "node-a" || in.Nodes[0].Name != "node-a" {
		t.Error("a second replay returned the first one's memory")
	}
	if c.RESTConfig() != nil || c.Clientset() != nil {
		t.Error("a replaying collector exposes a connection it does not have")
	}
}
