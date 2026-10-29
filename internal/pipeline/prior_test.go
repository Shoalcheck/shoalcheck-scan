package pipeline

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func TestPriorReadings_SummarisesNodePoolsOldestFirstAndSkipsTheUnloadable(t *testing.T) {
	store := &history.Store{Dir: t.TempDir()}
	b, err := os.ReadFile("../../testdata/golden/sample-audit.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden types.AuditReport
	if err := json.Unmarshal(b, &golden); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		ar := golden
		ar.GeneratedAt = t0.AddDate(0, 0, 7*i)
		if _, err := store.Save(&ar, ar.GeneratedAt); err != nil {
			t.Fatal(err)
		}
	}
	// One unreadable file among them, older than the rest so the limit window below is unaffected: skipped, not fatal.
	if err := os.WriteFile(store.Dir+"/"+history.Slug(golden.Cluster.Name)+"/2026-06-25T09-00-00Z.json", []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := PriorReadings(store, golden.Cluster.Name, 12)
	if len(got) != 3 {
		t.Fatalf("want 3 readings (the broken one skipped), got %d", len(got))
	}
	if !got[0].At.Before(got[1].At) || !got[1].At.Before(got[2].At) {
		t.Error("not oldest-first")
	}
	if len(got[0].Pools) != len(golden.Architecture.NodePools) || got[0].Pools[0].Type == "" || got[0].Pools[0].Count == 0 {
		t.Errorf("pools not summarised: %+v", got[0].Pools)
	}
	if PriorReadings(store, "no-such-cluster", 12) != nil {
		t.Error("a cluster with no history must yield nil, not an empty claim")
	}
	if PriorReadings(store, golden.Cluster.Name, 2) == nil || len(PriorReadings(store, golden.Cluster.Name, 2)) != 2 {
		t.Error("limit not honoured")
	}
}
