package prom

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// THE REAL-PROMETHEUS PROOF (ENG-05, decision D4). Two tests, both skipped unless their environment is set, and
// driven by scripts/proof/eng05-real-prometheus.sh:
//
//   - TestWriteBackfill writes one UTC day of cAdvisor-shaped series as OpenMetrics for promtool's backfill:
//     container_cpu_usage_seconds_total (a counter with a daily cycle) and container_memory_working_set_bytes,
//     one sample a minute, for SHOALCHECK_BACKFILL_CONTAINERS containers across a few hundred namespaces.
//   - TestUsageSharded_OnARealPrometheus reads that Prometheus: the single query the engine used to send must be
//     refused at the server's limits, and the sharded read must read every container.
//
// Nothing here runs in make ci; the script records what it measured in docs/engine/eng05-real-prometheus.md.

// backfillNamespaces deals n containers into namespaces of uneven size, deterministically: a few hundred teams
// between 15 and 160 containers, as a large multi-tenant cluster has.
func backfillNamespaces(n int) []int {
	var sizes []int
	left := n
	for i := 0; left > 0; i++ {
		s := 15 + (i*37)%146
		if s > left {
			s = left
		}
		sizes = append(sizes, s)
		left -= s
	}
	return sizes
}

func TestWriteBackfill(t *testing.T) {
	dir := os.Getenv("SHOALCHECK_BACKFILL_DIR")
	if dir == "" {
		t.Skip("SHOALCHECK_BACKFILL_DIR not set: the backfill is the D4 proof's, see scripts/proof/eng05-real-prometheus.sh")
	}
	containers, _ := strconv.Atoi(os.Getenv("SHOALCHECK_BACKFILL_CONTAINERS"))
	end, _ := strconv.ParseInt(os.Getenv("SHOALCHECK_BACKFILL_END"), 10, 64)
	day, _ := strconv.Atoi(os.Getenv("SHOALCHECK_BACKFILL_DAY")) // 0 is the day ending at end
	if containers <= 0 || end <= 0 {
		t.Fatal("SHOALCHECK_BACKFILL_CONTAINERS and SHOALCHECK_BACKFILL_END (unix seconds) are required")
	}
	step := int64(60)
	if v, _ := strconv.ParseInt(os.Getenv("SHOALCHECK_BACKFILL_STEP"), 10, 64); v > 0 {
		step = v
	}
	hi := end - int64(day)*86400
	lo := hi - 86400
	f, err := os.Create(filepath.Join(dir, fmt.Sprintf("day-%d.om", day)))
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 4<<20)
	type series struct {
		labels string
		i      int
	}
	var all []series
	i := 0
	for ns, size := range backfillNamespaces(containers) {
		for c := 0; c < size; c++ {
			pod, name := c, "app"
			all = append(all, series{fmt.Sprintf(`{namespace="team-%03d",pod="svc-%d-7f9c",container="%s"}`, ns, pod, name), i})
			i++
		}
	}
	buf := make([]byte, 0, 128)
	fmt.Fprintln(w, "# TYPE container_cpu_usage_seconds_total counter")
	for _, s := range all {
		rate := 0.02 + float64(s.i%50)/100 // cores
		for ts := lo; ts < hi; ts += step {
			// A daily cycle around the mean: the counter is its integral, so it only rises.
			x := float64(ts)
			v := rate*x + rate*0.5*86400/(2*math.Pi)*(1-math.Cos(2*math.Pi*x/86400))
			buf = append(buf[:0], "container_cpu_usage_seconds_total"...)
			buf = append(buf, s.labels...)
			buf = append(buf, ' ')
			buf = strconv.AppendFloat(buf, v, 'f', 3, 64)
			buf = append(buf, ' ')
			buf = strconv.AppendInt(buf, ts, 10)
			buf = append(buf, '\n')
			w.Write(buf)
		}
	}
	fmt.Fprintln(w, "# TYPE container_memory_working_set_bytes gauge")
	for _, s := range all {
		base := float64(64<<20) + float64(s.i%200)*float64(2<<20)
		for ts := lo; ts < hi; ts += step {
			v := base * (1 + 0.3*math.Sin(2*math.Pi*float64(ts)/86400+float64(s.i)))
			buf = append(buf[:0], "container_memory_working_set_bytes"...)
			buf = append(buf, s.labels...)
			buf = append(buf, ' ')
			buf = strconv.AppendFloat(buf, math.Round(v), 'f', 0, 64)
			buf = append(buf, ' ')
			buf = strconv.AppendInt(buf, ts, 10)
			buf = append(buf, '\n')
			w.Write(buf)
		}
	}
	fmt.Fprintln(w, "# EOF")
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("day %d: %d containers, %d namespaces, %d..%d", day, len(all), len(backfillNamespaces(containers)), lo, hi)
}

func TestUsageSharded_OnARealPrometheus(t *testing.T) {
	url := os.Getenv("SHOALCHECK_PROOF_PROMETHEUS_URL")
	if url == "" {
		t.Skip("SHOALCHECK_PROOF_PROMETHEUS_URL not set: the D4 proof, see scripts/proof/eng05-real-prometheus.sh")
	}
	want, _ := strconv.Atoi(os.Getenv("SHOALCHECK_BACKFILL_CONTAINERS"))
	c := NewClient(url, PromAuth{Mode: AuthNone})
	ctx := context.Background()

	start := time.Now()
	_, err := c.Query(ctx, `quantile_over_time(0.95, rate(container_cpu_usage_seconds_total{container!="",container!="POD"}[5m])[7d:5m])`)
	t.Logf("single query, as the engine sent it before ENG-05: %v after %s", err, time.Since(start).Round(time.Millisecond))
	if os.Getenv("SHOALCHECK_PROOF_EXPECT_REFUSAL") == "1" && (err == nil || !tooBig(ctx, err)) {
		t.Fatalf("the single query was not refused for its size: %v", err)
	}

	start = time.Now()
	u, rep, err := c.UsageSharded(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sharded read: %d containers, %d of %d namespaces, %d shards, shorter %v, unread %d, in %s",
		len(u), rep.Read, rep.Namespaces, rep.Shards, rep.Shorter, len(rep.Unread), time.Since(start).Round(time.Millisecond))
	for _, l := range rep.Coverage() {
		t.Logf("coverage: %s", l)
	}
	if len(u) != want || rep.Read != rep.Namespaces || len(rep.Unread) != 0 {
		t.Fatalf("the sharded read did not read every container: %d of %d", len(u), want)
	}
	if w := os.Getenv("SHOALCHECK_PROOF_EXPECT_SHORTER"); w != "" && rep.Shorter[w] == 0 {
		t.Fatalf("no namespace was read over %s: the ladder was not exercised", w)
	}
	var zero int
	for _, x := range u {
		if x.CPUCoresP95 <= 0 || x.MemBytesMax <= 0 {
			zero++
		}
	}
	if zero > 0 {
		t.Fatalf("%d containers came back without a CPU p95 or a memory max", zero)
	}
	if !strings.HasPrefix(os.Getenv("SHOALCHECK_PROOF_QUIET"), "1") {
		t.Logf("sample: %+v", u["team-000/svc-0-7f9c/app"])
	}
}
