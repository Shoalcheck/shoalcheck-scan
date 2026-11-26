package prom

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SHARDED USAGE (ENG-05). One query over every container in a large cluster is the query a real Prometheus refuses:
// the default query.max-samples is fifty million, and a week of a 5-minute subquery over thirty thousand containers
// loads more than that. The refusal used to reach the report as "usage query failed — rightsizing skipped", the
// whole cluster's usage lost to its own size.
//
// So the usage is read in shards. A census counts the containers per namespace (one cheap instant query), the
// namespaces are packed into shards of at most shardContainers, and each shard runs the four queries with a
// timeout. A shard the backend refuses for its size or its time is retried over a shorter window — 7d, then 3d,
// then 1d — and a shard no window can read is named, never guessed. The coverage is stated: "usage for 412 of 500
// namespaces".

// shardContainers is the most containers one shard asks about. Two thousand containers over a week of a 5-minute
// subquery is four million samples per query, an order under the default limit even at a 30-second scrape.
const shardContainers = 2000

// shardQueryTimeout bounds each query. A Prometheus's own default is two minutes; asking for less means a query
// this cannot afford is abandoned by this side first, and retried smaller.
var shardQueryTimeout = 90 * time.Second

// usageLadder is the windows a refused shard is retried over, longest first. Nothing under a day: a window under
// a day cannot represent a daily peak, and rightsizing would bank nothing on it anyway (ENG-04).
var usageLadder = []string{"7d", "3d", "1d"}

// ShardReport is what the sharded read covered. It is written by Usage7d and read by Methodology.
type ShardReport struct {
	Namespaces int            // namespaces the census found
	Read       int            // namespaces whose usage was read, at some window
	Shards     int            // shards queried
	Shorter    map[string]int // a window shorter than the first rung → namespaces read over it
	Unread     []string       // namespaces no window could read, sorted
}

// Coverage is the sentence a reader is given when the read was partial or shortened; "" when every namespace was
// read over the full window.
func (r *ShardReport) Coverage() []string {
	if r == nil {
		return nil
	}
	var out []string
	// COUNTS ONLY, NEVER NAMES. These sentences are methodology caveats, which --redact carries as product prose;
	// a namespace name in one would leave a redacted document carrying the customer's identifier. The names go to
	// the run's log (UnreadSaid), which stays on the operator's machine.
	if len(r.Unread) > 0 {
		out = append(out, fmt.Sprintf("usage was read for %d of %d namespaces; the backend refused every window (%s) "+
			"for the other %d, so no usage-based figure is given there", r.Read, r.Namespaces, strings.Join(usageLadder, ", "),
			len(r.Unread)))
	}
	var ws []string
	for w := range r.Shorter {
		ws = append(ws, w)
	}
	sort.Strings(ws)
	for _, w := range ws {
		out = append(out, fmt.Sprintf("%d of %d namespaces were read over %s, not %s: the longer query exceeded the "+
			"backend's limits, and the p95 there is over that shorter period", r.Shorter[w], r.Namespaces, w, usageLadder[0]))
	}
	return out
}

// UnreadSaid names the namespaces no window could read, for the run's log; "" when there are none.
func (r *ShardReport) UnreadSaid() string {
	if r == nil || len(r.Unread) == 0 {
		return ""
	}
	return "usage: no window could read namespaces " + strings.Join(r.Unread, ", ")
}

// shard is a set of namespaces read together; nil names means no namespace matcher (the census found none).
type shard struct{ names []string }

// census counts the containers per namespace with one instant query.
func (c *Client) census(ctx context.Context) (map[string]int, error) {
	rows, err := c.Query(ctx, `count by (namespace) (`+cAdvisorCPUMetric+`{container!="",container!="POD"})`)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, s := range rows {
		if ns := s.Metric["namespace"]; ns != "" {
			out[ns] += int(s.Value)
		}
	}
	return out, nil
}

// packShards packs namespaces, in name order, into shards of at most limit containers. A namespace larger than
// the limit is a shard of its own.
func packShards(counts map[string]int, limit int) []shard {
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []shard
	var cur shard
	size := 0
	for _, n := range names {
		if len(cur.names) > 0 && size+counts[n] > limit {
			out = append(out, cur)
			cur, size = shard{}, 0
		}
		cur.names = append(cur.names, n)
		size += counts[n]
	}
	if len(cur.names) > 0 {
		out = append(out, cur)
	}
	return out
}

// matcher is the label matcher every query of the shard carries.
func (s shard) matcher() string {
	m := `container!="",container!="POD"`
	if len(s.names) > 0 {
		// Namespace names are DNS labels — lowercase letters, digits and '-' — so none needs escaping in a regex;
		// the anchoring is Prometheus's own (=~ matches the whole value).
		m += `,namespace=~"` + strings.Join(s.names, "|") + `"`
	}
	return m
}

// usageQueries are the four queries for one shard over one window.
func usageQueries(matcher, window string) [4]string {
	return [4]string{
		fmt.Sprintf(`quantile_over_time(0.95, rate(container_cpu_usage_seconds_total{%s}[5m])[%s:5m])`, matcher, window),
		fmt.Sprintf(`max_over_time(rate(container_cpu_usage_seconds_total{%s}[5m])[%s:5m])`, matcher, window),
		fmt.Sprintf(`quantile_over_time(0.95, container_memory_working_set_bytes{%s}[%s])`, matcher, window),
		fmt.Sprintf(`max_over_time(container_memory_working_set_bytes{%s}[%s])`, matcher, window),
	}
}

// tooBig reports whether a query error is the backend refusing the query's size or time — the errors a smaller
// window can cure. Anything else (a refused credential, a malformed query, a dead endpoint) is not retried.
func tooBig(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false // the run itself was cancelled: nothing smaller helps
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := strings.ToLower(err.Error())
	for _, k := range []string{
		"too many samples",     // Prometheus: query.max-samples
		"timed out", "timeout", // Prometheus query.timeout; a proxy's 504
		"deadline exceeded",           // this side's per-query timeout
		"exceeded the maximum",        // Mimir: max chunks / bytes per query
		"max number of series",        // Mimir: max fetched series
		"series limit",                // Thanos store limits
		"maxsamplesperquery",          // VictoriaMetrics -search.maxSamplesPerQuery
		"maxseries",                   // VictoriaMetrics -search.maxSeries / maxUniqueTimeseries
		"maxuniquetimeseries",         //
		"gateway time", "bad gateway", // a proxy in front giving up first
	} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// readShard runs the shard's four queries down the ladder. It returns the samples and the window they cover, or
// ok=false when every window was refused for its size. A non-size error is returned as is.
func (c *Client) readShard(ctx context.Context, s shard) (vectors [4][]Sample, window string, ok bool, err error) {
	for _, w := range usageLadder {
		qs := usageQueries(s.matcher(), w)
		refused := false
		for i, q := range qs {
			qctx, cancel := context.WithTimeout(ctx, shardQueryTimeout)
			rows, qerr := c.Query(qctx, q)
			cancel()
			if qerr != nil {
				if tooBig(ctx, qerr) {
					refused = true
					break
				}
				return vectors, "", false, fmt.Errorf("prom: usage query %d over %s: %w", i+1, w, qerr)
			}
			vectors[i] = rows
		}
		if !refused {
			return vectors, w, true, nil
		}
		vectors = [4][]Sample{}
	}
	return vectors, "", false, nil
}
