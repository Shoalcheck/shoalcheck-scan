package pipeline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A RUN THAT READ NOTHING IS NOT A READING.
//
// Collect returns no error when every list fails: it records each failure and hands back an empty inventory, and
// the rules, run over nothing, find nothing. That is the right shape for a PARTIAL reading — a narrow identity
// that can list nodes and not pods still has something to say, and says what it could not read. It is the wrong
// shape for a run in which nothing came back at all: the document that results has zero findings, a headline
// that leads with "28 of 28 kinds could not be read", and — on every surface that counts or keeps a reading — the
// standing of a real one. `audit` wrote it at exit 0, kept it in history, and charged a licence slot under a key
// made of the context's name, so three attempts through a dead VPN used up a three-cluster licence for thirty
// days. The fleet loop had already learned this and skipped such a cluster; the single-cluster audit had not.
//
// So the question is asked once, here, and every surface asks it the same way: the CLI before it charges or
// writes anything, the fleet loop before it counts a member, the app before it shows a reading.
//
// DISCOVERY ALONE IS NOTHING. "server-resources" is the API server describing itself, and it answers for an
// identity that may list nothing else — the impersonated ServiceAccount with no role binding read exactly that
// one step. A run whose only success is discovery has read no object of the cluster.

// NothingReadError is the refusal: the run reached no object, and why, in the classified words the report uses.
type NothingReadError struct {
	Cluster string
	// Cause is the reason in a sentence, built from the classified causes collect measured — never the API's own
	// error text, which carries the server's address and the caller's identity.
	Cause string
}

func (e *NothingReadError) Error() string {
	return fmt.Sprintf("nothing could be read from %s: %s, so this run is not a reading of it", e.Cluster, e.Cause)
}

// NothingRead returns a *NothingReadError when ar records no successful list of any object kind, and nil when
// anything was read. It reads only the methodology, so it answers for a reading on disk as well as a live one.
func NothingRead(ar *types.AuditReport) error {
	if ar == nil {
		return nil
	}
	for _, k := range ar.Methodology.CollectedKinds {
		if k != "server-resources" {
			return nil
		}
	}
	name := ar.Cluster.Name
	if name == "" {
		name = "this cluster"
	}
	return &NothingReadError{Cluster: name, Cause: nothingReadCause(ar.Methodology.Unread)}
}

// nothingReadCause says why, from the classified causes. One cause is the common case — a refused connection
// refuses every list — and is said as a sentence about the API server; several are counted, because a mixed
// failure is itself information.
func nothingReadCause(unread []types.UnreadKind) string {
	counts := map[string]int{}
	for _, u := range unread {
		counts[u.Cause]++
	}
	sentence := map[string]string{
		"not reachable":                     "the API server could not be reached",
		"not permitted":                     "every list came back not permitted — the credentials were not accepted, or this identity may list nothing",
		"timed out":                         "the API server did not answer in time",
		"not served by this cluster":        "the API server serves none of the kinds a reading needs",
		"credentials not accepted":          "the API server did not accept these credentials (401) — sign in again or refresh the token, then read again",
		"credentials could not be obtained": "the kubeconfig's credential plugin did not produce credentials — run it by hand to see why (it may need a sign-in, or may not be installed)",
		"certificate not accepted":          "the API server's certificate was not accepted (x509) — the kubeconfig's certificate authority, or its server address, is not the one this cluster presents",
		"cut short":                         "every list stopped part-way, and the pages read before it stopped were not kept",
		"throttled":                         "the API server kept answering 429 Too Many Requests after every retry — read again when it is less busy",
	}
	if len(counts) == 1 {
		for cause, n := range counts {
			if s, ok := sentence[cause]; ok {
				return fmt.Sprintf("%s (%s)", s, nWord(n, "list", "lists")+" "+cause)
			}
			return fmt.Sprintf("every list failed (%s %s)", nWord(n, "list", "lists"), cause)
		}
	}
	if len(counts) == 0 {
		return "no list succeeded and no cause was recorded"
	}
	causes := make([]string, 0, len(counts))
	for cause := range counts {
		causes = append(causes, cause)
	}
	sort.Strings(causes)
	parts := make([]string, 0, len(causes))
	for _, cause := range causes {
		parts = append(parts, fmt.Sprintf("%d %s", counts[cause], cause))
	}
	return "every list failed (" + strings.Join(parts, ", ") + ")"
}
