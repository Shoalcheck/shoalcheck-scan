package collect

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
)

// A READING WITH NO FINDINGS SAYS SO AS AN EMPTY LIST, NOT AS null.
//
// A narrow identity's reading of the mesh testbed — four kinds read, no finding — was written with
// "findings": null. Null is the encoding for "no answer"; an empty list is the answer "none". A consumer that
// iterates the field (`jq '.findings | length'`, a dashboard, a script) gets an error or a null where the reading
// holds a zero, and the same field reads two ways depending on whether anything was found.
func TestBuildReport_NoFindingsIsAnEmptyListNotNull(t *testing.T) {
	ar := BuildReport(twoM6iLargeEKS(), nil, "c", 0, pricing.Embedded())
	b, err := json.Marshal(ar)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"findings":null`) || !strings.Contains(string(b), `"findings":[]`) {
		t.Errorf("an empty reading's findings are not an empty list: %s", string(b)[:200])
	}
}
