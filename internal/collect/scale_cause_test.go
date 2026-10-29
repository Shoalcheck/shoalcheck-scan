package collect

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A LIST CUT SHORT AND A LIST THE SERVER KEPT THROTTLING ARE CAUSES OF THEIR OWN.
//
// Both are what a large or busy cluster produces, and neither was named: a list whose page 31 failed read
// "timed out" or "could not be read", which describes a list that answered nothing, and a 429 fell through to
// "could not be read". The strings are the ones paginate and client-go produce.
func TestCauseOf_ALargeClustersFailuresAreNamed(t *testing.T) {
	throttled := apierrors.NewTooManyRequests("Too many requests, please try again later.", 0)
	cases := map[string]string{
		(&errCutShort{pages: 2, err: errors.New("etcdserver: request timed out")}).Error(): "cut short",
		(&errCutShort{pages: 30, err: throttled}).Error():                                  "cut short",
		throttled.Error(): "throttled",
		apierrors.NewTooManyRequestsError("the server has received too many requests and has asked us to try again later").Error(): "throttled",
		// Unchanged: an expired token on the first page is not a list cut short.
		apierrors.NewResourceExpired("The provided continue parameter is too old to display a consistent list result.").Error(): "could not be read",
		apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("no")).Error():                            "not permitted",
	}
	if len(cases) < 6 {
		t.Fatalf("%d cases; the table collapsed", len(cases))
	}
	for in, want := range cases {
		got := CauseOf(in)
		if got != want {
			t.Errorf("CauseOf(%q) = %q, want %q", in, got, want)
		}
		if !types.KnownCause(got) {
			t.Errorf("%q is not in the measured set, so a reading carrying it would lose it on reload", got)
		}
	}
}
