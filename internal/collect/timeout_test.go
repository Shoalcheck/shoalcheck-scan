package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// AN API SERVER THAT NEVER ANSWERS ENDS THE READING, IT DOES NOT HOLD IT.
//
// Measured against a TLS listener that completed the handshake and never replied: `audit` sat at "collecting…"
// for 296 seconds — until the listener itself went away — and then reported "0 problems". The config carried no
// timeout, and the first request of a collection, the server's version, takes no context; against a black-holed
// address it was 203 seconds of ten-second handshake timeouts, one list after another. A scheduled run would hold
// its lock for hours. Every request is now bounded, and once the server has been shown not to answer, the lists
// that would wait for it one by one are recorded with that cause instead of being sent.
func TestCollect_AServerThatNeverAnswersEndsTheReadingPromptly(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(done)

	c, err := New(kubeconfigFor(t, srv.URL), "c", WithRequestTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	type result struct {
		inv *Inventory
		err error
	}
	ch := make(chan result, 1)
	start := time.Now()
	go func() {
		inv, err := c.Collect(context.Background(), nil)
		ch <- result{inv, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Collect: %v", r.err)
		}
		if len(r.inv.Meta.Collected) != 0 {
			t.Errorf("a server that answered nothing produced collected kinds: %v", r.inv.Meta.Collected)
		}
		if len(r.inv.Meta.Denied) == 0 {
			t.Error("nothing was recorded as unread, so the reading would look complete")
		}
		for _, d := range r.inv.Meta.Denied {
			if _, cause := kindAndCause(d); cause != "timed out" {
				t.Errorf("a list against a silent server was classified %q: %s", cause, d)
				break
			}
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("a silent server held the collection for %s; each list waited for it in turn", el)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a collection against a server that never answers had not ended after 15s")
	}
}

// The default is bounded. A collector built the way every audit builds it carries a per-request timeout, so no
// single request can hold a reading open indefinitely.
func TestNew_EveryRequestIsBoundedByDefault(t *testing.T) {
	c, err := New(kubeconfigFor(t, "http://127.0.0.1:1"), "c")
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.Timeout <= 0 {
		t.Error("the rest.Config carries no timeout, so a request to a server that never answers waits forever")
	}
}
