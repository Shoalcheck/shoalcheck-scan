package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A STOP ENDS EVERY REQUEST, DISCOVERY INCLUDED. client-go's discovery client takes no context, so a reading told
// to stop sat in ServerResourcesForGroupVersion against an API server that never answered. The server here answers
// nothing past the root; Collect is handed a context that is never cancelled, so only WithStop can end it.
func TestWithStop_EndsRequestsThatTakeNoContext(t *testing.T) {
	hung := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hung <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	body := "apiVersion: v1\nkind: Config\nclusters: [{name: k, cluster: {server: " + srv.URL + "}}]\n" +
		"users: [{name: u, user: {}}]\ncontexts: [{name: c, context: {cluster: k, user: u}}]\ncurrent-context: c\n"
	if err := os.WriteFile(kc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stop, cancel := context.WithCancel(context.Background())
	col, err := New(kc, "c", WithStop(stop))
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		col.Collect(context.Background(), nil)
	}()
	select {
	case <-hung:
	case <-time.After(10 * time.Second):
		t.Fatal("the collector never reached the server, so there is nothing in flight to stop")
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("five seconds after the stop the collector is still waiting on the server")
	}
}
