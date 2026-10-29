package collect

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// WithStop ends every request this collector's clients make once stop is done — discovery included.
//
// A CONTEXT HANDED TO COLLECT IS NOT ENOUGH. client-go's discovery client takes none (it uses context.TODO), so a
// reading told to stop sat in ServerResourcesForGroupVersion against an API server that never answered. The stop
// is installed where every request passes — the transport — and outermost, so a request it refuses was never
// sent and is not counted, while one it cuts short is recorded as issued, because it was.
func WithStop(stop context.Context) Option {
	return func(o *options) { o.stop = stop }
}

type stopTransport struct {
	stop context.Context
	next http.RoundTripper
}

func (t stopTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.stop.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(r.Context())
	unhook := context.AfterFunc(t.stop, cancel)
	resp, err := t.next.RoundTrip(r.WithContext(ctx))
	if err != nil {
		unhook()
		cancel()
		return nil, err
	}
	// The body is read after RoundTrip returns, so the request's context lives until it is closed.
	resp.Body = &stopBody{ReadCloser: resp.Body, done: func() { unhook(); cancel() }}
	return resp, nil
}

type stopBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *stopBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.done)
	return err
}
