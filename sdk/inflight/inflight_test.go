package inflight

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/zap-proto/zip"
)

// The drain ends when the last handler returns, while a stream the client is
// still reading stays open: the stream's handler returned when it began writing.
func TestDrainWaitsForHandlersNotStreams(t *testing.T) {
	app := zip.New(zip.Config{AppName: "inflight", DisableStartupMessage: true})
	app.Use(zip.H(Count))
	release := make(chan struct{})
	app.Raw(http.MethodGet, "/slow", func(c *zip.Ctx) error {
		<-release
		return c.JSON(200, "done")
	})
	app.Raw(http.MethodGet, "/stream", func(c *zip.Ctx) error {
		return c.SendStreamWriter(func(w *bufio.Writer) {
			for {
				if _, err := w.WriteString(": ping\n\n"); err != nil || w.Flush() != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	})

	at := filepath.Join(t.TempDir(), "s.sock")
	go func() { _ = app.Listen("http://" + at) }()
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", at)
		},
	}}
	var stream *http.Response
	for range 200 {
		r, err := hc.Get("http://x/stream")
		if err == nil {
			stream = r
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stream == nil {
		t.Fatal("stream never opened")
	}
	defer stream.Body.Close()
	if _, err := bufio.NewReader(stream.Body).ReadString('\n'); err != nil {
		t.Fatalf("read stream: %v", err)
	}

	slow := make(chan string, 1)
	go func() {
		r, err := hc.Get("http://x/slow")
		if err != nil {
			slow <- err.Error()
			return
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		slow <- string(b)
	}()
	for handling.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := Drain(context.Background())
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("the drain ended while a handler was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the drain waited on the open stream after the last handler returned")
	}
	if got := <-slow; got != `"done"` {
		t.Fatalf("slow request = %q, want it served", got)
	}
}
