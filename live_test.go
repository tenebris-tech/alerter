/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLive sends one real alert through every channel configured in the
// operator's ~/.alerter, with the caller's own ALERTER_* variables taking
// precedence as they would in a real process. It runs only with ALERTER_LIVE_TEST=1 (make
// test-live) and fails unless each configured channel accepted the alert.
func TestLive(t *testing.T) {
	if !live {
		t.Skip("set ALERTER_LIVE_TEST=1 to send real alerts from ~/.alerter")
	}
	unsetAfter(t, allChannelVars...)
	t.Setenv("HOME", realHome)
	for k, v := range liveEnv {
		if k != EnvLogFile {
			t.Setenv(k, v)
		}
	}
	path := filepath.Join(t.TempDir(), "alerts.txt")
	host, _ := os.Hostname()
	d, err := New(WithAppName("alerter live test"), WithInstanceName(host), WithLogFile(path))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hook := liveWebhookListener(t)
	var names []string
	for _, s := range d.sinks {
		names = append(names, s.name())
	}
	t.Logf("channels configured: %v", names)
	if len(names) == 0 {
		t.Fatal("no channel configured in ~/.alerter")
	}
	d.Urgent("Live delivery test", "alerter sent this to check its delivery channels; no action needed")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b, _ := os.ReadFile(path) //nolint:gosec // test temp file
	t.Logf("alert log:\n%s", b)
	if s := d.Stats(); s.Sent != 1 || s.Failed != 0 {
		t.Errorf("stats = %+v; see the alert log above", s)
	}
	if hook != nil {
		if n := hook.count(); n != 1 {
			t.Errorf("webhook listener received %d request(s), want 1", n)
		} else {
			t.Logf("webhook listener received: %s", hook.bodies[0])
		}
	}
}

// liveWebhookListener listens on the configured webhook URL when it is a
// loopback address, standing in for the receiver; nil otherwise.
func liveWebhookListener(t *testing.T) *fakeAPI {
	t.Helper()
	u, err := url.Parse(os.Getenv(EnvWebhookURL))
	if err != nil || u.Scheme != "http" || !isLoopback(u.Hostname()) {
		return nil
	}
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		t.Fatalf("webhook listener on %s: %v", u.Host, err)
	}
	f := &fakeAPI{}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}
