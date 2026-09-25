/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// received is one request the test listener took.
type received struct {
	method, path string
	header       http.Header
	body         string
}

// listener is a webhook receiver on a loopback address, so alert can confirm
// that the webhook channel delivered.
type listener struct {
	srv  *http.Server
	addr string

	mu  sync.Mutex
	got []received
}

// listenWebhook starts a listener on the webhook URL's address when that
// address is loopback. It returns nil, nil for an empty or non-loopback URL:
// a remote endpoint receives the alerts itself.
func listenWebhook(raw string) (*listener, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || !isLoopback(u.Hostname()) {
		return nil, nil //nolint:nilerr // the alerter reports a bad URL; not ours to listen on
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("webhook %s: the test listener speaks plain http only", raw)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return nil, fmt.Errorf("webhook test listener: %w", err)
	}
	l := &listener{addr: ln.Addr().String()}
	l.srv = &http.Server{Handler: l, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = l.srv.Serve(ln) }()
	return l, nil
}

func (l *listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	l.mu.Lock()
	l.got = append(l.got, received{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: string(b)})
	l.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// requests returns what arrived so far.
func (l *listener) requests() []received {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]received(nil), l.got...)
}

func (l *listener) close() { _ = l.srv.Shutdown(context.Background()) }

// report describes each request: method, path, the headers other than the
// ones Go's client adds, and the body.
func (r received) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", r.method, r.path)
	var names []string
	for k := range r.header {
		switch k {
		case "User-Agent", "Accept-Encoding", "Content-Length":
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(&b, "  %s: %s\n", k, strings.Join(r.header[k], ", "))
	}
	fmt.Fprintf(&b, "  %s\n", r.body)
	return b.String()
}

// isLoopback reports whether host is localhost or a loopback address.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
