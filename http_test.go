/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI records every request body and answers with status.
type fakeAPI struct {
	mu       sync.Mutex
	status   int
	reply    string
	delay    time.Duration
	requests []*http.Request
	bodies   []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r)
	f.bodies = append(f.bodies, string(b))
	status, reply, delay := f.status, f.reply, f.delay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, reply)
}

func (f *fakeAPI) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

// serve starts f and points *endpoint at it for the test.
func serve(t *testing.T, f *fakeAPI, endpoint *string) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	old := *endpoint
	*endpoint = srv.URL + "/api"
	t.Cleanup(func() { *endpoint = old })
}

func TestPushoverSend(t *testing.T) {
	f := &fakeAPI{reply: `{"status":1}`}
	serve(t, f, &pushoverURL)
	p := &pushoverSink{token: "apptoken", dests: []string{"user1", "user2"}, http: &http.Client{}}
	if err := p.send(context.Background(), sample); err != nil {
		t.Fatalf("send: %v", err)
	}
	if f.count() != 2 {
		t.Fatalf("requests = %d, want one per destination", f.count())
	}
	for i, user := range []string{"user1", "user2"} {
		r := f.requests[i]
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("request %d: %s %s", i, r.Method, r.Header.Get("Content-Type"))
		}
		form, err := url.ParseQuery(f.bodies[i])
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"token": "apptoken", "user": user, "priority": "1",
			"title":     subject(sample),
			"message":   body(sample),
			"timestamp": "1790258400",
		}
		for k, v := range want {
			if form.Get(k) != v {
				t.Errorf("request %d: %s = %q, want %q", i, k, form.Get(k), v)
			}
		}
	}
}

func TestPushoverLowPriorityAndLimits(t *testing.T) {
	f := &fakeAPI{}
	serve(t, f, &pushoverURL)
	p := &pushoverSink{token: "t", dests: []string{"u"}, http: &http.Client{}}
	a := Alert{Title: strings.Repeat("T", 400), Details: strings.Repeat("d", 2000), Time: sample.Time}
	if err := p.send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	form, _ := url.ParseQuery(f.bodies[0])
	if form.Get("priority") != "0" {
		t.Errorf("low priority = %q", form.Get("priority"))
	}
	if n := len([]rune(form.Get("title"))); n != pushoverTitleMax {
		t.Errorf("title length %d", n)
	}
	if n := len([]rune(form.Get("message"))); n != pushoverMessageMax {
		t.Errorf("message length %d", n)
	}
}

func TestPushoverErrors(t *testing.T) {
	f := &fakeAPI{status: http.StatusBadRequest, reply: `{"user":"invalid","status":0}`}
	serve(t, f, &pushoverURL)
	p := &pushoverSink{token: "t", dests: []string{"bad1", "bad2"}, http: &http.Client{}}
	err := p.send(context.Background(), sample)
	if err == nil || !strings.Contains(err.Error(), "status 400") || !strings.Contains(err.Error(), `"user":"invalid"`) {
		t.Errorf("error = %v", err)
	}
	if f.count() != 2 {
		t.Errorf("a failing destination must not stop the next: %d requests", f.count())
	}

	pushoverURL = "http://127.0.0.1:1/unreachable"
	if err := p.send(context.Background(), sample); err == nil {
		t.Error("expected a connection error")
	}
	pushoverURL = "://bad"
	if err := p.send(context.Background(), sample); err == nil {
		t.Error("expected a request error")
	}
}

func TestSMSSend(t *testing.T) {
	f := &fakeAPI{reply: `{"data":{"id":"x"}}`}
	serve(t, f, &telnyxURL)
	s := &smsSink{apiKey: "KEY123", from: "+15550001111", to: []string{"+15550002222", "+15550003333"}, http: &http.Client{}}
	if err := s.send(context.Background(), sample); err != nil {
		t.Fatalf("send: %v", err)
	}
	if f.count() != 2 {
		t.Fatalf("requests = %d, want one per recipient", f.count())
	}
	for i, to := range s.to {
		r := f.requests[i]
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer KEY123" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request %d: %s auth=%q type=%q", i, r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
		}
		var got map[string]string
		if err := json.Unmarshal([]byte(f.bodies[i]), &got); err != nil {
			t.Fatal(err)
		}
		if got["from"] != "+15550001111" || got["to"] != to || got["text"] != smsText(sample) || len(got) != 3 {
			t.Errorf("request %d body = %v", i, got)
		}
	}
}

func TestSMSErrors(t *testing.T) {
	f := &fakeAPI{status: http.StatusUnauthorized, reply: `{"errors":[{"code":"10009"}]}`}
	serve(t, f, &telnyxURL)
	s := &smsSink{apiKey: "k", from: "+15550001111", to: []string{"+15550002222", "+15550003333"}, http: &http.Client{}}
	err := s.send(context.Background(), sample)
	if err == nil || !strings.Contains(err.Error(), "telnyx status 401") || !strings.Contains(err.Error(), "+15550003333") {
		t.Errorf("error = %v", err)
	}
	if f.count() != 2 {
		t.Errorf("a failing recipient must not stop the next: %d requests", f.count())
	}

	telnyxURL = "http://127.0.0.1:1/unreachable"
	if err := s.send(context.Background(), sample); err == nil {
		t.Error("expected a connection error")
	}
	telnyxURL = "://bad"
	if err := s.send(context.Background(), sample); err == nil {
		t.Error("expected a request error")
	}
}

func TestHTTPSinkHonoursContext(t *testing.T) {
	f := &fakeAPI{delay: 5 * time.Second}
	serve(t, f, &pushoverURL)
	p := &pushoverSink{token: "t", dests: []string{"u"}, http: &http.Client{}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := p.send(ctx, sample); err == nil {
		t.Error("expected a timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("send did not stop at the context deadline")
	}
}
