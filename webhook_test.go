/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookConfig(t *testing.T) {
	setEnv(t, map[string]string{
		EnvWebhookURL:     "https://hooks.example.com/alert?k=1",
		EnvWebhookHeaders: `{"Authorization":"Bearer abc==","X-Tag":"a, b=c"}`,
	})
	sinks, err := sinksFromEnv()
	if err != nil || len(sinks) != 1 || sinks[0].name() != "webhook" {
		t.Fatalf("sinks = %v, err = %v", sinks, err)
	}
	w := sinks[0].(*webhookSink)
	if w.url != "https://hooks.example.com/alert?k=1" || w.headers["Authorization"] != "Bearer abc==" || w.headers["X-Tag"] != "a, b=c" {
		t.Errorf("webhook = %+v", w)
	}

	t.Setenv(EnvWebhookHeaders, "")
	sinks, err = sinksFromEnv()
	if err != nil || len(sinks[0].(*webhookSink).headers) != 0 {
		t.Errorf("headers are optional: %v", err)
	}
}

func TestWebhookConfigErrors(t *testing.T) {
	cases := map[string]struct{ url, headers, want string }{
		"headers without url": {"", `{"A":"b"}`, EnvWebhookURL},
		"no scheme":           {"hooks.example.com/x", "", "http or https"},
		"ftp":                 {"ftp://hooks.example.com/x", "", "http or https"},
		"no host":             {"https:///x", "", "http or https"},
		"unparsable":          {"http://[::1", "", "http or https"},
		"headers not json":    {"https://h/x", "Authorization=Bearer x", "JSON object"},
		"headers a list":      {"https://h/x", `["A","b"]`, "JSON object"},
		"header value number": {"https://h/x", `{"A":1}`, "JSON object"},
		"bad header name":     {"https://h/x", `{"Bad Name":"x"}`, `"Bad Name"`},
		"empty header name":   {"https://h/x", `{"":"x"}`, `""`},
		"newline in value":    {"https://h/x", `{"X-A":"x\r\nInjected: y"}`, `"X-A"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			setEnv(t, map[string]string{EnvWebhookURL: tc.url, EnvWebhookHeaders: tc.headers})
			_, err := sinksFromEnv()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestWebhookPayload(t *testing.T) {
	var got map[string]any
	if err := json.Unmarshal([]byte(webhookPayload(sample)), &got); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	want := map[string]any{
		"priority": float64(1), "priority_name": "urgent",
		"title": "Provider authentication failed", "description": "claude-cli returned 401",
		"details": "run `claude login`\non the host\n", "event_id": "claude-cli",
		"app": "ClawEh", "instance": "empire", "time": "2026-09-24T10:00:00-04:00",
		"repeats": float64(3), "subject": "Provider authentication failed (ClawEh@empire)",
	}
	if len(got) != len(want) {
		t.Errorf("payload has %d fields, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}

	var normal map[string]any
	_ = json.Unmarshal([]byte(webhookPayload(Alert{Title: "t", Time: sample.Time})), &normal)
	if normal["priority"] != float64(0) || normal["priority_name"] != "normal" || normal["repeats"] != float64(0) {
		t.Errorf("normal payload = %v", normal)
	}
	for _, k := range []string{"details", "event_id", "app", "instance"} {
		if _, ok := normal[k]; ok {
			t.Errorf("empty %s should be omitted", k)
		}
	}
}

func TestWebhookSend(t *testing.T) {
	f := &fakeAPI{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	w := &webhookSink{url: srv.URL + "/hook", headers: map[string]string{"Authorization": "Bearer t", "X-Source": "alerter"}, http: newHTTPClient()}
	if err := w.send(context.Background(), sample); err != nil {
		t.Fatalf("send: %v", err)
	}
	r := f.requests[0]
	if r.Method != http.MethodPost || r.URL.Path != "/hook" || r.Header.Get("Content-Type") != "application/json" ||
		r.Header.Get("Authorization") != "Bearer t" || r.Header.Get("X-Source") != "alerter" {
		t.Errorf("request: %s %s %v", r.Method, r.URL.Path, r.Header)
	}
	if f.bodies[0] != webhookPayload(sample) {
		t.Errorf("body = %s", f.bodies[0])
	}

	// A configured Content-Type wins over the default.
	w.headers = map[string]string{"Content-Type": "application/vnd.alert+json"}
	_ = w.send(context.Background(), sample)
	if got := f.requests[1].Header.Get("Content-Type"); got != "application/vnd.alert+json" {
		t.Errorf("content type = %q", got)
	}
}

func TestWebhookErrors(t *testing.T) {
	f := &fakeAPI{status: http.StatusForbidden, reply: "denied"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	w := &webhookSink{url: srv.URL, http: newHTTPClient()}
	if err := w.send(context.Background(), sample); err == nil || !strings.Contains(err.Error(), "status 403: denied") {
		t.Errorf("error = %v", err)
	}
	w.url = "http://127.0.0.1:1/unreachable"
	if err := w.send(context.Background(), sample); err == nil {
		t.Error("expected a connection error")
	}
	w.url = "://bad"
	if err := w.send(context.Background(), sample); err == nil {
		t.Error("expected a request error")
	}
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	elsewhere := &fakeAPI{}
	other := httptest.NewServer(elsewhere)
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	w := &webhookSink{url: redirect.URL, headers: map[string]string{"Authorization": "Bearer secret"}, http: newHTTPClient()}
	if err := w.send(context.Background(), sample); err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Errorf("error = %v", err)
	}
	if elsewhere.count() != 0 {
		t.Error("the redirect was followed, carrying the headers to another host")
	}
}

func TestValidHeaderName(t *testing.T) {
	for s, want := range map[string]bool{
		"Authorization": true, "X-Api-Key": true, "x_custom.1~": true,
		"": false, "Bad Name": false, "Colon:": false, "Ünicode": false,
	} {
		if validHeaderName(s) != want {
			t.Errorf("validHeaderName(%q) = %v", s, !want)
		}
	}
}

func TestWebhookPayloadLevels(t *testing.T) {
	for _, tc := range []struct {
		in   int
		num  float64
		name string
	}{
		{Normal, 0, "normal"}, {Urgent, 1, "urgent"}, {Emergency, 2, "emergency"},
		{-1, 0, "normal"}, {3, 0, "normal"},
	} {
		var p map[string]any
		if err := json.Unmarshal([]byte(webhookPayload(Alert{Priority: tc.in, Title: "t"})), &p); err != nil {
			t.Fatal(err)
		}
		if p["priority"] != tc.num || p["priority_name"] != tc.name {
			t.Errorf("level %d: priority %v %v, want %v %s", tc.in, p["priority"], p["priority_name"], tc.num, tc.name)
		}
		if _, ok := p["high"]; ok {
			t.Error("payload still has the removed high field")
		}
	}
}
