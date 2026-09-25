/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tenebris-tech/alerter"
)

// TestMain keeps the suite away from the operator's ~/.alerter and ALERTER_*
// variables, so no test here reaches a real service.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "alert-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = os.Setenv("HOME", home)
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "ALERTER_") {
			_ = os.Unsetenv(k)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}

// freePort returns a loopback port nothing is listening on.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestListenWebhookOnlyForLoopback(t *testing.T) {
	for _, u := range []string{"", "https://hooks.example.com/alert", "http://10.0.0.1:8080/x", "http://[::1"} {
		l, err := listenWebhook(u)
		if l != nil || err != nil {
			t.Errorf("listenWebhook(%q) = %v, %v; want no listener", u, l, err)
		}
	}
	if _, err := listenWebhook("https://127.0.0.1:" + strings.Split(freePort(t), ":")[1] + "/x"); err == nil {
		t.Error("https loopback accepted; the listener speaks plain http")
	}
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = busy.Close() }()
	if _, err := listenWebhook("http://" + busy.Addr().String() + "/x"); err == nil {
		t.Error("expected an error for a port in use")
	}
}

func TestListenerRecordsAndReports(t *testing.T) {
	addr := freePort(t)
	l, err := listenWebhook("http://" + addr + "/hook")
	if err != nil || l == nil {
		t.Fatalf("listenWebhook: %v, %v", l, err)
	}
	defer l.close()
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/hook", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token", "t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d", resp.StatusCode)
	}
	got := l.requests()
	if len(got) != 1 {
		t.Fatalf("requests = %d", len(got))
	}
	want := "POST /hook\n  Content-Type: application/json\n  X-Token: t\n  {\"a\":1}\n"
	if r := got[0].report(); r != want {
		t.Errorf("report =\n%s\nwant\n%s", r, want)
	}
}

// TestWebhookEndToEnd sends the two test alerts through a real alerter whose
// only channel is a webhook on the test listener.
func TestWebhookEndToEnd(t *testing.T) {
	addr := freePort(t)
	t.Setenv(alerter.EnvWebhookURL, "http://"+addr+"/alert")
	t.Setenv(alerter.EnvWebhookHeaders, `{"Authorization":"Bearer test"}`)
	al, err := alerter.New(alerter.WithAppName("alert"), alerter.WithLogFile(filepath.Join(t.TempDir(), "a.txt")))
	if err != nil {
		t.Fatal(err)
	}
	l, err := listenWebhook(os.Getenv(alerter.EnvWebhookURL))
	if err != nil || l == nil {
		t.Fatalf("listenWebhook: %v", err)
	}
	defer l.close()
	send(al, time.Now())
	if err := al.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := al.Stats(); s.Sent != 3 || s.Failed != 0 {
		t.Errorf("stats = %+v", s)
	}
	got := l.requests()
	if len(got) != 3 {
		t.Fatalf("webhook requests = %d, want 3", len(got))
	}
	for i, wantName := range []string{"normal", "priority", "emergency"} {
		var p map[string]any
		if err := json.Unmarshal([]byte(got[i].body), &p); err != nil {
			t.Fatalf("body %d not JSON: %v", i, err)
		}
		if p["priority"] != float64(i) || p["priority_name"] != wantName || got[i].header.Get("Authorization") != "Bearer test" {
			t.Errorf("request %d: priority=%v %v auth=%q", i, p["priority"], p["priority_name"], got[i].header.Get("Authorization"))
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "example.com": false, "10.0.0.1": false} {
		if isLoopback(h) != want {
			t.Errorf("isLoopback(%q) = %v", h, !want)
		}
	}
}
