/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakes are the fake services channels starts.
type fakes struct {
	push, sms, hook *fakeAPI
	mail            *fakeSMTP
}

// channels starts fake Pushover, Telnyx, SMTP and webhook services and
// configures all four through the environment, as an operator would. setup,
// when given, adjusts the fakes before they start.
func channels(t *testing.T, setup ...func(*fakes)) *fakes {
	t.Helper()
	f := &fakes{push: &fakeAPI{}, sms: &fakeAPI{}, hook: &fakeAPI{}, mail: &fakeSMTP{}}
	for _, fn := range setup {
		fn(f)
	}
	serve(t, f.push, &pushoverURL)
	serve(t, f.sms, &telnyxURL)
	host, port := startSMTP(t, f.mail)
	hookSrv := httptest.NewServer(f.hook)
	t.Cleanup(hookSrv.Close)
	setEnv(t, map[string]string{
		EnvPushoverToken: "tok", EnvPushoverDest: "user1",
		EnvTelnyxAPIKey: "key", EnvSMSFrom: "+15550001111", EnvSMSTo: "+15550002222",
		EnvSMTPHost: host, EnvSMTPPort: strconv.Itoa(port),
		EnvSMTPFrom: "alerts@example.com", EnvSMTPTo: "ops@example.com",
		EnvWebhookURL: hookSrv.URL + "/alert", EnvWebhookHeaders: `{"Authorization":"Bearer hook"}`,
	})
	return f
}

func TestDeliversToEveryChannel(t *testing.T) {
	f := channels(t)
	push, sms, mail, hook := f.push, f.sms, f.mail, f.hook
	d, path, _ := newTest(t)
	if len(d.sinks) != 4 {
		t.Fatalf("channels = %d, want 4", len(d.sinks))
	}
	d.High("Provider authentication failed", "claude-cli returned 401")
	log := closeAndRead(t, d, path)

	if push.count() != 1 || sms.count() != 1 || hook.count() != 1 {
		t.Errorf("pushover %d, sms %d, webhook %d requests; want 1 each", push.count(), sms.count(), hook.count())
	}
	if hook.requests[0].Header.Get("Authorization") != "Bearer hook" || !strings.Contains(hook.bodies[0], `"title":"Provider authentication failed"`) {
		t.Errorf("webhook request %v %s", hook.requests[0].Header, hook.bodies[0])
	}
	if _, rcpts, data, _, _ := mail.got(); len(rcpts) != 1 || !strings.Contains(data, "Subject: Provider authentication failed (Claw@empire)") {
		t.Errorf("mail rcpts %v data %q", rcpts, data)
	}
	if !strings.Contains(log, "HIGH Claw@empire Provider authentication failed") || strings.Contains(log, "ERROR") {
		t.Errorf("log = %q", log)
	}
	if s := d.Stats(); s.Sent != 1 || s.Failed != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestSuppressedRepeatsReachNoChannel(t *testing.T) {
	f := channels(t)
	push, sms := f.push, f.sms
	d, path, clk := newTest(t)
	for range 3 {
		d.Low("MCP server unreachable", "fusion", "")
	}
	clk.advance(DefaultSuppressWindow)
	d.Low("MCP server unreachable", "fusion", "")
	closeAndRead(t, d, path)
	if push.count() != 2 || sms.count() != 2 {
		t.Errorf("pushover %d, sms %d; want 2 each (first, then after the window)", push.count(), sms.count())
	}
	if !strings.Contains(sms.bodies[1], "(2 repeat(s) suppressed)") {
		t.Errorf("repeat count missing from the second text: %s", sms.bodies[1])
	}
}

func TestChannelFailureLoggedOthersStillDelivered(t *testing.T) {
	f := channels(t, func(f *fakes) { f.push.status, f.push.reply = http.StatusBadRequest, `{"token":"invalid"}` })
	sms, mail := f.sms, f.mail
	d, path, _ := newTest(t)
	d.Send(Alert{High: true, Title: "Config file invalid", EventID: "config"})
	log := closeAndRead(t, d, path)

	if sms.count() != 1 {
		t.Errorf("sms requests = %d; a failing channel must not stop the others", sms.count())
	}
	if _, _, data, _, _ := mail.got(); data == "" {
		t.Error("mail not delivered after the pushover failure")
	}
	want := "2026-09-24T10:00:00-04:00 ERROR alerter: pushover delivery failed [config]: Config file invalid\n" +
		`    pushover: status 400: {"token":"invalid"}` + "\n"
	if !strings.Contains(log, want) {
		t.Errorf("log =\n%s\nwant it to contain\n%s", log, want)
	}
	if s := d.Stats(); s.Sent != 0 || s.Failed != 1 {
		t.Errorf("stats = %+v, want failed 1", s)
	}
}

func TestEveryChannelFailureLogged(t *testing.T) {
	channels(t, func(f *fakes) {
		f.push.status, f.sms.status, f.hook.status, f.mail.rejectRcpt = 500, 500, 500, "ops@"
	})
	d, path, _ := newTest(t)
	d.Low("x", "y")
	log := closeAndRead(t, d, path)
	for _, ch := range []string{"pushover", "sms", "smtp", "webhook"} {
		if !strings.Contains(log, "ERROR alerter: "+ch+" delivery failed: x\n") {
			t.Errorf("no %s failure in log:\n%s", ch, log)
		}
	}
	if s := d.Stats(); s.Failed != 1 || s.Sent != 0 {
		t.Errorf("stats = %+v; one alert, one failure", s)
	}
}

func TestHungChannelBoundedByTimeout(t *testing.T) {
	old := sinkTimeout
	sinkTimeout = 100 * time.Millisecond
	t.Cleanup(func() { sinkTimeout = old })
	f := channels(t, func(f *fakes) { f.push.delay = 10 * time.Second })
	sms := f.sms
	d, path, _ := newTest(t)
	start := time.Now()
	d.High("a", "b")
	log := closeAndRead(t, d, path)
	if time.Since(start) > 5*time.Second {
		t.Error("a hung channel held up delivery")
	}
	if sms.count() != 1 || !strings.Contains(log, "pushover delivery failed") {
		t.Errorf("sms %d; log:\n%s", sms.count(), log)
	}
}

func TestChannelsDeliveredInParallel(t *testing.T) {
	old := sinkTimeout
	sinkTimeout = 300 * time.Millisecond
	t.Cleanup(func() { sinkTimeout = old })
	channels(t, func(f *fakes) {
		f.push.delay, f.sms.delay, f.mail.silent = 10*time.Second, 10*time.Second, true
	})
	d, path, _ := newTest(t)
	start := time.Now()
	d.High("a", "b")
	log := closeAndRead(t, d, path)
	// Three hung channels in turn would take three timeouts.
	if el := time.Since(start); el > 2*sinkTimeout {
		t.Errorf("delivery took %v; channels were not sent in parallel", el)
	}
	if n := strings.Count(log, "delivery failed"); n != 3 {
		t.Errorf("%d failures logged, want 3 (the webhook answers):\n%s", n, log)
	}
}

func TestLogFailureWithChannelsCounted(t *testing.T) {
	push := channels(t).push
	d, _, _ := newTest(t)
	d.log.mu.Lock()
	d.log.w = failingWriter{}
	d.log.mu.Unlock()
	d.High("x", "y")
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if push.count() != 1 {
		t.Error("a log failure must not stop channel delivery")
	}
	if s := d.Stats(); s.Failed != 1 || s.Sent != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestFormatFailureMultiline(t *testing.T) {
	err := errors.Join(errors.New("sms to +1: a"), errors.New("sms to +2: b"))
	got := formatFailure(sample.Time, "sms", Alert{Title: "t"}, err)
	want := "2026-09-24T10:00:00-04:00 ERROR alerter: sms delivery failed: t\n    sms to +1: a\n    sms to +2: b\n"
	if got != want {
		t.Errorf("formatFailure = %q", got)
	}
}
