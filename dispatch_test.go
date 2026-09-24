/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// channels starts fake Pushover, Telnyx and SMTP services and configures all
// three through the environment, as an operator would. setup, when given,
// adjusts the fakes before they start.
func channels(t *testing.T, setup ...func(push, sms *fakeAPI, mail *fakeSMTP)) (push, sms *fakeAPI, mail *fakeSMTP) {
	t.Helper()
	push, sms, mail = &fakeAPI{}, &fakeAPI{}, &fakeSMTP{}
	for _, f := range setup {
		f(push, sms, mail)
	}
	serve(t, push, &pushoverURL)
	serve(t, sms, &telnyxURL)
	host, port := startSMTP(t, mail)
	setEnv(t, map[string]string{
		EnvPushoverToken: "tok", EnvPushoverDest: "user1",
		EnvTelnyxAPIKey: "key", EnvSMSFrom: "+15550001111", EnvSMSTo: "+15550002222",
		EnvSMTPHost: host, EnvSMTPPort: strconv.Itoa(port),
		EnvSMTPFrom: "alerts@example.com", EnvSMTPTo: "ops@example.com",
	})
	return push, sms, mail
}

func TestDeliversToEveryChannel(t *testing.T) {
	push, sms, mail := channels(t)
	d, path, _ := newTest(t)
	if len(d.sinks) != 3 {
		t.Fatalf("channels = %d, want 3", len(d.sinks))
	}
	d.High("Provider authentication failed", "claude-cli returned 401")
	log := closeAndRead(t, d, path)

	if push.count() != 1 || sms.count() != 1 {
		t.Errorf("pushover %d, sms %d requests; want 1 each", push.count(), sms.count())
	}
	if _, rcpts, data, _, _ := mail.got(); len(rcpts) != 1 || !strings.Contains(data, "Subject: HIGH Claw@empire: Provider authentication failed") {
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
	push, sms, _ := channels(t)
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
	push, sms, mail := channels(t)
	push.status, push.reply = http.StatusBadRequest, `{"token":"invalid"}`
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
	channels(t, func(push, sms *fakeAPI, mail *fakeSMTP) {
		push.status, sms.status, mail.rejectRcpt = 500, 500, "ops@"
	})
	d, path, _ := newTest(t)
	d.Low("x", "y")
	log := closeAndRead(t, d, path)
	for _, ch := range []string{"pushover", "sms", "smtp"} {
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
	push, sms, _ := channels(t)
	push.delay = 10 * time.Second
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
	channels(t, func(push, sms *fakeAPI, mail *fakeSMTP) {
		push.delay, sms.delay, mail.silent = 10*time.Second, 10*time.Second, true
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
		t.Errorf("%d failures logged, want 3:\n%s", n, log)
	}
}

func TestLogFailureWithChannelsCounted(t *testing.T) {
	push, _, _ := channels(t)
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
