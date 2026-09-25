/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var allChannelVars = []string{
	EnvPushoverToken, EnvPushoverDest,
	EnvTelnyxAPIKey, EnvSMSFrom, EnvSMSTo,
	EnvSMTPHost, EnvSMTPPort, EnvSMTPUser, EnvSMTPPassword, EnvSMTPFrom, EnvSMTPTo,
	EnvWebhookURL, EnvWebhookHeaders,
}

var goodPushover = map[string]string{EnvPushoverToken: "tok", EnvPushoverDest: "u1, u2"}
var goodSMS = map[string]string{EnvTelnyxAPIKey: "key", EnvSMSFrom: "+15550001111", EnvSMSTo: "+15550002222,+15550003333"}
var goodSMTP = map[string]string{
	EnvSMTPHost: "mail.example.com", EnvSMTPPort: "2587", EnvSMTPUser: "user", EnvSMTPPassword: "pw",
	EnvSMTPFrom: "Alerts <alerts@example.com>", EnvSMTPTo: "a@example.com, B <b@example.com>",
}

func TestNoChannelsByDefault(t *testing.T) {
	sinks, err := sinksFromEnv()
	if err != nil || len(sinks) != 0 {
		t.Errorf("sinks = %v, err = %v; want none", sinks, err)
	}
}

func TestChannelsFromEnv(t *testing.T) {
	setEnv(t, goodPushover)
	setEnv(t, goodSMS)
	setEnv(t, goodSMTP)
	sinks, err := sinksFromEnv()
	if err != nil {
		t.Fatalf("sinksFromEnv: %v", err)
	}
	var names []string
	for _, s := range sinks {
		names = append(names, s.name())
	}
	if got := strings.Join(names, ","); got != "pushover,sms,smtp" {
		t.Fatalf("channels = %s", got)
	}

	p := sinks[0].(*pushoverSink)
	if p.token != "tok" || strings.Join(p.dests, "|") != "u1|u2" {
		t.Errorf("pushover = %+v", p)
	}
	s := sinks[1].(*smsSink)
	if s.apiKey != "key" || s.from != "+15550001111" || strings.Join(s.to, "|") != "+15550002222|+15550003333" {
		t.Errorf("sms = %+v", s)
	}
	m := sinks[2].(*smtpSink)
	if m.host != "mail.example.com" || m.port != 2587 || m.tls || m.user != "user" || m.pass != "pw" ||
		m.from.Address != "alerts@example.com" || len(m.to) != 2 || m.to[1].Address != "b@example.com" {
		t.Errorf("smtp = %+v", m)
	}
}

func TestEachChannelAlone(t *testing.T) {
	for name, vars := range map[string]map[string]string{"pushover": goodPushover, "sms": goodSMS, "smtp": goodSMTP} {
		t.Run(name, func(t *testing.T) {
			setEnv(t, vars)
			sinks, err := sinksFromEnv()
			if err != nil || len(sinks) != 1 || sinks[0].name() != name {
				t.Errorf("sinks = %v, err = %v; want only %s", sinks, err, name)
			}
		})
	}
}

func TestSMTPAddressLists(t *testing.T) {
	setEnv(t, goodSMTP)
	for to, want := range map[string]string{
		`"Ops, Team" <ops@example.com>, pager@example.com`: "ops@example.com|pager@example.com",
		"a@example.com,":        "a@example.com",
		", a@example.com , ":    "a@example.com",
		"a@example.com,b@x.org": "a@example.com|b@x.org",
	} {
		t.Setenv(EnvSMTPTo, to)
		sinks, err := sinksFromEnv()
		if err != nil {
			t.Errorf("%q: %v", to, err)
			continue
		}
		var got []string
		for _, a := range sinks[0].(*smtpSink).to {
			got = append(got, a.Address)
		}
		if strings.Join(got, "|") != want {
			t.Errorf("%q parsed as %v", to, got)
		}
	}
}

func TestHTTPClientRefusesRedirects(t *testing.T) {
	c := newHTTPClient()
	if err := c.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v", err)
	}
}

func TestSMTPDefaults(t *testing.T) {
	setEnv(t, map[string]string{EnvSMTPHost: "localhost", EnvSMTPFrom: "a@example.com", EnvSMTPTo: "b@example.com"})
	sinks, err := sinksFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	m := sinks[0].(*smtpSink)
	if m.port != defaultSMTPPort || m.tls || m.user != "" {
		t.Errorf("defaults = %+v", m)
	}
	t.Setenv(EnvSMTPPort, "465")
	sinks, err = sinksFromEnv()
	if err != nil || !sinks[0].(*smtpSink).tls {
		t.Errorf("port 465 must be implicit TLS (err %v)", err)
	}
}

func TestChannelConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		base map[string]string
		set  map[string]string // overrides; "" clears
		want string            // substring of the error
	}{
		{"pushover token only", nil, map[string]string{EnvPushoverToken: "t"}, EnvPushoverDest},
		{"pushover dest only", nil, map[string]string{EnvPushoverDest: "u"}, EnvPushoverToken},
		{"sms key only", nil, map[string]string{EnvTelnyxAPIKey: "k"}, EnvSMSFrom + ", " + EnvSMSTo},
		{"sms bad from", goodSMS, map[string]string{EnvSMSFrom: "5550001111"}, "E.164"},
		{"sms bad to", goodSMS, map[string]string{EnvSMSTo: "+15550002222,+1555abc"}, "+1555abc"},
		{"sms short", goodSMS, map[string]string{EnvSMSTo: "+123"}, "E.164"},
		{"smtp port only", nil, map[string]string{EnvSMTPPort: "25"}, EnvSMTPHost},
		{"smtp no to", goodSMTP, map[string]string{EnvSMTPTo: ""}, EnvSMTPTo},
		{"smtp empty to list", goodSMTP, map[string]string{EnvSMTPTo: " , "}, "no address"},
		{"smtp bad port", goodSMTP, map[string]string{EnvSMTPPort: "smtp"}, EnvSMTPPort},
		{"smtp port range", goodSMTP, map[string]string{EnvSMTPPort: "70000"}, EnvSMTPPort},
		{"smtp user without password", goodSMTP, map[string]string{EnvSMTPPassword: ""}, "both"},
		{"smtp password without user", goodSMTP, map[string]string{EnvSMTPUser: ""}, "both"},
		{"smtp bad from", goodSMTP, map[string]string{EnvSMTPFrom: "not an address"}, EnvSMTPFrom},
		{"smtp bad to", goodSMTP, map[string]string{EnvSMTPTo: "a@example.com, nope"}, EnvSMTPTo},
		{"pushover empty dest list", goodPushover, map[string]string{EnvPushoverDest: " , "}, "no key"},
		{"sms empty to list", goodSMS, map[string]string{EnvSMSTo: ","}, "no number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.base)
			setEnv(t, tc.set)
			_, err := sinksFromEnv()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestAllChannelErrorsReported(t *testing.T) {
	setEnv(t, map[string]string{EnvPushoverToken: "t", EnvSMSTo: "+15550002222", EnvSMTPHost: "h"})
	_, err := sinksFromEnv()
	for _, want := range []string{"pushover", "sms", "smtp"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %s", err, want)
		}
	}
}

var sample = Alert{
	Priority: Priority, Title: "Provider authentication failed", Description: "claude-cli returned 401",
	Details: "run `claude login`\non the host\n", EventID: "claude-cli",
	Time: time.Date(2026, 9, 24, 10, 0, 0, 0, time.FixedZone("EDT", -4*3600)),
	App:  "ClawEh", Instance: "empire", Repeats: 3,
}

func TestSubject(t *testing.T) {
	if got := subject(sample); got != "Provider authentication failed (ClawEh@empire)" {
		t.Errorf("subject = %q", got)
	}
	cases := map[string]Alert{
		"x (ClawEh)":      {Title: "x", App: "ClawEh"},
		"x (@empire)":     {Title: "x", Instance: "empire"},
		"x":               {Title: "x"},
		"line1 line2 (a)": {Priority: Priority, App: "a", Title: "line1\r\nline2 "},
	}
	for want, a := range cases {
		if got := subject(a); got != strings.TrimSpace(want) {
			t.Errorf("subject(%+v) = %q, want %q", a, got, strings.TrimSpace(want))
		}
	}
}

func TestBody(t *testing.T) {
	want := "claude-cli returned 401\n\n" +
		"Priority alert\nEvent: claude-cli\n" +
		"Time: 2026-09-24T10:00:00-04:00\nRepeats: 3 suppressed since the last one\n\n" +
		"run `claude login`\non the host\n"
	if got := body(sample); got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}
	minimal := body(Alert{Title: "x", Time: sample.Time})
	if minimal != "Normal alert\nTime: 2026-09-24T10:00:00-04:00\n" {
		t.Errorf("minimal body = %q", minimal)
	}
}

func TestSMSText(t *testing.T) {
	want := "Provider authentication failed: claude-cli returned 401\nPriority alert from ClawEh@empire (3 repeat(s) suppressed)"
	if got := smsText(sample); got != want {
		t.Errorf("smsText = %q", got)
	}
	long := smsText(Alert{Title: "x", Description: strings.Repeat("é", 1000)})
	if n := utf8.RuneCountInString(long); n != smsMax || !strings.HasSuffix(long, "…") {
		t.Errorf("long text: %d runes", n)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Errorf("truncate = %q", got)
	}
}

func TestValidE164(t *testing.T) {
	for s, want := range map[string]bool{
		"+15551234567": true, "+4420123456": true, "+1234567": true,
		"15551234567": false, "+1555-123-4567": false, "+123456": false, "+1234567890123456": false, "": false,
	} {
		if got := validE164(s); got != want {
			t.Errorf("validE164(%q) = %v", s, got)
		}
	}
}

func TestPriorityLineLevels(t *testing.T) {
	for _, tc := range []struct {
		a    Alert
		want string
	}{
		{Alert{Priority: Normal, App: "A", Instance: "i"}, "Normal alert from A@i"},
		{Alert{Priority: Priority, App: "A"}, "Priority alert from A"},
		{Alert{Priority: Emergency}, "Emergency alert"},
		{Alert{Priority: 5, Instance: "i"}, "Normal alert from @i"},
	} {
		if got := priorityLine(tc.a); got != tc.want {
			t.Errorf("priorityLine(%d) = %q, want %q", tc.a.Priority, got, tc.want)
		}
	}
}

// highLow matches the words high and low, not "slow" or "below".
var highLow = regexp.MustCompile(`(?i)\b(high|low)\b`)

// pushoverForm is the title and message Pushover would receive for a.
func pushoverForm(t *testing.T, a Alert) string {
	t.Helper()
	f := &fakeAPI{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	old := pushoverURL
	pushoverURL = srv.URL
	defer func() { pushoverURL = old }()
	p := &pushoverSink{token: "t", dests: []string{"u"}, prio: pushoverDefaults, http: newHTTPClient()}
	if err := p.send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	form, _ := url.ParseQuery(f.bodies[0])
	return form.Get("title") + "\n" + form.Get("message")
}

func TestHighLowPattern(t *testing.T) {
	for s, want := range map[string]bool{"HIGH": true, "a low one": true, "slow": false, "below": false, "highway": false} {
		if highLow.MatchString(s) != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
}

func TestTextNeverSaysHighOrLow(t *testing.T) {
	for _, p := range []int{Normal, Priority, Emergency} {
		a := Alert{Priority: p, Title: "Disk full", Description: "backup stopped", App: "A", Time: sample.Time}
		mail := string(newSMTPSink("h", 25, "", "").message(a))
		_, mailBody, _ := strings.Cut(mail, "\r\n\r\n")
		for name, text := range map[string]string{
			"subject": subject(a), "body": body(a), "sms": smsText(a), "webhook": webhookPayload(a),
			"mail body": mailBody, "pushover": pushoverForm(t, a),
		} {
			if highLow.MatchString(text) {
				t.Errorf("level %d %s says high or low: %q", p, name, text)
			}
			if (name == "subject" || name == "sms") && !strings.HasPrefix(text, "Disk full") {
				t.Errorf("level %d %s does not lead with the title: %q", p, name, text)
			}
		}
		if !strings.HasPrefix(body(a), "backup stopped\n") {
			t.Errorf("body does not lead with the description: %q", body(a))
		}
		if !strings.Contains(smsText(a), "\n"+priorityName(p)+" alert from A") {
			t.Errorf("sms lacks the level: %q", smsText(a))
		}
	}
}

// TestSourceStatedOnce: the subject carries the source, so the body sent
// under it (mail, Pushover) does not repeat it; SMS, with no subject, states
// it on its level line.
func TestSourceStatedOnce(t *testing.T) {
	for _, p := range []int{Normal, Priority, Emergency} {
		a := Alert{Priority: p, Title: "Disk full", Description: "backup stopped", App: "ClawEh", Instance: "empire", Time: sample.Time}
		if n := strings.Count(subject(a)+"\n"+body(a), "ClawEh@empire"); n != 1 {
			t.Errorf("level %d: source appears %d times in subject and body:\n%s\n%s", p, n, subject(a), body(a))
		}
		if n := strings.Count(pushoverForm(t, a), "ClawEh@empire"); n != 1 {
			t.Errorf("level %d: source appears %d times in the Pushover title and message", p, n)
		}
		if n := strings.Count(smsText(a), "ClawEh@empire"); n != 1 {
			t.Errorf("level %d: source appears %d times in the SMS: %q", p, n, smsText(a))
		}
		if !strings.Contains(body(a), "\n"+priorityName(p)+" alert\n") {
			t.Errorf("level %d: body lacks its level line: %q", p, body(a))
		}
	}
}
