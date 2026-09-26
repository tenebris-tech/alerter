/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"strings"
	"testing"
)

// sendAllLevels raises one alert at each level and returns the log.
func sendAllLevels(t *testing.T, d *Dispatcher, path string) string {
	t.Helper()
	d.Normal("Level zero", "n")
	d.Urgent("Level one", "p")
	d.Emergency("Level two", "e")
	return closeAndRead(t, d, path)
}

func TestMinPriUnsetSendsEverything(t *testing.T) {
	f := channels(t)
	d, path, _ := newTest(t)
	for _, c := range d.sinks {
		if c.min != Normal {
			t.Errorf("%s min = %d, want %d", c.name(), c.min, Normal)
		}
	}
	log := sendAllLevels(t, d, path)
	if f.push.count() != 3 || f.sms.count() != 3 || f.hook.count() != 3 || f.mail.count() != 3 {
		t.Errorf("pushover %d, sms %d, webhook %d, mail %d; want 3 each",
			f.push.count(), f.sms.count(), f.hook.count(), f.mail.count())
	}
	if strings.Contains(log, "WARNING") {
		t.Errorf("unexpected warning:\n%s", log)
	}
}

// TestMinPriPerChannel: each channel's threshold applies to that channel
// only; an alert at the threshold passes, one below is skipped.
func TestMinPriPerChannel(t *testing.T) {
	f := channels(t)
	setEnv(t, map[string]string{
		EnvSMSMinPri: "2", EnvPushoverMinPri: "1", EnvSMTPMinPri: "0",
	})
	d, path, _ := newTest(t)
	log := sendAllLevels(t, d, path)

	if f.sms.count() != 1 || !strings.Contains(f.sms.bodies[0], "Emergency alert") {
		t.Errorf("sms: %d texts %v; want only the Emergency", f.sms.count(), f.sms.bodies)
	}
	if f.push.count() != 2 || !strings.Contains(f.push.bodies[0], "Level+one") || !strings.Contains(f.push.bodies[1], "Level+two") {
		t.Errorf("pushover: %d messages %v; want Urgent and Emergency", f.push.count(), f.push.bodies)
	}
	if f.mail.count() != 3 {
		t.Errorf("mail: %d messages, want 3 (minimum 0)", f.mail.count())
	}
	if f.hook.count() != 3 {
		t.Errorf("webhook: %d requests, want 3 (unset)", f.hook.count())
	}
	if strings.Contains(log, "WARNING") || strings.Contains(log, "ERROR") {
		t.Errorf("log:\n%s", log)
	}
	if s := d.Stats(); s.Sent != 3 || s.Failed != 0 {
		t.Errorf("stats = %+v; a skipped channel is not a failure", s)
	}
}

func TestMinPriSkippedChannelNotCalled(t *testing.T) {
	// A channel that would fail is never reached for an alert below its
	// minimum, so nothing is logged and the alert counts as sent.
	f := channels(t, func(f *fakes) { f.sms.status = 500 })
	setEnv(t, map[string]string{EnvSMSMinPri: "1"})
	d, path, _ := newTest(t)
	d.Normal("x", "y")
	log := closeAndRead(t, d, path)
	if f.sms.count() != 0 || strings.Contains(log, "sms delivery failed") {
		t.Errorf("sms %d; log:\n%s", f.sms.count(), log)
	}
	if s := d.Stats(); s.Sent != 1 || s.Failed != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestMinPriOutOfRangeWarnsAndSendsAll(t *testing.T) {
	for _, v := range []string{"3", "-1", "two", "1.5"} {
		t.Run(v, func(t *testing.T) {
			f := channels(t)
			setEnv(t, map[string]string{EnvSMSMinPri: v, EnvWebhookMinPri: "2"})
			d, path, _ := newTest(t)
			log := sendAllLevels(t, d, path)
			want := "2026-09-24T10:00:00-04:00 WARNING alerter: " + EnvSMSMinPri + " " + `"` + v + `"` +
				" is not a priority from 0 to 2; sending every alert\n"
			if !strings.HasPrefix(log, want) {
				t.Errorf("log =\n%s\nwant it to start with\n%s", log, want)
			}
			if strings.Count(log, "WARNING") != 1 {
				t.Errorf("want exactly one warning:\n%s", log)
			}
			if f.sms.count() != 3 {
				t.Errorf("sms %d, want 3: a bad minimum means every alert", f.sms.count())
			}
			if f.hook.count() != 1 {
				t.Errorf("webhook %d, want 1: the valid minimum still applies", f.hook.count())
			}
		})
	}
}

func TestMinPriority(t *testing.T) {
	cases := []struct {
		value string
		want  int
		warn  bool
	}{
		{"", Normal, false}, {"0", Normal, false}, {"1", Urgent, false}, {"2", Emergency, false},
		{" 1 ", Urgent, false}, {"3", Normal, true}, {"-1", Normal, true}, {"x", Normal, true},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(EnvSMTPMinPri, tc.value)
			got, warn := minPriority(EnvSMTPMinPri)
			if got != tc.want || (warn != "") != tc.warn {
				t.Errorf("minPriority(%q) = %d, %q; want %d, warning %v", tc.value, got, warn, tc.want, tc.warn)
			}
		})
	}
}

func TestMinPriVarsCoverEveryChannel(t *testing.T) {
	channels(t)
	d, _, _ := newTest(t)
	for _, c := range d.sinks {
		key, ok := minPriVars[c.name()]
		if !ok || key != "ALERTER_"+strings.ToUpper(c.name())+"_MIN_PRI" {
			t.Errorf("%s: minimum-level variable %q", c.name(), key)
		}
	}
}
