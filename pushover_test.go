/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestPushoverPriorityConfig(t *testing.T) {
	setEnv(t, goodPushover)
	sinks, err := sinksFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if p := sinks[0].(*pushoverSink); p.high != 1 || p.low != 0 {
		t.Errorf("defaults high %d low %d, want 1 and 0", p.high, p.low)
	}
	for _, v := range []string{"-2", "-1", "0", "1", "2", " 2 "} {
		t.Setenv(EnvPushoverHigh, v)
		t.Setenv(EnvPushoverLow, v)
		sinks, err := sinksFromEnv()
		if err != nil {
			t.Errorf("%q: %v", v, err)
			continue
		}
		want, _ := strconv.Atoi(strings.TrimSpace(v))
		if p := sinks[0].(*pushoverSink); p.high != want || p.low != want {
			t.Errorf("%q: high %d low %d", v, p.high, p.low)
		}
	}
	for _, key := range []string{EnvPushoverHigh, EnvPushoverLow} {
		for _, v := range []string{"3", "-3", "high", "1.5", "0x1"} {
			t.Setenv(EnvPushoverHigh, "")
			t.Setenv(EnvPushoverLow, "")
			t.Setenv(key, v)
			if _, err := sinksFromEnv(); err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("%s=%q: error = %v", key, v, err)
			}
		}
	}
}

func TestPushoverPriorityWithoutToken(t *testing.T) {
	t.Setenv(EnvPushoverHigh, "0")
	if _, err := sinksFromEnv(); err == nil || !strings.Contains(err.Error(), EnvPushoverToken) {
		t.Errorf("a priority alone must require the token: %v", err)
	}
}

func TestPushoverSendsConfiguredPriority(t *testing.T) {
	f := &fakeAPI{}
	serve(t, f, &pushoverURL)
	cases := []struct {
		high, low     int
		alertHigh     bool
		wantPrio      string
		wantEmergency bool
	}{
		{1, 0, true, "1", false},
		{1, 0, false, "0", false},
		{0, -1, true, "0", false}, // priority alerts kept quiet
		{0, -2, false, "-2", false},
		{2, 0, true, "2", true},
		{1, 2, false, "2", true},
	}
	for i, tc := range cases {
		p := &pushoverSink{token: "t", dests: []string{"u"}, high: tc.high, low: tc.low, http: &http.Client{}}
		a := sample
		a.High = tc.alertHigh
		if err := p.send(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		form, _ := url.ParseQuery(f.bodies[i])
		if form.Get("priority") != tc.wantPrio {
			t.Errorf("case %d: priority %q, want %s", i, form.Get("priority"), tc.wantPrio)
		}
		if tc.wantEmergency && (form.Get("retry") != "60" || form.Get("expire") != "3600") {
			t.Errorf("case %d: emergency without retry/expire: %v", i, form)
		}
		if !tc.wantEmergency && (form.Has("retry") || form.Has("expire")) {
			t.Errorf("case %d: retry/expire sent below emergency: %v", i, form)
		}
	}
}
