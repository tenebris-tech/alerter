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

var pushoverLevelVars = []string{EnvPushoverNormal, EnvPushoverPriority, EnvPushoverEmergency}

func TestPushoverPriorityDefaults(t *testing.T) {
	setEnv(t, goodPushover)
	sinks, err := sinksFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if p := sinks[0].(*pushoverSink); p.prio != [3]int{0, 1, 2} {
		t.Errorf("defaults = %v, want [0 1 2]", p.prio)
	}
}

func TestPushoverPriorityEachVariable(t *testing.T) {
	setEnv(t, goodPushover)
	for lvl, key := range pushoverLevelVars {
		for _, v := range []string{"-2", "-1", "0", "1", "2", " 2 "} {
			t.Run(key+"="+v, func(t *testing.T) {
				t.Setenv(key, v)
				sinks, err := sinksFromEnv()
				if err != nil {
					t.Fatal(err)
				}
				want := pushoverDefaults
				want[lvl], _ = strconv.Atoi(strings.TrimSpace(v))
				if got := sinks[0].(*pushoverSink).prio; got != want {
					t.Errorf("prio = %v, want %v (only level %d changed)", got, want, lvl)
				}
			})
		}
	}
}

func TestPushoverPriorityAllZero(t *testing.T) {
	setEnv(t, goodPushover)
	for _, k := range pushoverLevelVars {
		t.Setenv(k, "0")
	}
	sinks, err := sinksFromEnv()
	if err != nil || sinks[0].(*pushoverSink).prio != [3]int{} {
		t.Errorf("prio = %v, err %v; want all 0", sinks, err)
	}
}

func TestPushoverPriorityInvalid(t *testing.T) {
	setEnv(t, goodPushover)
	for _, key := range pushoverLevelVars {
		for _, v := range []string{"3", "-3", "high", "1.5", "0x1", "+", "1 2"} {
			t.Run(key+"="+v, func(t *testing.T) {
				t.Setenv(key, v)
				if _, err := sinksFromEnv(); err == nil || !strings.Contains(err.Error(), key) {
					t.Errorf("error = %v, want it to name %s", err, key)
				}
			})
		}
	}
}

func TestPushoverPriorityWithoutToken(t *testing.T) {
	for _, key := range pushoverLevelVars {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "0")
			if _, err := sinksFromEnv(); err == nil || !strings.Contains(err.Error(), EnvPushoverToken) {
				t.Errorf("a priority alone must require the token: %v", err)
			}
		})
	}
}

func TestPushoverSendsPriorityForLevel(t *testing.T) {
	cases := []struct {
		name          string
		prio          [3]int
		level         int
		wantPrio      string
		wantEmergency bool
	}{
		{"defaults normal", pushoverDefaults, Normal, "0", false},
		{"defaults priority", pushoverDefaults, Priority, "1", false},
		{"defaults emergency", pushoverDefaults, Emergency, "2", true},
		{"all quiet emergency", [3]int{0, 0, 0}, Emergency, "0", false},
		{"all quiet priority", [3]int{0, 0, 0}, Priority, "0", false},
		{"lowest normal", [3]int{-2, 0, 1}, Normal, "-2", false},
		{"quiet normal", [3]int{-1, 0, 1}, Normal, "-1", false},
		{"emergency on priority", [3]int{0, 2, 2}, Priority, "2", true},
		{"emergency on normal", [3]int{2, 0, 0}, Normal, "2", true},
		{"out of range level is normal", [3]int{-1, 1, 2}, 9, "-1", false},
		{"negative level is normal", [3]int{-1, 1, 2}, -5, "-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeAPI{}
			serve(t, f, &pushoverURL)
			p := &pushoverSink{token: "t", dests: []string{"u"}, prio: tc.prio, http: &http.Client{}}
			a := sample
			a.Priority = tc.level
			if err := p.send(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			form, _ := url.ParseQuery(f.bodies[0])
			if form.Get("priority") != tc.wantPrio {
				t.Errorf("priority %q, want %s", form.Get("priority"), tc.wantPrio)
			}
			if tc.wantEmergency && (form.Get("retry") != "60" || form.Get("expire") != "3600") {
				t.Errorf("emergency without retry/expire: %v", form)
			}
			if !tc.wantEmergency && (form.Has("retry") || form.Has("expire")) {
				t.Errorf("retry/expire sent below emergency: %v", form)
			}
		})
	}
}

// TestPushoverLevelsEndToEnd sends one alert per level through New, with the
// levels configured in the environment, and checks the priority each carried.
func TestPushoverLevelsEndToEnd(t *testing.T) {
	f := &fakeAPI{}
	serve(t, f, &pushoverURL)
	setEnv(t, goodPushover)
	setEnv(t, map[string]string{EnvPushoverNormal: "-1", EnvPushoverPriority: "0", EnvPushoverEmergency: "1"})
	d, path, _ := newTest(t)
	d.Normal("n", "")
	d.Priority("p", "")
	d.Emergency("e", "")
	d.Send(Alert{Priority: 42, Title: "bogus"})
	closeAndRead(t, d, path)
	// Two destinations per alert (goodPushover has u1 and u2).
	want := map[string]string{"n": "-1", "p": "0", "e": "1", "bogus": "-1"}
	got := map[string]string{}
	for _, b := range f.bodies {
		form, _ := url.ParseQuery(b)
		title := strings.TrimSuffix(form.Get("title"), " (Claw@empire)")
		if prev, seen := got[title]; seen && prev != form.Get("priority") {
			t.Errorf("%s sent at %s and %s", title, prev, form.Get("priority"))
		}
		got[title] = form.Get("priority")
	}
	for title, p := range want {
		if got[title] != p {
			t.Errorf("%s: priority %q, want %s (all: %v)", title, got[title], p, got)
		}
	}
	if len(f.bodies) != 8 {
		t.Errorf("requests = %d, want 8", len(f.bodies))
	}
}

// TestPushoverDefaultEmergencyEndToEnd: with no priority variables set, an
// Emergency alert through New is a Pushover emergency with retry and expire.
func TestPushoverDefaultEmergencyEndToEnd(t *testing.T) {
	f := &fakeAPI{}
	serve(t, f, &pushoverURL)
	setEnv(t, map[string]string{EnvPushoverToken: "tok", EnvPushoverDest: "u"})
	d, path, _ := newTest(t)
	d.Emergency("e", "")
	d.Normal("n", "")
	closeAndRead(t, d, path)
	if len(f.bodies) != 2 {
		t.Fatalf("requests = %d", len(f.bodies))
	}
	e, _ := url.ParseQuery(f.bodies[0])
	n, _ := url.ParseQuery(f.bodies[1])
	if e.Get("priority") != "2" || e.Get("retry") != "60" || e.Get("expire") != "3600" {
		t.Errorf("emergency form = %v", e)
	}
	if n.Get("priority") != "0" || n.Has("retry") {
		t.Errorf("normal form = %v", n)
	}
}
