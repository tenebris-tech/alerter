/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"net/url"
	"strings"
	"testing"
)

func TestEveryLevelThroughEveryChannel(t *testing.T) {
	f := channels(t)
	d, path, _ := newTest(t)
	d.Normal("Level zero", "n")
	d.Urgent("Level one", "p")
	d.Emergency("Level two", "e")
	log := closeAndRead(t, d, path)

	if s := d.Stats(); s.Sent != 3 || s.Failed != 0 {
		t.Fatalf("stats = %+v", s)
	}
	for _, want := range []string{
		" NORMAL    Claw@empire Level zero: n\n",
		" URGENT    Claw@empire Level one: p\n",
		" EMERGENCY Claw@empire Level two: e\n",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	if f.push.count() != 3 || f.sms.count() != 3 || f.hook.count() != 3 {
		t.Fatalf("pushover %d, sms %d, webhook %d; want 3 each", f.push.count(), f.sms.count(), f.hook.count())
	}
	names := []string{"Normal", "Urgent", "Emergency"}
	pushPrio := []string{"0", "1", "2"}
	// Channels run in parallel per alert, but alerts are delivered in order.
	for i := range 3 {
		form, _ := url.ParseQuery(f.push.bodies[i])
		msg := form.Get("message")
		if form.Get("priority") != pushPrio[i] || !strings.Contains(msg, "\n"+names[i]+" alert\n") ||
			strings.Contains(msg, "Claw@empire") || form.Get("title") != "Level "+[]string{"zero", "one", "two"}[i]+" (Claw@empire)" {
			t.Errorf("pushover %d: priority %q title %q message %q", i, form.Get("priority"), form.Get("title"), msg)
		}
		if !strings.Contains(f.sms.bodies[i], names[i]+" alert from Claw@empire") {
			t.Errorf("sms %d: %s", i, f.sms.bodies[i])
		}
		if !strings.Contains(f.hook.bodies[i], `"priority":`+pushPrio[i]+`,"priority_name":"`+strings.ToLower(names[i])+`"`) {
			t.Errorf("webhook %d: %s", i, f.hook.bodies[i])
		}
	}
}

// TestEscalationIsNotSuppressed: the same condition at another level is not
// a repeat, so raising it to Emergency is never held back; repeats at one
// level still collapse.
func TestEscalationIsNotSuppressed(t *testing.T) {
	d, path, _ := newTest(t)
	d.Normal("Disk full", "first")
	d.Normal("Disk full", "repeat")
	d.Emergency("Disk full", "escalated")
	d.Emergency("Disk full", "repeat")
	d.Normal("Disk full", "back down, still a repeat of the first")
	log := closeAndRead(t, d, path)
	if !strings.Contains(log, " NORMAL    Claw@empire Disk full: first\n") ||
		!strings.Contains(log, " EMERGENCY Claw@empire Disk full: escalated\n") ||
		strings.Count(log, "Disk full") != 2 {
		t.Errorf("log:\n%s", log)
	}
	if s := d.Stats(); s.Sent != 2 || s.Suppressed != 3 {
		t.Errorf("stats = %+v, want sent 2 suppressed 3", s)
	}
}

func TestKeyIncludesLevelAndNormalises(t *testing.T) {
	base := Alert{Title: "t", EventID: "e"}
	keys := map[string]bool{}
	for _, p := range []int{Normal, Urgent, Emergency} {
		a := base
		a.Priority = p
		keys[a.key()] = true
	}
	if len(keys) != 3 {
		t.Error("levels share a key")
	}
	odd := base
	odd.Priority = 42
	if odd.key() != base.key() {
		t.Error("an out-of-range level must key as Normal")
	}
	if (Alert{Title: "t"}).key() == base.key() {
		t.Error("event id not in the key")
	}
}
