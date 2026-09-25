/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/tenebris-tech/alerter"
)

// recorder captures what send raises.
type recorder struct{ alerts []alerter.Alert }

func (r *recorder) Send(a alerter.Alert) { r.alerts = append(r.alerts, a) }
func (r *recorder) Normal(t, d string, x ...string) {
	r.Send(alerter.Alert{Priority: alerter.Normal, Title: t, Description: d, Details: strings.Join(x, "\n")})
}
func (r *recorder) Priority(t, d string, x ...string) {
	r.Send(alerter.Alert{Priority: alerter.Priority, Title: t, Description: d, Details: strings.Join(x, "\n")})
}
func (r *recorder) Emergency(t, d string, x ...string) {
	r.Send(alerter.Alert{Priority: alerter.Emergency, Title: t, Description: d, Details: strings.Join(x, "\n")})
}
func (r *recorder) Close(context.Context) error { return nil }

func TestSendRaisesOnePerLevel(t *testing.T) {
	r := &recorder{}
	send(r)
	if len(r.alerts) != testAlerts || testAlerts != 3 {
		t.Fatalf("alerts = %d (testAlerts %d), want 3", len(r.alerts), testAlerts)
	}
	titles := map[string]bool{}
	for i, want := range []int{alerter.Normal, alerter.Priority, alerter.Emergency} {
		a := r.alerts[i]
		if a.Priority != want {
			t.Errorf("alert %d priority = %d, want %d", i, a.Priority, want)
		}
		if a.Details != "" {
			t.Errorf("details = %q; every service shows when a message arrived", a.Details)
		}
		titles[a.Title] = true
	}
	if len(titles) != 3 {
		t.Error("titles must differ or repeat suppression holds one back")
	}
}
