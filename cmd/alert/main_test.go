/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package main

import (
	"context"
	"testing"
	"time"

	"github.com/tenebris-tech/alerter"
)

// recorder captures what send raises.
type recorder struct{ alerts []alerter.Alert }

func (r *recorder) Send(a alerter.Alert) { r.alerts = append(r.alerts, a) }
func (r *recorder) High(t, d string, x ...string) {
	r.Send(alerter.Alert{High: true, Title: t, Description: d, Details: x[0]})
}
func (r *recorder) Low(t, d string, x ...string) {
	r.Send(alerter.Alert{Title: t, Description: d, Details: x[0]})
}
func (r *recorder) Close(context.Context) error { return nil }

func TestSendRaisesOneHighOneLow(t *testing.T) {
	r := &recorder{}
	send(r, time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC))
	if len(r.alerts) != 2 {
		t.Fatalf("alerts = %d, want 2", len(r.alerts))
	}
	hi, lo := r.alerts[0], r.alerts[1]
	if !hi.High || lo.High {
		t.Errorf("priorities = %v, %v; want high then low", hi.High, lo.High)
	}
	if hi.Title == lo.Title {
		t.Error("titles must differ or repeat suppression holds the second back")
	}
	for _, a := range r.alerts {
		if a.Details != "sent at 2026-09-24T10:00:00Z" {
			t.Errorf("details = %q", a.Details)
		}
	}
}
