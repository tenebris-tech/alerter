/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

// Command alert sends three test alerts, one at each level (Normal,
// Priority, Emergency), through every channel the environment (and
// ~/.alerter) configures, then reports what happened. It exits non-zero
// unless all three were delivered. With Pushover at its default priorities
// the Emergency test alert is a Pushover emergency: it bypasses quiet hours
// and repeats every minute until acknowledged, for up to an hour. Set
// ALERTER_PUSHOVER_EMERGENCY=0 to test quietly.
//
// When ALERTER_WEBHOOK_URL points at a loopback address, alert listens there
// itself, prints each webhook request it receives, and also fails unless
// all three alerts arrived.
//
//	go run ./cmd/alert
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tenebris-tech/alerter"
)

// closeTimeout allows for every channel's delivery timeout.
const closeTimeout = 2 * time.Minute

func main() {
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".")
	al, err := alerter.New(alerter.WithAppName("alert"), alerter.WithInstanceName(host))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hook, err := listenWebhook(os.Getenv(alerter.EnvWebhookURL))
	if err != nil {
		_ = al.Close(context.Background())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	send(al, time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	if err := al.Close(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := al.Stats()
	fmt.Printf("sent %d, failed %d, dropped %d, suppressed %d\n", s.Sent, s.Failed, s.Dropped, s.Suppressed)
	ok := s.Sent == testAlerts
	if hook != nil {
		hook.close()
		got := hook.requests()
		fmt.Printf("webhook listener on %s received %d request(s):\n", hook.addr, len(got))
		for _, r := range got {
			fmt.Print(r.report())
		}
		ok = ok && len(got) == testAlerts
	}
	if !ok {
		os.Exit(1)
	}
}

// testAlerts is how many alerts send raises.
const testAlerts = 3

// send raises one test alert at each level. Their titles differ, so repeat
// suppression never holds one back.
func send(al alerter.Alerter, now time.Time) {
	stamp := "sent at " + now.Format(time.RFC3339)
	al.Normal("Normal test alert", "alert sent this to test Normal delivery; no action needed", stamp)
	al.Priority("Priority test alert", "alert sent this to test Priority delivery; no action needed", stamp)
	al.Emergency("Emergency test alert", "alert sent this to test Emergency delivery; no action needed", stamp)
}
