/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

// Command alert sends two test alerts, one high priority and one low, through
// every channel the environment (and ~/.alerter) configures, then reports
// what happened. It exits non-zero when either alert was not delivered.
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
	send(al, time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	if err := al.Close(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := al.Stats()
	fmt.Printf("sent %d, failed %d, dropped %d, suppressed %d\n", s.Sent, s.Failed, s.Dropped, s.Suppressed)
	if s.Sent != 2 {
		os.Exit(1)
	}
}

// send raises the two test alerts. Their titles differ, so repeat suppression
// never holds one back.
func send(al alerter.Alerter, now time.Time) {
	stamp := "sent at " + now.Format(time.RFC3339)
	al.High("Test alert (high priority)", "alert sent this to test high-priority delivery; no action needed", stamp)
	al.Low("Test alert (low priority)", "alert sent this to test low-priority delivery; no action needed", stamp)
}
