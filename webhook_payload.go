/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"encoding/json"
	"time"
)

// webhookPayload renders an alert as the body of the webhook POST. It is the
// one place that decides the payload's shape; change it here.
func webhookPayload(a Alert) string {
	p := struct {
		Priority    string `json:"priority"` // "high" or "low"
		High        bool   `json:"high"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Details     string `json:"details,omitempty"`
		EventID     string `json:"event_id,omitempty"`
		App         string `json:"app,omitempty"`
		Instance    string `json:"instance,omitempty"`
		Time        string `json:"time"` // RFC 3339
		Repeats     int    `json:"repeats"`
		Subject     string `json:"subject"` // the one-line heading other channels use
	}{
		Priority:    "low",
		High:        a.High,
		Title:       a.Title,
		Description: a.Description,
		Details:     a.Details,
		EventID:     a.EventID,
		App:         a.App,
		Instance:    a.Instance,
		Time:        a.Time.Format(time.RFC3339),
		Repeats:     a.Repeats,
		Subject:     subject(a),
	}
	if a.High {
		p.Priority = "high"
	}
	b, _ := json.Marshal(p) // strings, a bool and an int: cannot fail
	return string(b)
}
