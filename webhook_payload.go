/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"encoding/json"
	"strings"
	"time"
)

// webhookPayload renders an alert as the body of the webhook POST. It is the
// one place that decides the payload's shape; change it here.
func webhookPayload(a Alert) string {
	p := struct {
		Priority     int    `json:"priority"`      // 0 normal, 1 priority, 2 emergency
		PriorityName string `json:"priority_name"` // "normal", "priority" or "emergency"
		Title        string `json:"title"`
		Description  string `json:"description"`
		Details      string `json:"details,omitempty"`
		EventID      string `json:"event_id,omitempty"`
		App          string `json:"app,omitempty"`
		Instance     string `json:"instance,omitempty"`
		Time         string `json:"time"` // RFC 3339
		Repeats      int    `json:"repeats"`
		Subject      string `json:"subject"` // the one-line heading other channels use
	}{
		Priority:     level(a.Priority),
		PriorityName: strings.ToLower(priorityName(a.Priority)),
		Title:        a.Title,
		Description:  a.Description,
		Details:      a.Details,
		EventID:      a.EventID,
		App:          a.App,
		Instance:     a.Instance,
		Time:         a.Time.Format(time.RFC3339),
		Repeats:      a.Repeats,
		Subject:      subject(a),
	}
	b, _ := json.Marshal(p) // strings and ints: cannot fail
	return string(b)
}
