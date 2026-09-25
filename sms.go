/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// telnyxURL is the Telnyx v2 send-message endpoint; tests point it at a fake.
var telnyxURL = "https://api.telnyx.com/v2/messages"

// smsMax bounds a text (subject and description) to a few segments.
const smsMax = 300

// smsSink sends one Telnyx text per recipient.
type smsSink struct {
	apiKey string
	from   string
	to     []string
	http   *http.Client
}

func smsFromEnv() (sink, error) {
	if !anySet(EnvTelnyxAPIKey, EnvSMSFrom, EnvSMSTo) {
		return nil, nil
	}
	if err := require("sms", EnvTelnyxAPIKey, EnvSMSFrom, EnvSMSTo); err != nil {
		return nil, err
	}
	s := &smsSink{apiKey: env(EnvTelnyxAPIKey), from: env(EnvSMSFrom), to: list(EnvSMSTo), http: newHTTPClient()}
	if len(s.to) == 0 {
		return nil, fmt.Errorf("alerter: sms: %s has no number", EnvSMSTo)
	}
	for _, n := range append([]string{s.from}, s.to...) {
		if !validE164(n) {
			return nil, fmt.Errorf("alerter: sms: %q is not an E.164 number (e.g. +15551234567)", n)
		}
	}
	return s, nil
}

func (s *smsSink) name() string { return "sms" }

// smsText leads with the title and description, then the priority line:
// "Provider authentication failed: claude-cli returned 401\nUrgent alert
// from ClawEh@empire".
func smsText(a Alert) string {
	t := strings.Join(strings.Fields(a.Title), " ")
	if a.Description != "" {
		t += ": " + a.Description
	}
	t += "\n" + priorityLine(a)
	if a.Repeats > 0 {
		t += fmt.Sprintf(" (%d repeat(s) suppressed)", a.Repeats)
	}
	return truncate(t, smsMax)
}

func (s *smsSink) send(ctx context.Context, a Alert) error {
	text := smsText(a)
	var errs []error
	for _, to := range s.to {
		if err := s.sendOne(ctx, to, text); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *smsSink) sendOne(ctx context.Context, to, text string) error {
	payload, err := json.Marshal(map[string]string{"from": s.from, "to": to, "text": text})
	if err != nil {
		return fmt.Errorf("sms to %s: %w", to, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telnyxURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("sms to %s: %w", to, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("sms to %s: %w", to, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("sms to %s: telnyx status %d: %s", to, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// validE164 accepts "+" followed by 7 to 15 digits.
func validE164(s string) bool {
	if len(s) < 8 || len(s) > 16 || s[0] != '+' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
