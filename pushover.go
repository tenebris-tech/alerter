/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// pushoverURL is the Pushover Message API endpoint; tests point it at a fake.
var pushoverURL = "https://api.pushover.net/1/messages.json"

// Pushover limits, in characters.
const (
	pushoverTitleMax   = 250
	pushoverMessageMax = 1024
)

// pushoverSink sends one Pushover message per destination key. High alerts
// go at priority 1 (bypasses quiet hours), low at 0.
type pushoverSink struct {
	token string
	dests []string
	http  *http.Client
}

func pushoverFromEnv() (sink, error) {
	if !anySet(EnvPushoverToken, EnvPushoverDest) {
		return nil, nil
	}
	if err := require("pushover", EnvPushoverToken, EnvPushoverDest); err != nil {
		return nil, err
	}
	p := &pushoverSink{token: env(EnvPushoverToken), dests: list(EnvPushoverDest), http: newHTTPClient()}
	if len(p.dests) == 0 {
		return nil, fmt.Errorf("alerter: pushover: %s has no key", EnvPushoverDest)
	}
	return p, nil
}

func (p *pushoverSink) name() string { return "pushover" }

func (p *pushoverSink) send(ctx context.Context, a Alert) error {
	var errs []error
	for _, d := range p.dests {
		if err := p.sendOne(ctx, a, d); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *pushoverSink) sendOne(ctx context.Context, a Alert, dest string) error {
	prio := "0"
	if a.High {
		prio = "1"
	}
	form := url.Values{}
	form.Set("token", p.token)
	form.Set("user", dest)
	form.Set("title", truncate(subject(a), pushoverTitleMax))
	form.Set("message", truncate(body(a), pushoverMessageMax))
	form.Set("priority", prio)
	form.Set("timestamp", strconv.FormatInt(a.Time.Unix(), 10))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pushoverURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("pushover: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("pushover: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("pushover: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
