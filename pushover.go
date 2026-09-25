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

// Default priorities: 1 bypasses the recipient's quiet hours, 0 does not.
const (
	defaultPushoverHigh = 1
	defaultPushoverLow  = 0
)

// Emergency (priority 2) messages repeat until acknowledged; Pushover
// requires the interval and the give-up time, in seconds.
const (
	pushoverRetry  = 60
	pushoverExpire = 3600
)

// pushoverSink sends one Pushover message per destination key, at the
// priority configured for high or low alerts (-2 lowest to 2 emergency).
type pushoverSink struct {
	token     string
	dests     []string
	high, low int
	http      *http.Client
}

func pushoverFromEnv() (sink, error) {
	if !anySet(EnvPushoverToken, EnvPushoverDest, EnvPushoverHigh, EnvPushoverLow) {
		return nil, nil
	}
	if err := require("pushover", EnvPushoverToken, EnvPushoverDest); err != nil {
		return nil, err
	}
	p := &pushoverSink{token: env(EnvPushoverToken), dests: list(EnvPushoverDest), http: newHTTPClient()}
	if len(p.dests) == 0 {
		return nil, fmt.Errorf("alerter: pushover: %s has no key", EnvPushoverDest)
	}
	var err error
	if p.high, err = pushoverPriority(EnvPushoverHigh, defaultPushoverHigh); err != nil {
		return nil, err
	}
	if p.low, err = pushoverPriority(EnvPushoverLow, defaultPushoverLow); err != nil {
		return nil, err
	}
	return p, nil
}

// pushoverPriority reads a priority variable: an integer from -2 to 2, or
// def when unset.
func pushoverPriority(key string, def int) (int, error) {
	v := env(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < -2 || n > 2 {
		return 0, fmt.Errorf("alerter: pushover: %s %q is not a priority from -2 to 2", key, v)
	}
	return n, nil
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
	prio := p.low
	if a.High {
		prio = p.high
	}
	form := url.Values{}
	form.Set("token", p.token)
	form.Set("user", dest)
	form.Set("title", truncate(subject(a), pushoverTitleMax))
	form.Set("message", truncate(body(a), pushoverMessageMax))
	form.Set("priority", strconv.Itoa(prio))
	if prio == 2 {
		form.Set("retry", strconv.Itoa(pushoverRetry))
		form.Set("expire", strconv.Itoa(pushoverExpire))
	}
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
