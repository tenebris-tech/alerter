/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// webhookSink POSTs each alert as JSON (see webhookPayload) to one URL, with
// the configured extra headers.
type webhookSink struct {
	url     string
	headers map[string]string
	http    *http.Client
}

func webhookFromEnv() (sink, error) {
	if !anySet(EnvWebhookURL, EnvWebhookHeaders) {
		return nil, nil
	}
	if err := require("webhook", EnvWebhookURL); err != nil {
		return nil, err
	}
	u, err := url.Parse(env(EnvWebhookURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("alerter: webhook: %s is not an http or https URL", EnvWebhookURL)
	}
	w := &webhookSink{url: u.String(), http: newHTTPClient()}
	if h := env(EnvWebhookHeaders); h != "" {
		if err := json.Unmarshal([]byte(h), &w.headers); err != nil {
			return nil, fmt.Errorf(`alerter: webhook: %s must be a JSON object of strings, e.g. {"Authorization":"Bearer x"}: %w`, EnvWebhookHeaders, err)
		}
		for k, v := range w.headers {
			if !validHeaderName(k) || strings.ContainsAny(v, "\r\n\x00") {
				return nil, fmt.Errorf("alerter: webhook: %s: invalid header %q", EnvWebhookHeaders, k)
			}
		}
	}
	return w, nil
}

func (w *webhookSink) name() string { return "webhook" }

func (w *webhookSink) send(ctx context.Context, a Alert) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, strings.NewReader(webhookPayload(a)))
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// validHeaderName reports whether s is an HTTP token (RFC 9110 5.1).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}
