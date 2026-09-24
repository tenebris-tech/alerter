/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// Environment variables that switch on and configure the delivery channels.
// A channel is on when any of its variables is set; a channel that is on
// but incomplete or malformed makes New fail, so a typo shows at startup.
// Lists (recipients) are comma separated.
const (
	EnvPushoverToken = "ALERTER_PUSHOVER_TOKEN" // application API token
	EnvPushoverDest  = "ALERTER_PUSHOVER_DEST"  // user or group keys

	EnvTelnyxAPIKey = "ALERTER_TELNYX_API_KEY" // Telnyx API v2 key
	EnvSMSFrom      = "ALERTER_SMS_FROM"       // E.164 sending number
	EnvSMSTo        = "ALERTER_SMS_TO"         // E.164 recipients

	EnvSMTPHost     = "ALERTER_SMTP_HOST"
	EnvSMTPPort     = "ALERTER_SMTP_PORT" // default 587; 465 is implicit TLS
	EnvSMTPUser     = "ALERTER_SMTP_USER" // with PASSWORD, or neither
	EnvSMTPPassword = "ALERTER_SMTP_PASSWORD"
	EnvSMTPFrom     = "ALERTER_SMTP_FROM"
	EnvSMTPTo       = "ALERTER_SMTP_TO"
)

// sinkTimeout bounds one delivery attempt to one channel, so a hung service
// cannot stall the queue. A variable so tests can shorten it.
var sinkTimeout = 30 * time.Second

// newHTTPClient returns the client for the HTTP channels. Redirects are not
// followed: a redirect would re-send the request body, which for Pushover
// carries the token, to whatever host it names.
func newHTTPClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// sink is one delivery channel beyond the log.
type sink interface {
	name() string
	send(ctx context.Context, a Alert) error
}

// sinksFromEnv builds every channel whose variables are set.
func sinksFromEnv() ([]sink, error) {
	var sinks []sink
	var errs []error
	for _, build := range []func() (sink, error){pushoverFromEnv, smsFromEnv, smtpFromEnv} {
		s, err := build()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if s != nil {
			sinks = append(sinks, s)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return sinks, nil
}

// env reads and trims one variable.
func env(key string) string { return strings.TrimSpace(os.Getenv(key)) }

// anySet reports whether any of the variables is non-empty.
func anySet(keys ...string) bool {
	for _, k := range keys {
		if env(k) != "" {
			return true
		}
	}
	return false
}

// require returns an error naming every variable in keys that is empty.
func require(channel string, keys ...string) error {
	var missing []string
	for _, k := range keys {
		if env(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("alerter: %s: %s not set", channel, strings.Join(missing, ", "))
	}
	return nil
}

// list splits a comma-separated variable, dropping empty entries.
func list(key string) []string {
	var out []string
	for _, s := range strings.Split(env(key), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// source is "App@Instance", "App", "@Instance" or "".
func source(a Alert) string {
	switch {
	case a.App != "" && a.Instance != "":
		return a.App + "@" + a.Instance
	case a.App != "":
		return a.App
	case a.Instance != "":
		return "@" + a.Instance
	}
	return ""
}

func priority(a Alert) string {
	if a.High {
		return "HIGH"
	}
	return "LOW"
}

// subject is the one-line heading every channel uses:
// "HIGH ClawEh@empire: Provider authentication failed". Line breaks are
// flattened so it is safe as a mail header.
func subject(a Alert) string {
	s := priority(a)
	if src := source(a); src != "" {
		s += " " + src
	}
	s += ": " + a.Title
	return strings.Join(strings.Fields(s), " ")
}

// body is the message text for channels that carry more than a line.
func body(a Alert) string {
	var b strings.Builder
	if a.Description != "" {
		b.WriteString(a.Description + "\n\n")
	}
	fmt.Fprintf(&b, "Priority: %s\n", priority(a))
	if src := source(a); src != "" {
		fmt.Fprintf(&b, "Source: %s\n", src)
	}
	if a.EventID != "" {
		fmt.Fprintf(&b, "Event: %s\n", a.EventID)
	}
	fmt.Fprintf(&b, "Time: %s\n", a.Time.Format(time.RFC3339))
	if a.Repeats > 0 {
		fmt.Fprintf(&b, "Repeats: %d suppressed since the last one\n", a.Repeats)
	}
	if a.Details != "" {
		b.WriteString("\n" + strings.TrimRight(a.Details, "\n") + "\n")
	}
	return b.String()
}

// truncate cuts s to at most n runes, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
