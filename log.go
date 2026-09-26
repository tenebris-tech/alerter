/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// logWriter appends alert records to a file or to stdout. One record per
// alert: a header line, then details indented on the following lines, so the
// file reads top to bottom and greps by title.
type logWriter struct {
	mu   sync.Mutex
	w    io.Writer
	file *os.File // nil when writing to stdout
}

// openLog opens path for appending, creating it if missing, or returns a
// writer on stdout when path is empty.
func openLog(path string) (*logWriter, error) {
	if path == "" {
		return &logWriter{w: os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // an operator-chosen log path
	if err != nil {
		return nil, fmt.Errorf("alerter: open log %s: %w", path, err)
	}
	return &logWriter{w: f, file: f}, nil
}

// format renders one alert as its log record.
func format(a Alert) string {
	var b strings.Builder
	b.WriteString(a.Time.Format(time.RFC3339))
	fmt.Fprintf(&b, " %-9s ", strings.ToUpper(priorityName(a.Priority)))
	switch {
	case a.App != "" && a.Instance != "":
		b.WriteString(a.App + "@" + a.Instance + " ")
	case a.App != "":
		b.WriteString(a.App + " ")
	case a.Instance != "":
		b.WriteString("@" + a.Instance + " ")
	}
	if a.EventID != "" {
		b.WriteString("[" + a.EventID + "] ")
	}
	b.WriteString(a.Title)
	if a.Description != "" {
		b.WriteString(": " + a.Description)
	}
	if a.Repeats > 0 {
		fmt.Fprintf(&b, " (%d repeat(s) suppressed since the last one)", a.Repeats)
	}
	b.WriteString("\n")
	if a.Details != "" {
		for _, line := range strings.Split(strings.TrimRight(a.Details, "\n"), "\n") {
			b.WriteString("    " + line + "\n")
		}
	}
	return b.String()
}

// formatFailure renders a channel delivery failure: a header line naming the
// channel and the alert, then the error indented.
func formatFailure(t time.Time, channel string, a Alert, err error) string {
	var b strings.Builder
	b.WriteString(t.Format(time.RFC3339) + " ERROR alerter: " + channel + " delivery failed")
	if a.EventID != "" {
		b.WriteString(" [" + a.EventID + "]")
	}
	b.WriteString(": " + a.Title + "\n")
	for _, line := range strings.Split(strings.TrimRight(err.Error(), "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

// formatWarning renders a configuration warning found at startup.
func formatWarning(t time.Time, msg string) string {
	return t.Format(time.RFC3339) + " WARNING alerter: " + msg + "\n"
}

func (l *logWriter) writeWarning(t time.Time, msg string) error {
	return l.writeString(formatWarning(t, msg))
}

func (l *logWriter) writeFailure(t time.Time, channel string, a Alert, err error) error {
	return l.writeString(formatFailure(t, channel, a, err))
}

func (l *logWriter) write(a Alert) error {
	return l.writeString(format(a))
}

func (l *logWriter) writeString(s string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := io.WriteString(l.w, s); err != nil {
		return fmt.Errorf("alerter: write log: %w", err)
	}
	return nil
}

// close closes the file; stdout is left open.
func (l *logWriter) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	l.w = io.Discard
	if err := f.Close(); err != nil {
		return fmt.Errorf("alerter: close log: %w", err)
	}
	return nil
}
