/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

// openLog opens path for appending, or returns a writer on stdout when path
// is empty. A missing file, and any missing directories above it, are created
// with exactly fileMode and dirMode; ones that already exist keep their modes.
func openLog(path string, dirMode, fileMode fs.FileMode) (*logWriter, error) {
	if path == "" {
		return &logWriter{w: os.Stdout}, nil
	}
	if err := makeDirs(filepath.Dir(path), dirMode); err != nil {
		return nil, err
	}
	// Create with O_EXCL to know whether the file is ours to set the mode of.
	// If it exists, reopen it; if it vanished in between, try once more.
	for range 2 {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileMode) //nolint:gosec // an operator-chosen log path
		if err == nil {
			if err := f.Chmod(fileMode); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("alerter: set log mode %s: %w", path, err)
			}
			return &logWriter{w: f, file: f}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("alerter: open log %s: %w", path, err)
		}
		f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // an operator-chosen log path
		if err == nil {
			return &logWriter{w: f, file: f}, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("alerter: open log %s: %w", path, err)
		}
	}
	return nil, fmt.Errorf("alerter: open log %s: %w", path, fs.ErrNotExist)
}

// makeDirs creates dir and any missing parents, each with exactly mode.
// Directories that already exist are left as they are.
func makeDirs(dir string, mode fs.FileMode) error {
	if _, err := os.Stat(dir); err == nil {
		return nil // exists (if it is not a directory, opening the log reports it)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("alerter: log directory %s: %w", dir, err)
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := makeDirs(parent, mode); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, mode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil // created by someone else meanwhile: not ours to change
		}
		return fmt.Errorf("alerter: create log directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("alerter: set log directory mode %s: %w", dir, err)
	}
	return nil
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
