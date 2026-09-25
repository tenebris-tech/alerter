/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

// Package alerter sends outbound alerts on behalf of an application: a
// condition the operator should hear about through something other than the
// application's own user channels. An application builds one Alerter at
// startup, hands it to the packages that need it, and calls Send from any
// goroutine. Delivery happens on a worker goroutine; callers never wait on
// I/O, and a full queue drops the alert rather than blocking.
//
// Every alert is written to a log: the file named by WithLogFile, else the
// file named by the ALERTER_LOG environment variable, else stdout. It is also
// delivered to each channel whose ALERTER_* environment variables are set:
// Pushover, SMS (Telnyx), mail (SMTP) and a JSON webhook. The calling application does not
// choose channels; the environment does. New first loads ~/.alerter, when it
// exists, into the environment (see EnvFileName).
package alerter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultQueueSize is the number of alerts that may wait for delivery
	// before Send starts dropping.
	DefaultQueueSize = 256
	// DefaultSuppressWindow is how long a repeat of an alert (same Title, or
	// same Title and EventID) is held back after one was sent.
	DefaultSuppressWindow = 10 * time.Minute
	// EnvLogFile names the environment variable consulted for the log path
	// when WithLogFile is not used.
	EnvLogFile = "ALERTER_LOG"
)

// Alert is one notification. The caller fills High, Title, Description and,
// optionally, Details and EventID; the alerter stamps the rest.
type Alert struct {
	// High marks a high-priority alert: something that stops the application
	// doing its job. Low priority (false) is degraded but working.
	High bool
	// Title is the short, stable statement of the condition. It is the
	// de-duplication key, so repeats should use the same title.
	Title string
	// Description says what happened this time, in a sentence.
	Description string
	// Details carries anything longer: an error text, a command line, a
	// stack of context. Optional.
	Details string
	// EventID distinguishes instances of the same condition, for example the
	// provider or server it concerns. When set, de-duplication is by Title
	// and EventID together.
	EventID string

	// Time, App and Instance are stamped by the alerter when the alert is
	// accepted; values supplied by the caller are overwritten.
	Time     time.Time
	App      string
	Instance string
	// Repeats is the number of identical alerts suppressed since the last one
	// delivered for this key, stamped on the first alert sent after the
	// window. Zero when nothing was suppressed.
	Repeats int
}

// key is the de-duplication key: title alone, or title and event id.
func (a Alert) key() string {
	if a.EventID == "" {
		return a.Title
	}
	return a.Title + "\x00" + a.EventID
}

// Alerter is what application packages receive. Send never blocks the caller
// beyond an enqueue and never panics; High and Low are shorthands for Send.
// Close delivers what is queued, within ctx, then stops.
type Alerter interface {
	Send(a Alert)
	High(title, description string, details ...string)
	Low(title, description string, details ...string)
	Close(ctx context.Context) error
}

// Stats counts what happened to the alerts handed to an alerter.
type Stats struct {
	// Sent alerts were delivered to the log and to every configured channel.
	Sent uint64
	// Dropped alerts were discarded because the queue was full or the alerter
	// was already closed.
	Dropped uint64
	// Suppressed alerts were repeats held back inside the suppress window.
	Suppressed uint64
	// Failed alerts reached delivery but the log write or at least one
	// channel returned an error. Each channel failure is recorded in the log.
	Failed uint64
}

// Option configures New.
type Option func(*options) error

type options struct {
	app, instance  string
	logFile        string
	queueSize      int
	suppressWindow time.Duration
	now            func() time.Time // tests
}

// WithAppName names the application in every alert, e.g. "ClawEh".
func WithAppName(name string) Option {
	return func(o *options) error {
		o.app = strings.TrimSpace(name)
		return nil
	}
}

// WithInstanceName distinguishes several instances of one application, e.g.
// the host name the application runs on.
func WithInstanceName(name string) Option {
	return func(o *options) error {
		o.instance = strings.TrimSpace(name)
		return nil
	}
}

// WithLogFile writes alerts to this file (full path and file name), created
// if missing and appended to otherwise. It takes precedence over ALERTER_LOG.
func WithLogFile(path string) Option {
	return func(o *options) error {
		path = strings.TrimSpace(path)
		if path == "" {
			return errors.New("alerter: WithLogFile: empty path")
		}
		o.logFile = path
		return nil
	}
}

// WithQueueSize sets how many alerts may wait for delivery before Send drops.
func WithQueueSize(n int) Option {
	return func(o *options) error {
		if n <= 0 {
			return fmt.Errorf("alerter: WithQueueSize: %d is not positive", n)
		}
		o.queueSize = n
		return nil
	}
}

// WithSuppressWindow sets how long a repeat of an alert is held back after one
// was sent. Zero turns suppression off.
func WithSuppressWindow(d time.Duration) Option {
	return func(o *options) error {
		if d < 0 {
			return fmt.Errorf("alerter: WithSuppressWindow: %v is negative", d)
		}
		o.suppressWindow = d
		return nil
	}
}

// withClock replaces the clock; tests only.
func withClock(now func() time.Time) Option {
	return func(o *options) error {
		o.now = now
		return nil
	}
}

// Dispatcher is the Alerter New returns: a queue, one delivery goroutine, and
// repeat suppression in front of the log.
type Dispatcher struct {
	app, instance  string
	suppressWindow time.Duration
	now            func() time.Time

	queue  chan Alert
	done   chan struct{}
	mu     sync.RWMutex // guards closed and the channel close
	closed bool

	log   *logWriter
	sinks []sink

	// last is the delivery goroutine's private view: when each key was last
	// delivered, and how many repeats were suppressed since.
	last map[string]*suppressed

	sent, dropped, suppressedN, failed atomic.Uint64
}

type suppressed struct {
	at    time.Time
	count int
}

// New builds an Alerter from the options and starts its delivery goroutine.
// It first loads ~/.alerter into the environment, then decides the log
// destination (WithLogFile, else ALERTER_LOG, else stdout) and the delivery
// channels (each channel whose ALERTER_* variables are set). An unreadable
// ~/.alerter, a named log file that cannot be opened, or a channel that is
// incompletely or wrongly configured is an error.
func New(opts ...Option) (*Dispatcher, error) {
	if err := loadEnvFile(); err != nil {
		return nil, err
	}
	o := options{
		queueSize:      DefaultQueueSize,
		suppressWindow: DefaultSuppressWindow,
		now:            time.Now,
	}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	path := o.logFile
	if path == "" {
		path = strings.TrimSpace(os.Getenv(EnvLogFile))
	}
	sinks, err := sinksFromEnv()
	if err != nil {
		return nil, err
	}
	lw, err := openLog(path)
	if err != nil {
		return nil, err
	}
	d := &Dispatcher{
		app:            o.app,
		instance:       o.instance,
		suppressWindow: o.suppressWindow,
		now:            o.now,
		queue:          make(chan Alert, o.queueSize),
		done:           make(chan struct{}),
		log:            lw,
		sinks:          sinks,
		last:           map[string]*suppressed{},
	}
	go d.run()
	return d, nil
}

// Send queues a for delivery. It returns at once; a full queue or a closed
// alerter drops the alert and counts it.
func (d *Dispatcher) Send(a Alert) {
	a.Time = d.now()
	a.App = d.app
	a.Instance = d.instance
	a.Repeats = 0

	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		d.dropped.Add(1)
		return
	}
	select {
	case d.queue <- a:
	default:
		d.dropped.Add(1)
	}
}

// High sends a high-priority alert. Details, when given, are joined with
// newlines.
func (d *Dispatcher) High(title, description string, details ...string) {
	d.Send(Alert{High: true, Title: title, Description: description, Details: strings.Join(details, "\n")})
}

// Low sends a low-priority alert.
func (d *Dispatcher) Low(title, description string, details ...string) {
	d.Send(Alert{Title: title, Description: description, Details: strings.Join(details, "\n")})
}

// Close stops accepting alerts, delivers what is already queued, and closes
// the log. It returns ctx's error if delivery does not finish in time; the
// alerts still queued are then lost when the process exits. Close is safe to
// call more than once.
func (d *Dispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	close(d.queue)
	d.mu.Unlock()

	select {
	case <-d.done:
	case <-ctx.Done():
		return fmt.Errorf("alerter: close: %w", ctx.Err())
	}
	return d.log.close()
}

// Stats returns the counters so far.
func (d *Dispatcher) Stats() Stats {
	return Stats{
		Sent:       d.sent.Load(),
		Dropped:    d.dropped.Load(),
		Suppressed: d.suppressedN.Load(),
		Failed:     d.failed.Load(),
	}
}

// run is the delivery goroutine: suppression, then the log and every
// channel in turn.
func (d *Dispatcher) run() {
	defer close(d.done)
	for a := range d.queue {
		if !d.admit(&a) {
			continue
		}
		if d.deliver(a) {
			d.sent.Add(1)
		} else {
			d.failed.Add(1)
		}
	}
}

// deliver writes a to the log and sends it to every channel at once, each
// bounded by sinkTimeout, so a dead channel delays the others by at most one
// timeout. A channel failure is recorded in the log. It reports whether every
// delivery succeeded.
func (d *Dispatcher) deliver(a Alert) bool {
	ok := d.log.write(a) == nil
	errs := make([]error, len(d.sinks))
	var wg sync.WaitGroup
	for i, s := range d.sinks {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), sinkTimeout)
			defer cancel()
			errs[i] = s.send(ctx, a)
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			ok = false
			_ = d.log.writeFailure(d.now(), d.sinks[i].name(), a, err)
		}
	}
	return ok
}

// admit applies repeat suppression. It reports whether a should be delivered,
// stamping Repeats with the number of copies held back since the last
// delivery of the same key.
func (d *Dispatcher) admit(a *Alert) bool {
	if d.suppressWindow <= 0 {
		return true
	}
	k := a.key()
	now := a.Time
	s, seen := d.last[k]
	if seen && now.Sub(s.at) < d.suppressWindow {
		s.count++
		d.suppressedN.Add(1)
		return false
	}
	if seen {
		a.Repeats = s.count
	}
	d.last[k] = &suppressed{at: now}
	if len(d.last) > 1024 {
		d.prune(now)
	}
	return true
}

// prune drops keys whose window has passed, so a long-running process with
// many distinct titles does not grow the map without bound.
func (d *Dispatcher) prune(now time.Time) {
	for k, s := range d.last {
		if now.Sub(s.at) >= d.suppressWindow {
			delete(d.last, k)
		}
	}
}
