/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	_ Alerter = (*Dispatcher)(nil)
	_ Alerter = Nop{}
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newTest builds a dispatcher writing to a temp file with a fixed clock, and
// returns the file path so tests can read what was written after Close.
func newTest(t *testing.T, opts ...Option) (*Dispatcher, string, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 9, 24, 10, 0, 0, 0, time.FixedZone("EDT", -4*3600))}
	path := filepath.Join(t.TempDir(), "alerts.txt")
	all := append([]Option{WithLogFile(path), withClock(c.now), WithAppName("Claw"), WithInstanceName("empire")}, opts...)
	d, err := New(all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = d.Close(context.Background()) })
	return d, path, c
}

func closeAndRead(t *testing.T, d *Dispatcher, path string) string {
	t.Helper()
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b, err := os.ReadFile(path) //nolint:gosec // test temp file
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(b)
}

func TestDefaults(t *testing.T) {
	d, _, _ := newTest(t)
	if cap(d.queue) != DefaultQueueSize {
		t.Errorf("queue size = %d, want %d", cap(d.queue), DefaultQueueSize)
	}
	if d.suppressWindow != DefaultSuppressWindow {
		t.Errorf("suppress window = %v, want %v", d.suppressWindow, DefaultSuppressWindow)
	}
	d2, _, _ := newTest(t, WithQueueSize(3), WithSuppressWindow(time.Second))
	if cap(d2.queue) != 3 || d2.suppressWindow != time.Second {
		t.Errorf("overrides not applied: queue %d window %v", cap(d2.queue), d2.suppressWindow)
	}
}

func TestOptionErrors(t *testing.T) {
	cases := []struct {
		name string
		opt  Option
	}{
		{"empty log file", WithLogFile("  ")},
		{"zero queue", WithQueueSize(0)},
		{"negative queue", WithQueueSize(-1)},
		{"negative window", WithSuppressWindow(-time.Second)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opt); err == nil {
				t.Errorf("New(%s) accepted an invalid option", tc.name)
			}
		})
	}
}

func TestDestinationPrecedence(t *testing.T) {
	dir := t.TempDir()
	optPath := filepath.Join(dir, "option.txt")
	envPath := filepath.Join(dir, "env.txt")

	t.Run("option beats environment", func(t *testing.T) {
		t.Setenv(EnvLogFile, envPath)
		d, err := New(WithLogFile(optPath))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		d.Urgent("t", "d")
		if err := d.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := os.Stat(optPath); err != nil {
			t.Errorf("option file not written: %v", err)
		}
		if _, err := os.Stat(envPath); !os.IsNotExist(err) {
			t.Errorf("environment file must not be used when the option is set")
		}
	})

	t.Run("environment when no option", func(t *testing.T) {
		t.Setenv(EnvLogFile, envPath)
		d, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		d.Normal("t", "d")
		if err := d.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		b, err := os.ReadFile(envPath) //nolint:gosec // test temp file
		if err != nil || !strings.Contains(string(b), "NORMAL    t: d") {
			t.Errorf("environment file content = %q, err = %v", b, err)
		}
	})

	t.Run("stdout when neither", func(t *testing.T) {
		t.Setenv(EnvLogFile, "")
		d, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if d.log.w != os.Stdout || d.log.file != nil {
			t.Error("expected the stdout writer")
		}
		if err := d.Close(context.Background()); err != nil {
			t.Errorf("Close on stdout: %v", err)
		}
	})

	t.Run("unopenable path is an error", func(t *testing.T) {
		if _, err := New(WithLogFile(filepath.Join(dir, "missing-dir", "alerts.txt"))); err == nil {
			t.Error("expected an open error")
		}
	})
}

func TestSendWritesRecord(t *testing.T) {
	d, path, _ := newTest(t)
	d.Send(Alert{Priority: Urgent, Title: "Provider authentication failed", Description: "claude-cli returned 401",
		Details: "line one\nline two\n", EventID: "claude-cli"})
	got := closeAndRead(t, d, path)
	want := "2026-09-24T10:00:00-04:00 URGENT    Claw@empire [claude-cli] Provider authentication failed: claude-cli returned 401\n" +
		"    line one\n    line two\n"
	if got != want {
		t.Errorf("record =\n%q\nwant\n%q", got, want)
	}
	if s := d.Stats(); s.Sent != 1 || s.Dropped != 0 || s.Suppressed != 0 || s.Failed != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestLevelHelpers(t *testing.T) {
	d, path, _ := newTest(t)
	d.Normal("N", "normal one")
	d.Urgent("P", "priority one", "d1", "d2")
	d.Emergency("E", "emergency one", "e1")
	got := closeAndRead(t, d, path)
	want := "2026-09-24T10:00:00-04:00 NORMAL    Claw@empire N: normal one\n" +
		"2026-09-24T10:00:00-04:00 URGENT    Claw@empire P: priority one\n    d1\n    d2\n" +
		"2026-09-24T10:00:00-04:00 EMERGENCY Claw@empire E: emergency one\n    e1\n"
	if got != want {
		t.Errorf("log =\n%s\nwant\n%s", got, want)
	}
}

// capture is a sink that records what reaches delivery.
type capture struct {
	mu     sync.Mutex
	alerts []Alert
}

func (c *capture) name() string { return "capture" }
func (c *capture) send(_ context.Context, a Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a)
	return nil
}

func TestHelpersStampPriority(t *testing.T) {
	d, _, _ := newTest(t, WithSuppressWindow(0))
	c := &capture{}
	d.sinks = []channel{{sink: c}}
	d.Normal("n", "")
	d.Urgent("p", "")
	d.Emergency("e", "")
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{Normal, Urgent, Emergency} {
		if c.alerts[i].Priority != want {
			t.Errorf("alert %d priority = %d, want %d", i, c.alerts[i].Priority, want)
		}
	}
}

func TestSendNormalisesPriority(t *testing.T) {
	d, path, _ := newTest(t, WithSuppressWindow(0))
	c := &capture{}
	d.sinks = []channel{{sink: c}}
	in := []int{-1, 3, 100, math.MinInt, math.MaxInt, Normal, Urgent, Emergency}
	want := []int{Normal, Normal, Normal, Normal, Normal, Normal, Urgent, Emergency}
	for i, p := range in {
		d.Send(Alert{Priority: p, Title: fmt.Sprintf("t%d", i)})
	}
	log := closeAndRead(t, d, path)
	for i := range in {
		if c.alerts[i].Priority != want[i] {
			t.Errorf("Priority %d delivered as %d, want %d", in[i], c.alerts[i].Priority, want[i])
		}
	}
	if n := strings.Count(log, " NORMAL    "); n != 6 {
		t.Errorf("%d NORMAL records, want 6:\n%s", n, log)
	}
}

func TestLevelAndName(t *testing.T) {
	cases := []struct {
		in    int
		level int
		name  string
	}{
		{Normal, Normal, "Normal"}, {Urgent, Urgent, "Urgent"}, {Emergency, Emergency, "Emergency"},
		{-1, Normal, "Normal"}, {3, Normal, "Normal"}, {math.MaxInt, Normal, "Normal"},
	}
	for _, tc := range cases {
		if level(tc.in) != tc.level || priorityName(tc.in) != tc.name {
			t.Errorf("%d: level %d name %q", tc.in, level(tc.in), priorityName(tc.in))
		}
	}
	if Normal != 0 || Urgent != 1 || Emergency != 2 {
		t.Error("the levels are part of the contract: 0, 1, 2")
	}
}

func TestFormat(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		a    Alert
		want string
	}{
		{"normal, no identity", Alert{Time: at, Title: "T"}, "2026-01-02T03:04:05Z NORMAL    T\n"},
		{"emergency", Alert{Time: at, Priority: Emergency, Title: "T"}, "2026-01-02T03:04:05Z EMERGENCY T\n"},
		{"out of range", Alert{Time: at, Priority: 7, Title: "T"}, "2026-01-02T03:04:05Z NORMAL    T\n"},
		{"app only", Alert{Time: at, Title: "T", App: "A"}, "2026-01-02T03:04:05Z NORMAL    A T\n"},
		{"instance only", Alert{Time: at, Title: "T", Instance: "I"}, "2026-01-02T03:04:05Z NORMAL    @I T\n"},
		{"repeats", Alert{Time: at, Priority: Urgent, Title: "T", Description: "D", Repeats: 3},
			"2026-01-02T03:04:05Z URGENT    T: D (3 repeat(s) suppressed since the last one)\n"},
		{"details without trailing newline", Alert{Time: at, Title: "T", Details: "x"}, "2026-01-02T03:04:05Z NORMAL    T\n    x\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := format(tc.a); got != tc.want {
				t.Errorf("format = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSuppression(t *testing.T) {
	d, path, c := newTest(t, WithSuppressWindow(10*time.Minute))
	for range 3 {
		d.Urgent("Logged out", "again")
	}
	d.Urgent("Logged out", "other provider", "")
	d.Send(Alert{Title: "Logged out", EventID: "codex"}) // different key
	d.Send(Alert{Title: "Logged out", EventID: "codex"}) // repeat of that key
	c.advance(11 * time.Minute)
	d.Urgent("Logged out", "after the window")
	got := closeAndRead(t, d, path)

	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 records, got %d:\n%s", len(lines), got)
	}
	if !strings.HasSuffix(lines[0], "Logged out: again") {
		t.Errorf("first record = %q", lines[0])
	}
	if !strings.Contains(lines[1], "[codex] Logged out") {
		t.Errorf("event-id record = %q", lines[1])
	}
	if !strings.HasSuffix(lines[2], "Logged out: after the window (3 repeat(s) suppressed since the last one)") {
		t.Errorf("post-window record = %q", lines[2])
	}
	if s := d.Stats(); s.Sent != 3 || s.Suppressed != 4 {
		t.Errorf("stats = %+v, want sent 3 suppressed 4", s)
	}
}

func TestSuppressionOff(t *testing.T) {
	d, path, _ := newTest(t, WithSuppressWindow(0))
	for range 3 {
		d.Normal("same", "x")
	}
	got := closeAndRead(t, d, path)
	if n := strings.Count(got, "same: x"); n != 3 {
		t.Errorf("records = %d, want 3 with suppression off", n)
	}
}

func TestPrune(t *testing.T) {
	d, _, c := newTest(t, WithSuppressWindow(time.Minute), WithQueueSize(4096))
	for i := range 1100 {
		d.Send(Alert{Title: fmt.Sprintf("t%d", i)})
	}
	c.advance(2 * time.Minute)
	d.Send(Alert{Title: "trigger"}) // past the threshold with everything expired
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(d.last) > 1024 {
		t.Errorf("suppression map not pruned: %d keys", len(d.last))
	}
}

// blockingWriter holds every write until release is closed.
type blockingWriter struct {
	release chan struct{}
	writes  int
	mu      sync.Mutex
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	<-b.release
	b.mu.Lock()
	b.writes++
	b.mu.Unlock()
	return len(p), nil
}

func TestQueueFullDrops(t *testing.T) {
	d, _, _ := newTest(t, WithQueueSize(2), WithSuppressWindow(0))
	bw := &blockingWriter{release: make(chan struct{})}
	d.log.mu.Lock()
	d.log.w = bw
	d.log.mu.Unlock()

	// One alert is taken by the worker and blocks in Write; two fill the
	// queue; the rest are dropped.
	for i := range 6 {
		d.Send(Alert{Title: fmt.Sprintf("t%d", i)})
		time.Sleep(5 * time.Millisecond)
	}
	if s := d.Stats(); s.Dropped < 3 {
		t.Errorf("dropped = %d, want at least 3", s.Dropped)
	}
	close(bw.release)
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s := d.Stats(); s.Sent+s.Dropped != 6 {
		t.Errorf("sent %d + dropped %d != 6", s.Sent, s.Dropped)
	}
}

func TestConcurrentSend(t *testing.T) {
	const goroutines, each = 200, 50
	d, path, _ := newTest(t, WithQueueSize(goroutines*each), WithSuppressWindow(0))
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			for i := range each {
				d.Send(Alert{Title: fmt.Sprintf("g%d-%d", g, i)})
			}
		})
	}
	wg.Wait()
	got := closeAndRead(t, d, path)
	if n := strings.Count(got, "\n"); n != goroutines*each {
		t.Errorf("records = %d, want %d", n, goroutines*each)
	}
	if s := d.Stats(); s.Sent != goroutines*each || s.Dropped != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestCloseIdempotentAndDropsAfter(t *testing.T) {
	d, _, _ := newTest(t)
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := d.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
	d.Urgent("late", "after close")
	if s := d.Stats(); s.Dropped != 1 {
		t.Errorf("dropped after close = %d, want 1", s.Dropped)
	}
}

func TestCloseTimeout(t *testing.T) {
	d, _, _ := newTest(t)
	bw := &blockingWriter{release: make(chan struct{})}
	d.log.mu.Lock()
	d.log.w = bw
	d.log.mu.Unlock()
	d.Normal("stuck", "in write")
	time.Sleep(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := d.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close error = %v, want deadline exceeded", err)
	}
	close(bw.release) // let the worker finish so the test does not leak it
	<-d.done
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteFailureCounted(t *testing.T) {
	d, _, _ := newTest(t)
	d.log.mu.Lock()
	d.log.w = failingWriter{}
	d.log.mu.Unlock()
	d.Urgent("x", "y")
	if err := d.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s := d.Stats(); s.Failed != 1 || s.Sent != 0 {
		t.Errorf("stats = %+v, want failed 1", s)
	}
}

func TestLogWriterCloseTwice(t *testing.T) {
	lw, err := openLog(filepath.Join(t.TempDir(), "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lw.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := lw.close(); err != nil {
		t.Errorf("second close: %v", err)
	}
	// Writes after close go nowhere but do not fail.
	if err := lw.write(Alert{Title: "x"}); err != nil {
		t.Errorf("write after close: %v", err)
	}
}

func TestNop(t *testing.T) {
	var n Nop
	n.Send(Alert{Title: "x"})
	n.Urgent("h", "d", "x")
	n.Emergency("e", "d")
	n.Normal("l", "d")
	if err := n.Close(context.Background()); err != nil {
		t.Errorf("Close: %v", err)
	}
}
