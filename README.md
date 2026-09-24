# alerter

Outbound alerts for Go services. An application builds one alerter at
startup, hands it to the packages that need it, and calls `Send` from any
goroutine. Delivery happens on a worker goroutine, so callers never wait on
I/O; a full queue drops the alert rather than blocking.

Version 0.0.x writes alerts to a log file. Later versions add delivery
channels (mail, push services), each configured by its own `ALERTER_*`
environment variables.

## Use

```go
al, err := alerter.New(
    alerter.WithAppName("ClawEh"),
    alerter.WithInstanceName(hostname),          // optional
    alerter.WithLogFile("/var/log/claw/alerts.txt"), // optional, see below
)
if err != nil {
    return err
}
defer al.Close(ctx)

al.High("Provider authentication failed", "claude-cli returned 401",
    "run `claude login` on the host")
al.Send(alerter.Alert{
    Title:       "MCP server unreachable",
    Description: "fusion did not answer for 3 probes",
    EventID:     "fusion", // repeats collapse per server
})
```

Packages that need alerting take the `alerter.Alerter` interface; `alerter.Nop`
satisfies it for tests and for hosts that run without alerting.

## Where alerts go

1. the file named by `WithLogFile`, if set;
2. otherwise the file named by the `ALERTER_LOG` environment variable;
3. otherwise stdout.

Both file settings expect a full path and file name. The file is created if
missing and appended to otherwise. One record per alert:

```
2026-09-24T10:00:00-04:00 HIGH ClawEh@empire [claude-cli] Provider authentication failed: claude-cli returned 401
    run `claude login` on the host
```

## Behaviour

- **Priority**: `High` is something that stops the application doing its job;
  `Low` is degraded but working.
- **Repeat suppression**: an alert with the same title (or the same title and
  `EventID`, when set) as one delivered inside the suppress window is held
  back and counted; the next delivery after the window says how many were
  suppressed. Default window 10 minutes (`WithSuppressWindow`; 0 turns it
  off).
- **Queue**: `DefaultQueueSize` (256) alerts may wait for delivery
  (`WithQueueSize`). When the queue is full, `Send` drops the alert and counts
  it. `Stats()` returns sent, dropped, suppressed and failed counts.
- **Close** delivers what is queued, within the context given, then closes
  the log.

## Development

`make test` is the gate: format check, `go vet`, `go test -race` with a 90%
coverage floor, and a summary. `make` runs it and then builds.
