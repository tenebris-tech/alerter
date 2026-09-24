# alerter

Outbound alerts for Go services. An application builds one alerter at
startup, hands it to the packages that need it, and calls `Send` from any
goroutine. Delivery happens on a worker goroutine, so callers never wait on
I/O; a full queue drops the alert rather than blocking.

Every alert is written to a log and delivered to each channel configured in
the environment: Pushover, SMS (Telnyx) and mail (SMTP). The application
never chooses where alerts go; the operator does, through `ALERTER_*`
variables.

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

## Configuration: `~/.alerter`

`New` first loads `~/.alerter`, when it exists, into the process environment:
one `KEY=VALUE` per line, `#` comment lines, optional `export ` and quotes.
Only `ALERTER_*` keys are loaded; anything else in the file is ignored, so the
file cannot change the host application's environment. A variable already
set in the environment (a service unit, a shell export) wins over the file.
An unreadable or malformed file makes `New` fail. The file holds credentials:
keep it mode 0600.

## Where alerts go

**The log**, always:

1. the file named by `WithLogFile`, if set;
2. otherwise the file named by the `ALERTER_LOG` environment variable;
3. otherwise stdout.

Both file settings expect a full path and file name. The file is created if
missing and appended to otherwise. One record per alert:

```
2026-09-24T10:00:00-04:00 HIGH ClawEh@empire [claude-cli] Provider authentication failed: claude-cli returned 401
    run `claude login` on the host
```

**Channels**, each one on when any of its variables is set. A channel that is
on but incomplete or malformed (a missing variable, a bad port, a number not
in E.164 form, an unparsable address) makes `New` fail, so a typo shows at
startup rather than at the first alert. Lists are comma separated.

| Channel | Variables | Notes |
|---|---|---|
| Pushover | `ALERTER_PUSHOVER_TOKEN` (application token), `ALERTER_PUSHOVER_DEST` (user or group keys) | High alerts at priority 1 (bypass quiet hours), low at 0. |
| SMS (Telnyx) | `ALERTER_TELNYX_API_KEY`, `ALERTER_SMS_FROM`, `ALERTER_SMS_TO` (E.164, e.g. `+15551234567`) | Subject line and description, up to 300 characters. |
| Mail (SMTP) | `ALERTER_SMTP_HOST`, `ALERTER_SMTP_FROM`, `ALERTER_SMTP_TO`; optional `ALERTER_SMTP_PORT` (default 587), `ALERTER_SMTP_USER` with `ALERTER_SMTP_PASSWORD` | Port 465 is implicit TLS; any other port must offer STARTTLS, so neither the alert nor the credentials cross the network in clear. A loopback host (a local relay) may run without TLS. |

Every channel receives every alert that passes repeat suppression. The
channels are sent to in parallel, each bounded by a 30-second timeout, so a
dead channel delays the others by at most that. A channel failure does not
stop the others; it is recorded in the log after the alert:

```
2026-09-24T10:00:00-04:00 ERROR alerter: pushover delivery failed [config]: Config file invalid
    pushover: status 400: {"token":"invalid","errors":["application token is invalid"],"status":0}
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
  it. `Stats()` returns sent, dropped, suppressed and failed counts; an alert
  is sent when the log and every channel took it, failed when any did not.
- **Close** delivers what is queued, within the context given, then closes
  the log. Allow for the channel timeouts when choosing the context.

## Development

`make test` is the gate: format check, `go vet`, `go test -race` with a 90%
coverage floor, and a summary. `make` runs it and then builds. The suite runs
with an empty `HOME` and no `ALERTER_*` variables, against fake services, so
it never sends a real alert.

`make test-live` sends one real alert through every channel configured in
`~/.alerter` (variables in the environment override the file) and fails
unless each accepted it.
