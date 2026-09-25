# alerter

Outbound alerts for Go services. An application builds one alerter at
startup, hands it to the packages that need it, and calls `Send` from any
goroutine. Delivery happens on a worker goroutine, so callers never wait on
I/O; a full queue drops the alert rather than blocking.

Every alert is written to a log and delivered to each channel configured in
the environment: Pushover, SMS (Telnyx), mail (SMTP) and a JSON webhook. The application
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

al.Priority("Provider authentication failed", "claude-cli returned 401",
    "run `claude login` on the host")
al.Emergency("Session store not writable", "disk full on /var")
al.Send(alerter.Alert{
    Priority:    alerter.Normal,
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
2026-09-24T10:00:00-04:00 PRIORITY  ClawEh@empire [claude-cli] Provider authentication failed: claude-cli returned 401
    run `claude login` on the host
```

The level is written as `NORMAL`, `PRIORITY` or `EMERGENCY`.

**Channels**, each one on when any of its variables is set. A channel that is
on but incomplete or malformed (a missing variable, a bad port, a number not
in E.164 form, an unparsable address) makes `New` fail, so a typo shows at
startup rather than at the first alert. Lists are comma separated.

| Channel | Variables | Notes |
|---|---|---|
| Pushover | `ALERTER_PUSHOVER_TOKEN` (application token), `ALERTER_PUSHOVER_DEST` (user or group keys); optional `ALERTER_PUSHOVER_NORMAL`, `ALERTER_PUSHOVER_PRIORITY`, `ALERTER_PUSHOVER_EMERGENCY` | The Pushover priority (-2 to 2) each alert level is sent at; defaults 0, 1 (bypasses quiet hours) and 2 (bypasses quiet hours and repeats every 60 seconds until acknowledged, for up to an hour). Set all three to 0 never to be woken. |
| SMS (Telnyx) | `ALERTER_TELNYX_API_KEY`, `ALERTER_SMS_FROM`, `ALERTER_SMS_TO` (E.164, e.g. `+15551234567`) | Title and description, then the priority line; up to 300 characters. |
| Mail (SMTP) | `ALERTER_SMTP_HOST`, `ALERTER_SMTP_FROM`, `ALERTER_SMTP_TO`; optional `ALERTER_SMTP_PORT` (default 587), `ALERTER_SMTP_USER` with `ALERTER_SMTP_PASSWORD` | Port 465 is implicit TLS; any other port must offer STARTTLS, so neither the alert nor the credentials cross the network in clear. A loopback host (a local relay) may run without TLS. |
| Webhook | `ALERTER_WEBHOOK_URL` (http or https); optional `ALERTER_WEBHOOK_HEADERS`, a JSON object of extra headers, e.g. `{"Authorization":"Bearer x"}` | One JSON `POST` per alert (below); any 2xx is success. Redirects are not followed. |

The webhook body, built by `webhookPayload` in `webhook_payload.go` (the one
place to change its shape):

```json
{"priority":1,"priority_name":"priority","title":"Provider authentication failed",
 "description":"claude-cli returned 401","details":"run `claude login` on the host",
 "event_id":"claude-cli","app":"ClawEh","instance":"empire",
 "time":"2026-09-24T10:00:00-04:00","repeats":0,
 "subject":"Provider authentication failed (ClawEh@empire)"}
```

`priority` is the level, 0 to 2, and `priority_name` is `normal`, `priority`
or `emergency`. `details`, `event_id`, `app` and `instance` are omitted when
empty.

Messages lead with what happened. The subject (the mail subject, the
Pushover title) is the title and source, `Provider authentication failed
(ClawEh@empire)`; the text starts with the description, followed by
`Priority alert from ClawEh@empire` or `Normal alert from ClawEh@empire`,
the event id, time, repeat count and details.

Every channel receives every alert that passes repeat suppression. The
channels are sent to in parallel, each bounded by a 30-second timeout, so a
dead channel delays the others by at most that. A channel failure does not
stop the others; it is recorded in the log after the alert:

```
2026-09-24T10:00:00-04:00 ERROR alerter: pushover delivery failed [config]: Config file invalid
    pushover: status 400: {"token":"invalid","errors":["application token is invalid"],"status":0}
```

## Behaviour

- **Priority**: `Alert.Priority` is `alerter.Normal` (0, degraded but
  working), `alerter.Priority` (1, stops the application doing part of its
  job) or `alerter.Emergency` (2, needs a person now); any other value is
  treated as Normal. `Normal()`, `Priority()` and `Emergency()` are
  shorthands for `Send`. How each level is delivered is the operator's
  choice (see `ALERTER_PUSHOVER_*`).
- **Repeat suppression**: an alert with the same level and title (and the
  same `EventID`, when set) as one delivered inside the suppress window is
  held back and counted, so an escalation to a higher level always gets
  through; the next delivery after the window says how many were
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

`go run ./cmd/alert` sends three test alerts, one at each level, through
whatever `~/.alerter` and the environment configure, prints the counts, and
exits non-zero unless all three were delivered. With the default Pushover
priorities the Emergency test alert repeats every minute until acknowledged;
set `ALERTER_PUSHOVER_EMERGENCY=0` (or all three) to test quietly. When
`ALERTER_WEBHOOK_URL` points at a loopback address (e.g.
`http://127.0.0.1:9876/alert`), it listens there itself, prints each request
it receives, and also requires all three to arrive; `make test-live` does the
same.

`make test-live` sends one real alert through every channel configured in
`~/.alerter` (variables in the environment override the file) and fails
unless each accepted it.
