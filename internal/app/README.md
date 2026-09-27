# internal/app

Application lifecycle. `App` is a thin aggregate over the service's transports.

```
app.go        App: builds the sub-applications, shuts them down together
http/app.go   the HTTP transport: owns the server, Run + Shutdown
```

`Run` is non-blocking: it starts the listener in a goroutine and returns, so
`main` is free to block on the signal channel. Shutdown is budgeted — ten seconds
for the whole app, five for draining the HTTP server.

## The pattern for a new transport

A sub-application (gRPC, a background worker, a metrics server) provides:

- a constructor taking the shared `*slog.Logger` and `*storage.Storage`,
- `Run(...)` that starts and returns immediately,
- `Shutdown(ctx) error` that stops it within the caller's deadline.

Add it as a field on `App`, build it in `app.New`, stop it in `App.Shutdown`.
Nothing in `cmd/main` needs to change beyond starting it.
