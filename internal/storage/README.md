# internal/storage

Database access. Queries are written as SQL and compiled into Go by
[sqlc](https://sqlc.dev); no query strings are built in Go code.

```
queries/*.sql   hand-written source of truth
db/*.go         generated output - never edited by hand
storage.go      pgx pool, lifecycle, and the few operations that need a transaction
sqlc.yaml       generator config
```

`Storage` embeds `*db.Queries`, so every generated method is available directly
on it (`st.GetUserByID(ctx, id)`), and hand-written methods sit next to them.

## Rules

- Never edit anything under `db/`.
- Never write SQL outside `queries/` — no ad-hoc `pool.Query` in handlers or
  services.
- `sqlc.yaml` reads the schema from the migrations repository, so the generator
  fails if that repository is missing or out of date. `make setup` clones it.
- Multi-statement operations that must be atomic get a method on `Storage` using
  `pool.Begin` + `Queries.WithTx(tx)` + `defer tx.Rollback(ctx)`, like
  `DeleteAccount`. Single statements stay pure sqlc.
- Type mapping is configured in `sqlc.yaml`: `uuid` becomes `uuid.UUID`, `inet`
  becomes `*netip.Addr`. Nullable columns arrive as `pgtype.*` wrappers — convert
  them at the HTTP boundary rather than leaking `{"String":...,"Valid":true}`
  into API responses.
- `New` panics when the database is unreachable: the service is useless without
  it, so it fails at startup rather than per request.

## Notes on the current schema

- `users` deletion cascades to `oauth_providers`, `refresh_tokens`, `user_roles`
  and `login_history`; `calendar_links.owner_id` is set to NULL instead, so
  shared calendars survive an account deletion.
- `refresh_tokens.parent_id` points at the token a rotation replaced, which makes
  a family a linked chain; `family_id` is the same for the whole chain.
- There is no cleanup of expired tokens yet, so the table only grows.
