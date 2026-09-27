# internal/http/auth

The HTTP layer and the auth business logic.

```
server.go    routing, handlers, requireAuth, OAuth state store
service.go   login flow, user provisioning, refresh-token families
errors.go    sentinel errors shared by the two
```

## Layering

`Server` deals with HTTP only: bind and validate the request, call `Service`,
translate the returned error into a status code, render JSON. `Service` never
touches `*gin.Context` and never picks status codes; it returns domain errors
from `errors.go`.

## Routes

Everything lives under `/api/v1`.

| Group   | Path                   | Guard                                          |
|---------|------------------------|------------------------------------------------|
| `auth`  | `/api/v1/auth/...`     | public — Istio lets it through unauthenticated |
| `users` | `/api/v1/users/me/...` | `requireAuth`                                  |

The provider is a path parameter (`/auth/:provider`), so adding an OAuth provider
adds no routes. Apple needs the `POST` variant of the callback because it uses
`response_mode=form_post`.

Note that the `users` group registers its root handlers as `/`, so
`/api/v1/users/me` answers with a redirect (301 for GET, 307 for PATCH and
DELETE) to `/api/v1/users/me/`.

## Two ways a caller is identified

`requireAuth` behaves differently per environment, and this is the single most
important thing to know about the service:

- **`ENVIRONMENT=prod`** — Istio has already verified the JWT against the JWKS
  endpoint and injected `X-User-Id`, `X-Email` and `X-Roles`. The service trusts
  those headers as-is. This is only safe while the pod is unreachable except
  through the gateway; an `AuthorizationPolicy` that enforces it is a hard
  requirement of the deployment.
- **anything else** — the `Authorization: Bearer <access_token>` header is
  validated locally through `jwt.Manager`.

Either way the handler reads `user_id` (`uuid.UUID`), `email` (`string`) and
`roles` (`[]string`) from the gin context. `X-Roles` arrives base64-encoded JSON,
which is what `parseRoles` unwraps.

## Auth flow

```
GET  /auth/:provider           state (32 random bytes, 10 min) -> redirect to consent screen
GET  /auth/:provider/callback  browser redirect back  ┐
POST /auth/:provider/callback  Apple form_post        ├─> Service.HandleOAuthCallback
POST /auth/exchange            native / SPA clients   ┘
```

All three entry points converge on `Service.HandleOAuthCallback`, which exchanges
the code, finds or provisions the user, writes `login_history` and opens a token
family.

The state store is a map in the process. Two consequences: the callback must
reach the same replica, and `/auth/exchange` only checks `state` when the client
sends one.
TODO: review in the future

## Refresh-token families

One family = one device session. Rotation keeps `family_id` and links the new
token to the old one through `parent_id`.

A token that is already used or revoked is treated as stolen: the entire family
is revoked and the caller gets `ErrTokenReused`. That is why `GET
/users/me/sessions` groups by family (`DISTINCT ON (family_id)`) and why
`DELETE /users/me/sessions/{id}` takes a **family id**, not a token id.

## Conventions for new endpoints

- Request bodies are anonymous structs with `binding` tags, bound via
  `c.BindJSON`.
- Errors render as `{"error": "<message>"}`; the message stays generic when it
  would leak internals.
- Status mapping belongs to the handler: check `errors.Is` against the sentinels
  in `errors.go` and add a new sentinel rather than matching on error strings.
- Anything user-specific reads its identity from the gin context, never from the
  request body or a query parameter.
- Log with the injected `*slog.Logger`, with `op` set to the operation name.
