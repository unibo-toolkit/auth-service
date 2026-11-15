# internal/http/auth

```
server.go    routing, requireAuth, profile and session handlers
service.go   holds the storage dependency
```

## Routes

| Method           | Path                                   | Guard         |
|------------------|----------------------------------------|---------------|
| GET              | `/health`                              | public        |
| GET              | `/.well-known/jwks.json`               | public        |
| GET/PATCH/DELETE | `/api/v1/users/me/`                    | `requireAuth` |
| GET              | `/api/v1/users/me/sessions`            | `requireAuth` |
| DELETE           | `/api/v1/users/me/sessions/:sessionID` | `requireAuth` |
| GET              | `/api/v1/users/me/login-history`       | `requireAuth` |

Both public paths sit at the root because the service is the OIDC issuer:
`iss` is `https://auth.uniplanner.it`, and discovery has to resolve against it.

## Authorization

`requireAuth` validates the `Authorization: Bearer` access token through
`jwt.Verifier` in every environment — signature by `kid`, issuer, expiry, `typ`
and the API audience — and publishes `user_id` and `roles` into the gin context.

This service holds the signing keys, so it never trusts identity headers from
the gateway. Other services may trust `X-User-Id` and friends, but only behind
an `AuthorizationPolicy` that keeps their pods unreachable around the gateway.
