# internal/oauth

Provider-agnostic OAuth layer. It turns an authorization code into a `UserInfo`
and knows nothing about users, tokens or the database — that belongs to
`internal/http/auth`.

```
Manager (registry, keyed by route name)
  └── Provider (interface)
        ├── GoogleProvider   code -> oauth2 token -> userinfo endpoint
        └── AppleProvider    code -> oauth2 token -> id_token claims
```

## The pattern

Every provider follows the same shape, and new ones are expected to keep it:

1. A struct holding one `*oauth2.Config` plus whatever the provider needs for
   authentication (Apple keeps the `.p8` signing key).
2. `GetAuthURL(state)` — no provider ever generates or validates the state; the
   HTTP layer owns it.
3. `ExchangeCode(code, additionalData)` — maps the provider's response onto
   `UserInfo`, and only onto `UserInfo`. Provider-specific fields either fit that
   struct or are dropped.
4. Failures are wrapped around the package sentinels `ErrCodeExchange` and
   `ErrUserInfo` so callers can classify them without knowing the provider.
5. The constructor is called once at startup from `NewHttpService`, guarded by a
   check that the provider is configured; a missing client id leaves the provider
   unregistered and `/auth/{name}` answers 400.

`UserInfo.ID` is the provider's stable subject (Google `id`, Apple `sub`). It is
what `oauth_providers.provider_id` stores and the only value safe to identify a
returning user with — emails change and Apple's private relay addresses differ
per app.

## Adding a provider

1. Add `` with the struct, constructor and the two
   interface methods.
2. Add its credentials to `OAuthConfig` in `internal/config`, to `.env.example`,
   and register it in `NewHttpService` behind an "is it configured" check.
3. Nothing else changes: routing (`/api/v1/auth/:provider`), state handling, user
   provisioning and token issuing are already provider-agnostic.

## Rules

- One instance serves every request. Providers must be safe for concurrent use —
  never store per-request data on the struct or mutate the shared `oauth2.Config`
  inside `ExchangeCode`.
- `RegisterProvider` is startup-only: the registry map is read without a lock.
- Keep secrets out of logs and out of `UserInfo`.

## Apple specifics

- The client secret is not static: it is an ES256 JWT signed with the `.p8` key,
  issued per exchange and valid for up to 180 days.
- The user's name arrives once — in the `user` form field of the first callback,
  passed through as `additionalData`. It is not in the `id_token` and never comes
  again, so it has to be persisted on first login.
- The `id_token` is currently parsed without verifying Apple's signature.
