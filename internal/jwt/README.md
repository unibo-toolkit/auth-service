# internal/jwt

Token issuing and verification. RS256 throughout: the service is the only holder
of the private key, everyone else verifies with the public key served as JWKS.

```
manager.go   Manager: generate / validate access and refresh tokens, hash refresh tokens
keys.go      PEM parsing and the JWKS document
```

## Token model

|             | Access                                                | Refresh                                                 |
|-------------|-------------------------------------------------------|---------------------------------------------------------|
| TTL         | `ACCESS_TOKEN_TTL` (900s)                             | `REFRESH_TOKEN_TTL` (2592000s)                          |
| Claims      | `uid`, `email`, `roles` + iss/sub/aud/exp/iat/nbf/jti | `uid`, `fid` + iss/sub/exp/iat/jti                      |
| Audience    | `JWT_AUDIENCE`                                        | none                                                    |
| Stored      | nowhere                                               | `refresh_tokens.token_hash` = base64url(SHA-256(token)) |
| Verified by | Istio (prod) or `ValidateAccessToken` (dev)           | `ValidateRefreshToken` + a database lookup              |

`fid` is the token family: every rotation keeps it, so detecting one replayed
token is enough to revoke the whole device session. The family lifecycle lives in
`internal/http/auth`, not here.

Both tokens carry the `kid` header from `JWT_KID`, matching the single key in the
JWKS document.

## Keys

- `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` hold PEM blocks as environment
  variables; literal `\n` sequences are accepted, so a key fits on one `.env`
  line.
- `MustNewJwtManager` panics unless both parse **and** the public key matches the
  private one — a mismatch would mean Istio silently rejecting every token.
- `make setup` generates a development pair into `keys/` (gitignored).

## Rules

- Everything that signs or verifies a token goes through `Manager`. No other
  package touches the RSA keys.
- Raw refresh tokens never reach the database or the logs; store
  `HashRefreshToken(token)` instead.
- `JWT_ISSUER`, `JWT_AUDIENCE` and `JWT_KID` must stay in sync with the Istio
  `RequestAuthentication` in the `infra` repository. Changing any of them without
  changing the mesh config breaks authentication for every client.

## Current limits

- `validateToken` checks the signature and the time claims only. Issuer, audience
  and token kind are not enforced, so a refresh token also passes
  `ValidateAccessToken`. Istio rejects it in prod because of the missing
  audience, but the local `Bearer` path accepts it.
- JWKS serves exactly one key, so key rotation has no grace period: publishing
  the old and the new key together is a prerequisite for rotating `JWT_KID`.
