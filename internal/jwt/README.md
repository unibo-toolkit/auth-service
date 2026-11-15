# internal/jwt

RSA signing-key rotation and strict validation of access tokens.

`JWT_SIGNING_KEYS` contains private PEM keys separated by `;;`. The first key
signs new tokens; every key is published at `/.well-known/jwks.json` and remains
available for verification during a rotation grace period. Public keys are
derived from the private keys. A deterministic `kid` is calculated as the first
16 base64url characters of SHA-256 over the DER public key.

`Signer.Sign` always uses RS256 and adds the current key's `kid`. `Verifier`
accepts RS256 only, selects the verification key by `kid`, and checks issuer,
expiration, not-before time, token type and audience.

Refresh tokens are opaque values rather than JWTs. Their generation and hashing
live in `internal/oidc/opaque`.
