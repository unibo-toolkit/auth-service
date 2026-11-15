-- name: CreateAuthRequest :one
INSERT INTO auth_requests (
    client_id, redirect_uri, scopes, state, nonce, code_challenge,
    code_challenge_method, prompt, max_age, provider_hint, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetAuthRequest :one
SELECT * FROM auth_requests
WHERE id = $1
  AND completed_at IS NULL
  AND expires_at > NOW();

-- name: AttachAuthRequestSession :one
UPDATE auth_requests
SET session_id = $2
WHERE id = $1
  AND completed_at IS NULL
  AND expires_at > NOW()
RETURNING *;

-- name: SetAuthRequestFederationState :one
UPDATE auth_requests
SET federation_state = $2,
    federation_nonce = $3
WHERE id = $1
  AND completed_at IS NULL
  AND expires_at > NOW()
RETURNING *;

-- name: ConsumeAuthRequestFederationState :one
UPDATE auth_requests
SET federation_state = NULL,
    federation_nonce = NULL
WHERE federation_state = $1
  AND completed_at IS NULL
  AND expires_at > NOW()
RETURNING *;

-- name: MarkAuthRequestConsented :one
UPDATE auth_requests
SET consent_granted = TRUE
WHERE id = $1
  AND completed_at IS NULL
  AND expires_at > NOW()
RETURNING *;

-- name: CompleteAuthRequest :one
UPDATE auth_requests
SET completed_at = NOW()
WHERE id = $1
  AND completed_at IS NULL
  AND expires_at > NOW()
RETURNING *;
