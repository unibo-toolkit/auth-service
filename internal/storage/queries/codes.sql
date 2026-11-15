-- name: CreateAuthorizationCode :one
INSERT INTO oauth_authorization_codes (
    code_hash, client_id, user_id, session_id, redirect_uri, scopes, nonce,
    code_challenge, code_challenge_method, auth_time, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: ConsumeAuthorizationCode :one
UPDATE oauth_authorization_codes
SET consumed_at = NOW()
WHERE code_hash = $1
  AND consumed_at IS NULL
  AND expires_at > NOW()
RETURNING *;

-- name: GetAuthorizationCodeByHash :one
SELECT * FROM oauth_authorization_codes
WHERE code_hash = $1;
