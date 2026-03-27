-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    user_id, token_hash, family_id, parent_id,
    ip_address, user_agent, device_name, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: GetActiveSessionsByUserID :many
SELECT * FROM refresh_tokens
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
ORDER BY created_at DESC
LIMIT 20;

-- name: GetActiveSessionFamilies :many
SELECT DISTINCT ON (family_id)
    id, user_id, family_id, ip_address, user_agent, device_name,
    created_at, used_at, expires_at
FROM refresh_tokens
WHERE user_id = $1
  AND revoked_at IS NULL
  AND expires_at > NOW()
ORDER BY family_id, created_at DESC
LIMIT 20;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), revoked_reason = $2
WHERE id = $1;

-- name: RevokeTokenFamily :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), revoked_reason = 'family_compromised'
WHERE family_id = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserTokens :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), revoked_reason = 'logout_all'
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserTokensForDeletion :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), revoked_reason = 'account_deleted'
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: UpdateTokenUsedAt :exec
UPDATE refresh_tokens
SET used_at = NOW()
WHERE id = $1;
