-- name: CreateSSOSession :one
INSERT INTO sso_sessions (
    user_id, token_hash, auth_time, amr, ip_address, user_agent, device_name,
    last_seen_at, idle_expires_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $3, $8, $9)
RETURNING *;

-- name: GetSSOSessionByHash :one
SELECT * FROM sso_sessions
WHERE token_hash = $1
  AND revoked_at IS NULL
  AND expires_at > NOW()
  AND idle_expires_at > NOW();

-- name: TouchSSOSession :one
UPDATE sso_sessions
SET last_seen_at = NOW(),
    idle_expires_at = LEAST($2, expires_at)
WHERE id = $1
  AND revoked_at IS NULL
  AND expires_at > NOW()
  AND idle_expires_at > NOW()
RETURNING *;

-- name: RevokeSSOSession :exec
UPDATE sso_sessions
SET revoked_at = NOW(),
    revoked_reason = $2
WHERE id = $1
  AND revoked_at IS NULL;

-- name: RevokeAllUserSSOSessions :exec
UPDATE sso_sessions
SET revoked_at = NOW(),
    revoked_reason = $2
WHERE user_id = $1
  AND revoked_at IS NULL;

-- name: ListActiveSSOSessions :many
SELECT * FROM sso_sessions
WHERE user_id = $1
  AND revoked_at IS NULL
  AND expires_at > NOW()
  AND idle_expires_at > NOW()
ORDER BY last_seen_at DESC;
