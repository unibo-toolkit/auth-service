-- name: GetActiveConsent :one
SELECT * FROM oauth_consents
WHERE user_id = $1
  AND client_id = $2
  AND revoked_at IS NULL;

-- name: UpsertConsent :one
INSERT INTO oauth_consents (user_id, client_id, scopes)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, client_id) DO UPDATE
SET scopes = EXCLUDED.scopes,
    granted_at = NOW(),
    revoked_at = NULL
RETURNING *;

-- name: RevokeConsent :exec
UPDATE oauth_consents
SET revoked_at = NOW()
WHERE user_id = $1
  AND client_id = $2
  AND revoked_at IS NULL;
