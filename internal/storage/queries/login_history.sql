-- name: CreateLoginHistory :one
INSERT INTO login_history (
    user_id, oauth_provider, ip_address, user_agent, success, failure_reason
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetLoginHistory :many
SELECT * FROM login_history
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT 50;
