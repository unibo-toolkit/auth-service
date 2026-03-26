-- name: CreateOAuthProvider :one
INSERT INTO oauth_providers (user_id, provider, provider_id, email)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetOAuthProvider :one
SELECT * FROM oauth_providers
WHERE provider = $1 AND provider_id = $2;
