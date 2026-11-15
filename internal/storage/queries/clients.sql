-- name: GetClientByClientID :one
SELECT * FROM oauth_clients
WHERE client_id = $1;

-- name: ListClients :many
SELECT * FROM oauth_clients
ORDER BY created_at, client_id;

-- name: CreateClient :one
INSERT INTO oauth_clients (
    client_id, secret_hash, name, logo_url, is_public, is_first_party,
    redirect_uris, post_logout_redirect_uris, grant_types, scopes, audiences,
    roles_claim, access_ttl, refresh_ttl, max_age, owner_id, disabled_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16, $17
)
RETURNING *;

-- name: UpdateClient :one
UPDATE oauth_clients
SET name = $2,
    logo_url = $3,
    is_public = $4,
    is_first_party = $5,
    redirect_uris = $6,
    post_logout_redirect_uris = $7,
    grant_types = $8,
    scopes = $9,
    audiences = $10,
    roles_claim = $11,
    access_ttl = $12,
    refresh_ttl = $13,
    max_age = $14,
    owner_id = $15,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetClientSecret :exec
UPDATE oauth_clients
SET secret_hash = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: DisableClient :exec
UPDATE oauth_clients
SET disabled_at = COALESCE(disabled_at, NOW()),
    updated_at = NOW()
WHERE id = $1;
