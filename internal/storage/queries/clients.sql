-- name: GetClientByClientID :one
SELECT *,
       EXTRACT(EPOCH FROM access_ttl)::bigint  AS access_ttl_seconds,
       EXTRACT(EPOCH FROM refresh_ttl)::bigint AS refresh_ttl_seconds,
       COALESCE(EXTRACT(EPOCH FROM max_age), 0)::bigint AS max_age_seconds
FROM oauth_clients
WHERE client_id = $1;

-- name: ListClients :many
SELECT *,
       EXTRACT(EPOCH FROM access_ttl)::bigint  AS access_ttl_seconds,
       EXTRACT(EPOCH FROM refresh_ttl)::bigint AS refresh_ttl_seconds,
       COALESCE(EXTRACT(EPOCH FROM max_age), 0)::bigint AS max_age_seconds
FROM oauth_clients
ORDER BY created_at, client_id;

-- name: CreateClient :one
INSERT INTO oauth_clients (
    client_id, secret_hash, name, logo_url, is_public, is_first_party,
    redirect_uris, post_logout_redirect_uris, grant_types, scopes, audiences,
    roles_claim, access_ttl, refresh_ttl, max_age, owner_id, disabled_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, make_interval(secs => sqlc.arg(access_ttl_seconds)::bigint),
    make_interval(secs => sqlc.arg(refresh_ttl_seconds)::bigint),
    CASE WHEN sqlc.narg(max_age_seconds)::bigint IS NULL THEN NULL
         ELSE make_interval(secs => sqlc.narg(max_age_seconds)::bigint) END,
    sqlc.narg(owner_id), sqlc.narg(disabled_at)
)
RETURNING *,
          EXTRACT(EPOCH FROM access_ttl)::bigint  AS access_ttl_seconds,
          EXTRACT(EPOCH FROM refresh_ttl)::bigint AS refresh_ttl_seconds,
          COALESCE(EXTRACT(EPOCH FROM max_age), 0)::bigint AS max_age_seconds;

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
    access_ttl = make_interval(secs => sqlc.arg(access_ttl_seconds)::bigint),
    refresh_ttl = make_interval(secs => sqlc.arg(refresh_ttl_seconds)::bigint),
    max_age = CASE WHEN sqlc.narg(max_age_seconds)::bigint IS NULL THEN NULL
                   ELSE make_interval(secs => sqlc.narg(max_age_seconds)::bigint) END,
    owner_id = sqlc.narg(owner_id),
    updated_at = NOW()
WHERE id = $1
RETURNING *,
          EXTRACT(EPOCH FROM access_ttl)::bigint  AS access_ttl_seconds,
          EXTRACT(EPOCH FROM refresh_ttl)::bigint AS refresh_ttl_seconds,
          COALESCE(EXTRACT(EPOCH FROM max_age), 0)::bigint AS max_age_seconds;

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
