-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    $1,
    $2
)
RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: WriteChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    $1,
    $2
)
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps
ORDER BY created_at;

-- name: Get1Chirp :one
SELECT * FROM chirps
WHERE id = $1
ORDER BY created_at;

-- name: GetUser :one
SELECT * FROM users
WHERE email = $1;

-- name: StoreRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expired_at)
VALUES (
    $1,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    $2,
    CURRENT_TIMESTAMP + INTERVAL '60 days'
)
RETURNING *;

-- name: ReadRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE token = $1
RETURNING *;


