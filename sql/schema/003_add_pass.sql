-- +goose Up
ALTER TABLE users
ADD COLUMN hashed_password TEXT NOT NULL DEFAULT 'unset';

--ALTER TABLE users
--ADD COLUMN token TEXT NOT NULL DEFAULT 'unset';

--ALTER TABLE users
--ADD COLUMN refresh_token TEXT NOT NULL DEFAULT 'unset';


-- +goose Down
ALTER TABLE users 
DROP COLUMN hashed_password;

--ALTER TABLE users 
--DROP COLUMN token;

--ALTER TABLE users 
--DROP COLUMN refresh_token;