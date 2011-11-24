ALTER TABLE users ADD COLUMN is_manager int(1) NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX trusted_realm_uq ON trusted (realm, user_id);
ALTER TABLE users ADD COLUMN is_enabled int(1) NOT NULL DEFAULT 0;
UPDATE users SET is_enabled = 1;
