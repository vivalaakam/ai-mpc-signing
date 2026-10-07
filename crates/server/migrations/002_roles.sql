ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'signer';

ALTER TABLE users ADD CONSTRAINT users_role_chk CHECK (role IN ('signer', 'admin'));
