CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    box_public TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE groups (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    threshold INT NOT NULL,
    max_signers INT NOT NULL,
    status TEXT NOT NULL,
    api_token TEXT NOT NULL UNIQUE,
    verifying_key_hex TEXT,
    public_key_package TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT groups_threshold_chk CHECK (threshold >= 2 AND threshold <= max_signers),
    CONSTRAINT groups_size_chk CHECK (max_signers <= 16),
    CONSTRAINT groups_status_chk CHECK (status IN ('forming', 'dkg', 'active', 'failed'))
);

CREATE TABLE group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    identifier INT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id),
    UNIQUE (group_id, identifier),
    CONSTRAINT group_members_identifier_chk CHECK (identifier > 0)
);

CREATE INDEX group_members_user_idx ON group_members (user_id);

CREATE TABLE signing_requests (
    id UUID PRIMARY KEY,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    message BYTEA NOT NULL,
    status TEXT NOT NULL,
    signature_hex TEXT,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT signing_requests_status_chk CHECK (status IN ('pending', 'signing', 'completed', 'failed'))
);

CREATE INDEX signing_requests_group_idx ON signing_requests (group_id, created_at DESC);

CREATE TABLE signing_approvals (
    request_id UUID NOT NULL REFERENCES signing_requests(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    decision TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, user_id),
    CONSTRAINT signing_approvals_decision_chk CHECK (decision IN ('approved', 'rejected'))
);

CREATE TABLE sign_participants (
    request_id UUID NOT NULL REFERENCES signing_requests(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    identifier INT NOT NULL,
    PRIMARY KEY (request_id, user_id)
);

CREATE TABLE dkg_round1 (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    package TEXT NOT NULL,
    PRIMARY KEY (group_id, identifier)
);

CREATE TABLE dkg_round2 (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    from_identifier INT NOT NULL,
    to_user_id UUID NOT NULL REFERENCES users(id),
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (group_id, from_identifier, to_user_id)
);

CREATE TABLE dkg_publics (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    package TEXT NOT NULL,
    PRIMARY KEY (group_id, identifier)
);

CREATE TABLE sign_commitments (
    request_id UUID NOT NULL REFERENCES signing_requests(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    commitment TEXT NOT NULL,
    PRIMARY KEY (request_id, identifier)
);

CREATE TABLE sign_shares (
    request_id UUID NOT NULL REFERENCES signing_requests(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    share TEXT NOT NULL,
    PRIMARY KEY (request_id, identifier)
);
