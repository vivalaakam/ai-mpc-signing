ALTER TABLE groups DROP CONSTRAINT groups_status_chk
;

ALTER TABLE groups ADD CONSTRAINT groups_status_chk CHECK (status IN ('forming', 'dkg', 'active', 'failed', 'resharing'))
;

ALTER TABLE groups ADD COLUMN share_generation INT NOT NULL DEFAULT 0
;

CREATE TABLE group_events (
    id UUID PRIMARY KEY,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor_username TEXT NOT NULL,
    subject_username TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT group_events_kind_chk CHECK (kind IN ('member_added', 'member_removed'))
)
;

CREATE INDEX group_events_group_idx ON group_events (group_id, created_at)
;

CREATE TABLE reshare_sessions (
    group_id UUID PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
    generation INT NOT NULL,
    phase TEXT NOT NULL,
    threshold INT NOT NULL,
    refresh_package TEXT,
    CONSTRAINT reshare_sessions_phase_chk CHECK (phase IN ('waiting', 'refresh', 'repair')),
    CONSTRAINT reshare_sessions_generation_chk CHECK (generation > 0)
)
;

CREATE TABLE reshare_roster (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id),
    UNIQUE (group_id, identifier),
    CONSTRAINT reshare_roster_role_chk CHECK (role IN ('stayer', 'joiner')),
    CONSTRAINT reshare_roster_identifier_chk CHECK (identifier > 0)
)
;

CREATE TABLE reshare_round1 (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    package TEXT NOT NULL,
    PRIMARY KEY (group_id, identifier)
)
;

CREATE TABLE reshare_round2 (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    from_identifier INT NOT NULL,
    to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (group_id, from_identifier, to_user_id)
)
;

CREATE TABLE reshare_refresh_public (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    package TEXT NOT NULL,
    PRIMARY KEY (group_id, identifier)
)
;

CREATE TABLE reshare_deltas (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    joiner_identifier INT NOT NULL,
    from_identifier INT NOT NULL,
    to_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    PRIMARY KEY (group_id, joiner_identifier, from_identifier, to_user_id)
)
;

CREATE TABLE reshare_sigmas (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    joiner_identifier INT NOT NULL,
    from_identifier INT NOT NULL,
    ciphertext TEXT NOT NULL,
    commitment TEXT NOT NULL,
    PRIMARY KEY (group_id, joiner_identifier, from_identifier)
)
;

CREATE TABLE reshare_verifyings (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    joiner_identifier INT NOT NULL,
    verifying_share TEXT NOT NULL,
    PRIMARY KEY (group_id, joiner_identifier)
)
;

CREATE TABLE reshare_final_public (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    identifier INT NOT NULL,
    package TEXT NOT NULL,
    PRIMARY KEY (group_id, identifier)
)
;
