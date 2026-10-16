ALTER TABLE group_members ADD COLUMN accepted_at TIMESTAMPTZ;

UPDATE group_members gm
SET accepted_at = gm.joined_at
FROM groups g
WHERE g.id = gm.group_id
  AND g.status <> 'forming'
  AND gm.accepted_at IS NULL;

ALTER TABLE group_events DROP CONSTRAINT group_events_kind_chk;

ALTER TABLE group_events ADD CONSTRAINT group_events_kind_chk CHECK (
    kind IN ('member_added', 'member_removed', 'member_confirmed')
);
