-- Phase 3, device signing: when the key of a peer was pinned (unix seconds), NULL while not pinned.
-- The first signed report of a device pins the `pk` it was signed with; a registration with another
-- key is then refused (`Database::update_pk`). On `peer`, not `device`: device rows get evicted.
alter table peer add column pk_pinned_at integer;
