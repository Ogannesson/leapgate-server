-- Review C-16: the audit tables' retention purge and the device table's eviction read only these
-- columns, which sit after 4~8 KB text columns (in overflow pages): without an index every purge
-- walked the whole tables inside the write lock.
create index audit_conn_created on audit_conn(created_at);
create index audit_file_created on audit_file(created_at);
create index audit_alarm_created on audit_alarm(created_at);

-- The oldest evictable device rows (`device.rs` `make_room`), unowned or per owner, in
-- `last_seen_at` order. Covers every use of `device_user(user_id)`, which it replaces; a partial
-- index `where user_id is null` is not chosen by the planner (measured in the review).
drop index device_user;
create index device_user_seen on device(user_id, last_seen_at);
