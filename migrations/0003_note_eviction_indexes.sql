-- Review D-5, E-5: the controller's note (`audit.rs` `conn`, not authenticated) updates the newest
-- few records of (session_id, device_id) of each connection type. On `audit_conn_session(session_id)`
-- the device was checked row by row in the table, so a made-up device's 20,000 records of a session
-- id cost every note for that session id a walk over them in the write lock; on this index each type
-- is an exact range read backwards, stopping after the few it updates. Covers every use of
-- `audit_conn_session`.
drop index audit_conn_session;
create index audit_conn_session_dev on audit_conn(session_id, device_id, conn_type);

-- Review E-6: the authed and close reports (`audit.rs` `OPEN`) look for the newest record of
-- (device_id, conn_id) still open. On `audit_conn_dev(device_id, conn_id)` every closed record of the
-- pair was read in the table, `closed_at` sitting in the overflow pages after the 4 KB `auth`, so
-- 20,000 closed records made up under one conn_id cost every such report ~20 ms in the write lock;
-- this index holds the open records only. `OPEN` was the only use of `audit_conn_dev`.
drop index audit_conn_dev;
create index audit_conn_open on audit_conn(device_id, conn_id) where closed_at is null;

-- Review D-6: the owned arm of the device eviction (`device.rs` `EVICTABLE`) read
-- `device_user_seen(user_id, last_seen_at)` as a range on `user_id`, so it sorted every owned row,
-- reading each one's id in the table and, for the token check, its owner's tokens one by one. On
-- this partial index it reads the owned rows in `last_seen_at` order with the id and owner at hand,
-- stopping at the first evictable ones; the token check is one lookup on `token_user_device`,
-- which covers every use of `token_user`. (`device_user_seen` stays for the unowned arm and the
-- per-owner lookups.)
create index device_owned_seen on device(last_seen_at, user_id, id) where user_id is not null;
drop index token_user;
create index token_user_device on token(user_id, device_id);
