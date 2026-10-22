-- Review D-5: the controller's note (`audit.rs` `conn`, not authenticated) updates the newest few
-- records of (session_id, device_id). On `audit_conn_session(session_id)` the device was checked
-- row by row in the table, so a made-up device's 20,000 records of a session id cost every note for
-- that session id a walk over them in the write lock; on this index it is an exact range read
-- backwards, stopping after the few it updates. Covers every use of `audit_conn_session`.
drop index audit_conn_session;
create index audit_conn_session_dev on audit_conn(session_id, device_id);
