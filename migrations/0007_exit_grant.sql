-- Phase 4 (application exit): besides its owner, who sees a device in their exit directory.
-- One user or one group per row. device_id has no foreign key: device rows are evicted
-- (LEAPGATE.md §9.3) and a grant must not go with them, nor fail before the device reports.
create table exit_grant (
  device_id text not null,
  user_id   integer references user(id) on delete cascade,
  group_id  integer references user_group(id) on delete cascade,
  check ((user_id is null) <> (group_id is null))
);
create unique index exit_grant_user  on exit_grant(device_id, user_id)  where user_id is not null;
create unique index exit_grant_group on exit_grant(device_id, group_id) where group_id is not null;
