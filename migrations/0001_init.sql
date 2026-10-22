-- Porta 第一期表结构：照 PORTA.md §4.2 原样；conn_attempt 照笔记 02 §4.4 原样。

-- hbbs 原表，原样保留（见笔记 02 §2.4）
create table if not exists peer ( guid blob primary key not null, id varchar(100) not null, uuid blob not null,
  pk blob not null, created_at datetime not null default(current_timestamp), user blob, status tinyint,
  note varchar(300), info text not null ) without rowid;
create unique index if not exists index_peer_id on peer (id);
create index if not exists index_peer_user on peer (user);
create index if not exists index_peer_created_at on peer (created_at);
create index if not exists index_peer_status on peer (status);

create table user (
  id            integer primary key,
  name          text not null unique,          -- 登录名，区分大小写；一律按字符串绑定和读取（组面板要求字符串，笔记 03 §7）
  display_name  text not null default '',
  email         text not null default '',
  note          text not null default '',
  password_hash text not null default '',      -- '' = 不能用密码登录；'$argon2id$…'；导入的 '$2a$…'（bcrypt）或 'md5:<hex>'
  is_admin      integer not null default 0,
  status        integer not null default 1,    -- 1 正常，0 禁用
  created_at    integer not null,
  updated_at    integer not null
);

create table user_group (
  id            integer primary key,
  name          text not null unique,
  share_devices integer not null default 0,    -- 1：组员在组面板里互相看得到用户和设备（对应 rustdesk-api groups.type=2）
  note          text not null default '',
  created_at    integer not null
);
create table group_member (
  group_id integer not null references user_group(id) on delete cascade,
  user_id  integer not null references user(id) on delete cascade,
  primary key (group_id, user_id)
);

create table token (
  token_hash   text primary key,               -- sha256(令牌) 的 hex
  user_id      integer not null references user(id) on delete cascade,
  device_id    text not null default '',       -- 登录请求里的 id/uuid
  device_uuid  text not null default '',
  created_at   integer not null,
  last_used_at integer not null
);
create index token_user on token(user_id);

create table ab (
  guid       text primary key,                 -- UUIDv4 字符串
  name       text not null,
  owner_id   integer not null references user(id) on delete cascade,
  personal   integer not null,                 -- 1 个人簿（每人一本），0 共享簿
  note       text not null default '',
  created_at integer not null,
  updated_at integer not null
);
create unique index ab_personal on ab(owner_id) where personal = 1;
create unique index ab_shared_name on ab(name) where personal = 0;  -- 客户端拿簿名当主键（笔记 04 §6）

create table ab_rule (                         -- 共享簿授权；簿主人隐含完全控制，不写这张表
  ab_guid  text not null references ab(guid) on delete cascade,
  user_id  integer references user(id) on delete cascade,
  group_id integer references user_group(id) on delete cascade,
  rule     integer not null check (rule in (1, 2, 3)),   -- 1 只读，2 读写，3 完全控制
  check ((user_id is null) <> (group_id is null))
);
create unique index ab_rule_user  on ab_rule(ab_guid, user_id)  where user_id is not null;
create unique index ab_rule_group on ab_rule(ab_guid, group_id) where group_id is not null;

create table ab_peer (
  ab_guid      text not null references ab(guid) on delete cascade,
  id           text not null,
  data         text not null default '{}',     -- 客户端上传的其余字段原样保存（保留原 JSON 类型），不含 id/tags/hash/password
  tags         text not null default '[]',     -- JSON 字符串数组
  hash_enc     text not null default '',       -- 个人簿的密码哈希，加密存（§13）
  password_enc text not null default '',       -- 共享簿的明文密码，加密存
  created_at   integer not null,
  updated_at   integer not null,
  primary key (ab_guid, id)
);

create table ab_tag (
  ab_guid text not null references ab(guid) on delete cascade,
  name    text not null,
  color   integer not null,                    -- ARGB 无符号 32 位，按 i64 存取
  primary key (ab_guid, name)
);

create table device (                          -- 来自 HTTP 上报；和 hbbs 的 peer 表按 id 关联
  id            text primary key,
  uuid          text not null default '',      -- 上报里的 base64 uuid
  user_id       integer references user(id) on delete set null,  -- 最近在这台设备上登录的账号
  hostname      text not null default '',
  username      text not null default '',
  os            text not null default '',
  version       text not null default '',      -- sysinfo 里的客户端版本原样，例如 "1.5.0"
  ver           integer not null default 0,    -- 心跳 ver（数字版本）
  client_type   text not null default 'rustdesk',  -- 'rustdesk' | 'porta'
  sysinfo       text not null default '',      -- 最近一次 sysinfo 原文；'' 表示还没收到
  first_seen_at integer not null,
  last_seen_at  integer not null,
  last_ip       text not null default ''
);
create index device_user on device(user_id);

create table strategy_option (                 -- 心跳下发的选项；scope '*' 为全局，否则为设备 id
  scope text not null,
  key   text not null,
  value text not null,
  primary key (scope, key)
);
insert into strategy_option(scope, key, value) values ('*', 'relay-server', '');  -- 清掉被控端本地写死的中继（总方案 §3.7 前提一）

create table device_policy (                   -- device_id '*' 存全局 epoch
  device_id      text primary key,
  relay_pin      text not null default '',     -- 非空：这台设备作被控端时固定用这个中继
  strategy_epoch integer not null default 0    -- 强制重推时递增
);

create table audit_conn (                      -- 一次入站连接一行（笔记 03 §5.2）
  id         integer primary key,
  device_id  text not null,                    -- 被控端 id
  conn_id    integer not null,                 -- 被控端进程内计数，只在 (device_id, 最近未关闭) 内有意义
  session_id text not null default '',         -- u64 十进制字符串（可能超过 i64）
  peer_id    text not null default '',
  peer_name  text not null default '',
  ip         text not null default '',
  conn_type  integer,
  auth       text not null default '',         -- 认证成功那条上报的其余字段，原样 JSON
  note       text not null default '',         -- 控制端会话结束时写的备注
  created_at integer not null,
  authed_at  integer,
  closed_at  integer
);
create index audit_conn_dev on audit_conn(device_id, conn_id);
create index audit_conn_session on audit_conn(session_id);

create table audit_file (
  id integer primary key, device_id text not null, conn_id integer not null, peer_id text not null default '',
  type integer not null default 0, path text not null default '', is_file integer not null default 0,
  info text not null default '', created_at integer not null
);

create table audit_alarm (
  id integer primary key, device_id text not null, conn_id integer, typ integer not null,
  info text not null default '', created_at integer not null
);

-- 连接结果记录（PORTA.md §8，笔记 02 §4.4）
create table if not exists conn_attempt (
  id                  integer primary key autoincrement,
  started_at          integer not null,   -- unix ms，第一条 PunchHoleRequest
  a_ip                text not null,      -- try_into_v4(addr).ip()
  a_port              integer not null,   -- A:p1 端口；WS 为 0
  via                 text not null,      -- 'tcp' | 'ws'
  a_user              text,               -- PunchHoleRequest.token 反查的账号；未登录为 NULL
  a_device_id         text,               -- 同上，登录时上报的设备 id（若 API 记了）
  a_version           text,               -- PunchHoleRequest.version
  b_id                text not null,      -- PunchHoleRequest.id
  b_ip                text,               -- try_into_v4(peer.socket_addr).ip()
  conn_type           integer not null,   -- PunchHoleRequest.conn_type
  a_nat_type          integer not null,   -- PunchHoleRequest.nat_type
  a_force_relay       integer not null,
  a_has_v6            integer not null,   -- socket_addr_v6 非空
  a_udp_port          integer not null default 0,
  attempts            integer not null default 1,  -- 合并进来的重复请求数
  signal              text not null,      -- 'punch_hole' | 'fetch_local_addr' | 'fail_offline' | 'fail_id_not_exist' | 'fail_license' | 'relay_only'
  server_forced_relay integer not null,   -- ALWAYS_USE_RELAY 或 mask 异或
  relay_offered       text,               -- hbbs 放进 PunchHole/FetchLocalAddr 的 relay_server
  route_reason        text,               -- 路由模块给的理由（geo/fixed/rr/none）
  reply               text,               -- 'punch_hole_sent' | 'local_addr' | 'relay_response' | NULL
  reply_at            integer,
  b_version           text,
  b_nat_type          integer,            -- PunchHoleSent.nat_type
  b_has_v6            integer,
  b_relay             text,               -- B 回的 relay_server；≠ relay_offered 说明 B 本地写死了中继
  relay_uuid          text,               -- 分支 X 的 uuid，或回落时第一个 RequestRelay.uuid
  relay_req_at        integer,            -- 回落：匹配到的第一个 RequestRelay
  relay_req_count     integer not null default 0,
  relay_resp_at       integer,            -- 回落：B 回的 RelayResponse 转给 A 的时间
  outcome             text,               -- 取值见 PORTA.md §8
  finalized_at        integer
);
create index if not exists idx_ca_started on conn_attempt(started_at);
create index if not exists idx_ca_b on conn_attempt(b_id, started_at);
