-- 自研 ICE 的结果（P-A）。控制端在信令连接上补报，不认证，只作统计；
-- 和 conn_attempt 分开，避免把"ICE 胜出"按 IP 硬合并进上游那一行。
create table ice_result (
  id          integer primary key autoincrement,
  at          integer not null,   -- unix ms，S 记录的时刻
  a_ip        text not null,      -- try_into_v4(A 信令连接地址).ip()
  b_id        text not null,      -- OFFER 里的目标 ID
  outcome     text not null,      -- connected|no_answer|bad_answer|no_pair|kcp_failed|secure_failed|abandoned|unknown
  elapsed_ms  integer,            -- RESULT.elapsed_ms；abandoned 为 NULL
  local_kind  text,               -- connected 才有：host|srflx|prflx
  remote_kind text,
  family      integer,            -- 4|6，connected 才有
  local_net   text                -- ethernet|wlan|other，connected 才有
);
create index if not exists idx_ice_at on ice_result(at);
