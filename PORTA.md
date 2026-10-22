# porta-server：Porta 的服务端（第一期实施契约）

本仓库是 `rustdesk/rustdesk-server@873230e` 的**硬分叉**（不再合并上游，安全修复手工摘取），作为子模块挂在总仓库 `Porta` 的 `server/` 下。总体方案见总仓库 `docs/architecture.md`，本文件是第一期（服务端）写代码时要遵守的契约：范围、模块边界、表结构、配置、各模块的行为规则。上游的 `AGENTS.md` 规则（不引入 `unwrap()`/`expect()`、不做纯格式化改动）照样适用。

字段级细节不在这里重复，写代码前读总仓库 `docs/research/第一期服务端/` 下对应的笔记（下文简称"笔记 01~06"）：
- 01 心跳与策略下发；02 hbbs 内部结构与挂钩点；03 账号、组面板、设备上报、审计接口；04 地址簿接口；05 rustdesk-api 表结构与迁移；06 GeoIP 落地。
- 笔记里的行号对应 `rustdesk-server@873230e` 原版；本仓库的代码已经和原版有差异，按函数名定位。
- 笔记和本文件冲突时以本文件为准；笔记里的【推测】，实现时要读码或实测确认。

## 1. 第一期范围

做：
1. **兼容原版 RustDesk 客户端**（1.4.x~1.5.x）：会合协议和 HTTP API 照旧，新能力只做加法。
2. **TCP 密钥交换（KeyExchange）**：原版 hbbs 没有，登录过 API、配了 key 的客户端连原版 hbbs 每次都在 18 秒后报 "Failed to secure tcp"。必须做（笔记 02 §6.2）。
3. **IPv6 打洞信令转发**：原版 hbbs 丢掉 `socket_addr_v6`，要补（笔记 02 §6.5）。注意：IPv6 打洞的开关是控制端本地的 LocalConfig 选项，心跳策略改不到（笔记 01 §4），原版客户端要在控制端手动勾选"Enable IPv6 P2P connection"；服务端只负责转发。
4. **路由第一级**：按双方公网 IP 的地理位置和运营商估算延迟选中继，中继有权重，可按设备固定中继（§7）。
5. **连接结果记录**：每次连接最终是直连、中继还是失败，用来统计中继回落率（§8）。
6. **原生 HTTP API**（替代 rustdesk-api）：账号、组面板、新版地址簿（个人簿 + 共享簿 + 用户组授权）、sysinfo、心跳策略下发、审计（§9~§12）。
7. **记录每台设备的客户端类型和版本**，为以后退出兼容做准备。
8. **命令行管理**和**从 rustdesk-api 一次性导入**（§14、§15）。

不做（第一期）：OIDC 和第三方登录、邮箱验证码和 TOTP、Web 管理后台、路由第二级（客户端测速）、强制设备签名、TCP 注册（走代理/WebSocket/禁 UDP 的被控端原版就显示离线，维持现状）、修改 ID（`RegisterPk.old_id`）、`HttpProxyRequest`（API 经 21116 回落）、WebRTC 信令转发、转发 `udp_port`（UDP 打洞）、心跳下发 `disconnect`、`audit/conn/active`、`PUT /api/audit`、旧版地址簿 `GET/POST /api/ab`，以及总方案第 4 节列的全部"明确不做"。hbbr（`src/relay_server.rs`）不改逻辑。

## 2. 代码布局与文件归属

平铺在 `src/` 下，和上游文件并列。第一期并行开发时，每个模块只改自己名下的文件；共享文件只由骨架阶段修改，并行阶段确需改动（例如加依赖）时单独提交、在汇报里说明。

| 文件 | 内容 | 归属 |
|---|---|---|
| `Cargo.toml`、`Cargo.lock`、`src/lib.rs`、`src/main.rs` | 依赖、模块声明、入口（服务模式 / 命令行模式分派） | 骨架 |
| `migrations/0001_init.sql` | 全部表（§4） | 骨架 |
| `src/state.rs` | `AppState`：进程内共享的句柄（§3） | 骨架 |
| `src/config.rs` | `porta.toml` 解析（§5） | 骨架 |
| `src/database.rs` | 连接池、迁移、hbbs 原有的 peer 查询 | 骨架 |
| `src/auth.rs` | 密码哈希/校验、令牌生成/哈希/反查 | 骨架 |
| `src/crypto.rs` | 密码字段加密（§13） | 骨架 |
| `src/api/mod.rs` | axum 路由表、通用响应和请求体解析、Bearer 认证提取器、静态说明页 | 骨架 |
| `src/rendezvous_server.rs`、`src/kx.rs`、`src/peer.rs`、`src/common.rs` | 会合逻辑和挂钩（§6） | 会合 |
| `src/router/` | 路由第一级、健康检查、GeoIP 加载与更新（§7） | 路由 |
| `src/conn_tracker.rs` | 连接结果记录与统计（§8） | 结果记录 |
| `src/api/account.rs`、`src/api/group.rs` | 账号接口、组面板（§9.2、§11、§12.3） | 账号 |
| `src/api/ab.rs` | 地址簿 12 个接口（§12） | 地址簿 |
| `src/api/device.rs`、`src/api/audit.rs`、`src/strategy.rs` | sysinfo、心跳、策略、审计（§9.3、§10） | 设备 |
| `src/cli/`、`src/import.rs` | 命令行与导入（§14、§15） | 命令行 |

骨架阶段为后面各模块建好空文件和函数签名（`todo!()` 不允许留到合并后），并行模块在签名内实现。签名需要调整时，改动方在汇报里写清楚，由集成阶段统一。

删掉：`src/mod.rs`（孤儿文件）、`database::tests::test_insert`（出错不报、等于空跑，`peer_roundtrip` 已覆盖）、`common::check_software_update`（向 RustDesk 官方外呼）。

## 3. 进程结构与共享状态

- 入口 `main.rs`：第一个参数是已知子命令（§14）时进入命令行模式，否则照原样解析 hbbs 参数、启动服务。
- `RendezvousServer::start_with_bind` 自己建 tokio 运行时；API（axum）、路由健康检查、GeoIP 更新、结果记录的落库任务都在这个运行时里 `spawn`。
- `AppState`（`Clone`，内部全是 `Arc`/池句柄），同一份交给 `RendezvousServer` 和 axum：
  - `db: SqlitePool`（全进程一个池，§4.1）
  - `pm: PeerMap`（原有，在线状态 = 内存里有且 `last_reg_time` 不到 30 秒，笔记 02 §2.5）
  - `router: Arc<Router>`（替代原来每个 clone 一份的 `relay_servers`/`relay_servers0` 快照，笔记 02 §1.6、§3.5）
  - `tracker: Arc<ConnTracker>`
  - `secret: Arc<SecretBox>`（§13）
  - `cfg: Arc<Config>`
  - `server_pk`、`sk`（`get_server_sk` 的结果，KeyExchange 和签名用）
- 模块自己的小状态（登录失败计数、审计 nonce 去重表）放在模块内的 `static`，不进 `AppState`。
- 所有 IP 在比较、查库、落库前先规范化：`::ffff:a.b.c.d` → IPv4（`to_canonical()` 或 `try_into_v4`）。

## 4. 存储

### 4.1 连接池与迁移
- 一个 `sqlx::SqlitePool`：WAL、`busy_timeout` 5 秒、`foreign_keys` 打开，池大小 `MAX_DATABASE_CONNECTIONS`（默认改为 8）。路径仍是 `DB_URL`，默认 `./db_v2.sqlite3`。
- 迁移用 `sqlx::migrate!("./migrations")`（编译期嵌入文件，不需要数据库），服务和命令行启动时都执行。原来 `create_tables` 里的 `peer` 表 DDL 挪进 `0001`，保留 `if not exists`，这样能直接接管已有的 hbbs 数据库。
- 全部用运行时 `sqlx::query()`，不用编译期宏。
- 迁移文件必须是 LF（校验和按字节算）。已发布的迁移不再修改，第一期合并前可以直接改 `0001`。
- 时间一律存 unix 秒（`integer`），`conn_attempt` 按笔记 02 用毫秒。

### 4.2 表结构（`migrations/0001_init.sql` 照此实现，列名、类型、约束不得自行改动）

```sql
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
```

`conn_attempt` 表照笔记 02 §4.4 的 DDL 原样放进 `0001`。

## 5. 配置

- hbbs 原有参数（`-p`、`-k`、`-r`、`--mask`、`DB_URL`、`.env`、`-c` 指定的 INI…）全部照旧。
- Porta 自己的结构化配置放在 `porta.toml`：路径取参数 `--porta-config`（环境变量同名规则照 `get_arg`），默认工作目录下的 `porta.toml`；文件不存在就全用默认值。改了要重启。
- 中继列表：`porta.toml` 里有 `[[relay]]` 就用它；没有就用 `-r` 的列表（权重 1，无覆盖）。控制台 `rs a,b,c` 仍可在运行时临时替换。

```toml
[api]
listen = "0.0.0.0:21114"          # HTTPS 交给前面的反向代理

[geo]
dir = "geoip"                     # 放 mmdb 的目录（相对工作目录）
source = "dbip"                   # dbip：自动下载 DB-IP Lite；manual：只读目录里已有的文件（MaxMind 走这条）
city_file = ""                    # 留空按 source 的默认文件名
asn_file = ""
auto_update = true
# server_location = { lat = 0.0, lon = 0.0, country = "XX", carrier = "" }  # 私网来源地址按服务端位置算（笔记 06 §5.2）

[routing]
detour = 2.0                      # 绕行系数 k：rtt_ms = 距离km × 2 × k / 200
cross_carrier_ms = 0              # 同国、不同运营商组的惩罚（每段）
cross_border_ms = 0               # 一端在本国、另一端在境外的惩罚（每段）
[routing.country.CN]              # 按国家覆盖；内置默认就带这一组（笔记 06 §4.2）
cross_carrier_ms = 10
cross_border_ms = 30
[routing.carriers]                # 追加 ASN → 运营商组；内置一张中国三大运营商的小表
# 4134 = "cn-telecom"

[[relay]]
host = "relay1.example.com:21117" # 原样发给客户端
weight = 1.0                      # 代价乘数，流量贵的调高
multi_bgp = false                 # 多线 BGP 机房：不算跨运营商
# lat = 0.0; lon = 0.0; country = "XX"; carrier = ""   # 可选，覆盖 IP 库查出的位置
```

## 6. 会合模块（`rendezvous_server.rs` 等）

改动都按"只加挂钩、不重写流程"做，行为和原版保持一致，除非下面明确要求。
1. **KeyExchange v1**：21116/TCP 每条连接 accept 后、有 `sk` 时先发 `KeyExchange`（v1：签名的临时公钥 + `signed_params`），读第一帧：是 `KeyExchange` 且 `keys.len()==2` 就建立加密，之后收发都加解密；第一帧不是 `KeyExchange` 就按明文 `RendezvousMessage` 处理。写半边存进 `tcp_punch` 时要带上加密器（`Sink` 改型）。完整步骤和客户端测试里的服务端替身见笔记 02 §6.2。21118（WebSocket）上客户端会不会同样要求加密，读客户端 `secure_tcp` 的调用点确认；要求的话 WS 也做。
2. **IPv6 信令转发**：按笔记 02 §6.5 的表补 `socket_addr_v6`（以及 `PunchHole` 的 `force_relay`、`PunchHoleResponse` 的 `upnp_port`）。不转发 `udp_port` 和 WebRTC 字段。hbbs 强制中继（`ALWAYS_USE_RELAY` 或 mask 异或）时清空转发的 v6 地址并置 `force_relay`（笔记 02 §6.4）。
3. **路由挂钩**：`handle_punch_hole_request` 里调 `router.select(&RouteQuery{a_ip, b_ip, b_id, a_token, conn_type})`；`RelayResponse` 分支和控制台 `tg` 也改调 router。`io_loop` 的中继定时器分支、`Data::RelayServers` 删掉，健康检查挪进 router（笔记 02 §3.5）。控制台 `rs` 无参数时打印 `router.status_text()`。
4. **结果记录挂钩**：H1~H5 五处调用 `tracker`（笔记 02 §4.4），只取字段、不阻塞（tracker 内部用通道异步落库）。
5. 修掉控制台 `aur` 把中继列表清空的那一行（笔记 02 §3.4）。
6. 删掉 `check_software_update` 及其调用。
7. 不改：注册规则、`UUID_MISMATCH` 逻辑、IP 限流、mask/local_ip、`test_hbbs` 自检。

## 7. 路由第一级（`src/router/`）

- 接口：`Router::select(&RouteQuery) -> RouteDecision { relay: String, reason: &'static str }`。返回单个中继字符串（原版客户端只认一个）；空串语义照旧（被控端退回"hbbs 主机:21117"）。
- 候选：健康检查通过的中继。被控端（`b_id`）在 `device_policy.relay_pin` 有固定中继时直接用它，不看健康状态（运维的明确意图）。
- 代价：`cost(R) = (rtt(A,R) + rtt(B,R)) × weight(R)`，取最小。`rtt` 按笔记 06 §4：大圆距离 × 2 × `detour` / 200 km/ms，加每段的跨运营商组、跨境惩罚；`multi_bgp` 的中继不算跨运营商。缺位置的回退规则按笔记 06 §5.2（一方未知用 `2 × rtt(已知方, R)`；都未知或中继无位置时在健康中继里轮询）。
- 中继位置：配置覆盖优先，否则解析主机名后查库，结果缓存。客户端 IP 的查询结果做小 LRU，换库后清空。
- 健康检查：每 3 秒对每台中继做一次 TCP 建连（3 秒超时），只有一台也要查；记录是否可达和建连耗时；全部失败时保留上一轮结果（和原版一致）。
- GeoIP：`maxminddb`（开 `mmap`）。`source = "dbip"` 且 `auto_update` 时，启动后在后台检查、此后每天检查一次，目录里没有当月文件就下载 `dbip-{city,asn}-lite-YYYY-MM.mmdb.gz`（当月 404 时退回上月），解压到临时文件、用 maxminddb 打开抽查通过后原子替换并热切换。没有库时路由退回轮询，不阻塞启动。下载用已有的 `reqwest` + `flate2`（笔记 06 §3）。
- 每次决策打一行 debug 日志：双方国家/运营商组、候选代价、选中的中继和 `reason`。
- 运营商组：内置中国三大运营商的主要 ASN 表（写代码前到 bgp.he.net 或 PeeringDB 核对），查不到时按"ASN 相等算同组"。不用 AS 名称做字符串匹配。

## 8. 连接结果记录（`src/conn_tracker.rs`）

- 按笔记 02 §4.4 实现：内存跟踪器（键 `try_into_v4(A:p1)`、`(A 公网 IP, B id)`、`try_into_v4(A:p3)`），每 5 秒扫一遍把到期的记录定稿写入 `conn_attempt`，定稿规则照笔记。热路径只做内存操作。
- `a_user`/`a_device_id` 用 `PunchHoleRequest.token` 经 `auth::token_owner` 反查（未登录为 NULL）。
- 提供统计查询给命令行：按时间范围算中继回落率 = (`relay` + `relay_or_v6`) / (`relay*` + `direct*`)，并列出各 `outcome` 的计数，以及 `b_relay ≠ relay_offered` 的次数（被控端本地写死了中继）。

## 9. HTTP API 通则

### 9.1 必须遵守（任何一条写错，原版客户端都会走错分支）
1. **任何接口都不回 5xx**：客户端遇到 5xx 或连不上会改走 hbbs 的 TCP 代理（第一期不做），白等最长 36 秒，心跳也跟着卡住。内部错误：审计接口回 200 + `{"error":"…"}`（客户端会重试），其他接口回 400 + `{"error":"…"}`。
2. 请求体一律用 `Bytes` 收、自己解析 JSON；不用 axum 的 `Json` 提取器（出错回 415/422 纯文本）。响应带 `Content-Type: application/json; charset=utf-8`。
3. 令牌无效、过期、账号禁用 → **401**（客户端据此清登录态）。
4. `/api/login-options` 回 `[]`（没有第三方登录）。
5. 用户信息里 `name` 必须是非空字符串；登录成功必须带 `user`；`info`、`is_admin`、`status` 不能是 null（笔记 03 §2.5）。
6. 列表接口回 `{"total": int, "data": [...]}`，`total` 必须是整数；分页参数 `current`、`pageSize`，不能把每页压到客户端要的条数以下。
7. sysinfo 成功回纯文本 `SYSINFO_UPDATED`（逐字节，不带换行和引号）；**不回 `ID_NOT_FOUND`**（会让客户端每 3 秒重传）。
8. 审计成功回 200 + **空 body**；按 `nonce` 去重 5 分钟（重复的也回空 body）。
9. 地址簿：9 个写接口成功只认 200 + 空 body；读接口按笔记 04 §1.2 的三种解析器回；`/api/ab/personal` 永远回 200 + 非空 `guid`（个人簿不存在就当场建）；`settings`、`shared/profiles` 正常实现（不回 404）。
10. JSON 里不给 null；字符串字段不能给数字（SQLite 读出的纯数字字符串要保持字符串）。
- 详细字段和每个接口的推荐回包：账号/组/设备/审计看笔记 03，地址簿看笔记 04。

### 9.2 账号接口（`account.rs`）
`GET /api/login-options`、`POST /api/login`（只做 `type=account`）、`POST /api/currentUser`、`POST /api/logout`。见 §11。

### 9.3 设备上报（`device.rs`、`audit.rs`）
`POST /api/sysinfo`、`POST /api/heartbeat`、`POST /api/audit/conn`、`POST /api/audit/file`、`POST /api/audit/alarm`。不带认证（兼容债务），做弱校验：hbbs 的 `peer` 表里有这个 id 时，要求 `base64(peer.uuid) == body.uuid`（编码和客户端 `encode64` 一致），不符时 sysinfo 回 403 空 body（客户端 120 秒后重试）、心跳回 `{}`、审计回 200 空 body 但不入库；`peer` 表里没有时照常接受。

### 9.4 其他
- `GET /`：静态说明页（HTML）：服务名 Porta、源代码地址（AGPL-3.0 第 13 条：链接到公开仓库）、"IP Geolocation by DB-IP" 署名并链接 https://db-ip.com 。客户端"在 Web 控制台管理"菜单打开的就是这里。
- 其余未知路径回 404。

## 10. 心跳与策略（`strategy.rs`、`device.rs`）

- 生效选项 = 全局（`scope='*'`）⊕ 设备（`scope=<id>`，同键覆盖）。
- 版本号 `rev`：对（生效选项按键排序的规范 JSON、全局 epoch、设备 epoch）做 sha256，取前 8 字节转 `i64` 后与 `i64::MAX` 按位与，结果为 0 时取 1。任何生效选项变化或 epoch 递增都会换版本；不用自增计数器。
- 下发规则（笔记 01 §2.2）：**仅当 `req.modified_at != rev` 时**，响应同时带 `"modified_at": rev` 和 `"strategy": {"config_options": {…全部生效选项…}}`；否则两者都不带。值一律是字符串，不给 null。这样"设备首次接入或策略变更时清一次 `relay-server`"自然成立，之后用户在本地改了也不会每次被覆盖。
- 设备还没有 sysinfo（`device.sysinfo = ''`）时响应带 `"sysinfo": true`。
- 每次心跳更新 `device.last_seen_at`、`ver`、`last_ip`；设备行不存在就建。
- sysinfo：存原文，拆出 `hostname`、`username`、`os`、`version`；`client_type` 第一期一律 `rustdesk`（Porta 客户端以后在上报里加专门的键来区分，见笔记 01 §6）。

## 11. 账号、令牌、密码（`auth.rs`、`account.rs`）

- 密码：argon2id（`argon2` crate 默认参数）。校验时按前缀识别 `$argon2id$`、`$2a$/$2b$/$2y$`（bcrypt）、`md5:`（rustdesk-api 旧格式 `md5(明文+"rustdesk-api")`，笔记 05 §3）；旧格式校验通过后当场改存 argon2id。`password_hash = ''` 的账号不能密码登录。
- 令牌：32 字节随机数的 base64url（无填充），库里只存 sha256 hex。没有过期时间；登出、改密码、禁用账号时删掉该用户的令牌（登出只删当前这个）。每次使用更新 `last_used_at`。
- 登录时把请求体里的设备 `id`/`uuid` 记进令牌行，并把 `device.user_id` 设成这个用户（设备行不存在就建）；登出时若 `device.user_id` 是本人则清空。
- 登录失败限流：同一用户名或同一来源 IP 15 分钟内失败 5 次后，15 分钟内直接拒绝（回 `{"error": "…"}`）。
- `auth::token_owner(token) -> Option<(user_id, user_name, device_id)>` 给会合模块用。

## 12. 地址簿、权限、用户组（`ab.rs`、`group.rs`）

### 12.1 地址簿
- 个人簿：每个用户一本，`personal=1`，名字固定为客户端认的 `My address book`（客户端按名字认个人簿，笔记 04 §6）。
- 共享簿：命令行创建；名字全局唯一，且不能叫 `My address book`。`shared/profiles` 列出当前用户能看到的共享簿（主人或有规则），`owner` 填主人的用户名，`rule` 填该用户的有效权限，`info` 回 `{}`。个人簿不出现在 profiles 里。
- 有效权限 = 主人为 3；否则取"直接授给本人的规则"和"授给本人所在任一组的规则"中的最大值；都没有就是无权访问（读写一律 403 + `{"error"}`）。
- 权限语义（维护者 2026-10-22 定）：1 只读；2 读写，可以增删改簿内的设备和标签；3 在 12 个接口里和 2 相同，管理簿本身（改名、成员）走命令行。只读簿收到写请求要拒绝（客户端多选模式下仍会发，笔记 04）。
- `max_peer_one_ab` 回 0（不限）。
- 设备：`peer/add` 对已存在的 id 按"合并更新"处理并回成功（客户端加标签、加设备都不查重，笔记 04）；`peer/update` 只合并请求里出现的字段；个人簿存 `hash`、共享簿存明文 `password`，两者都加密落盘，读出时解密回给客户端；`tags` 存字符串数组；其余字段原样存进 `data`（保留原 JSON 类型）。
- 标签：改名、删除时由服务端级联修改本簿所有设备的 `tags`。`color` 按 i64 存取。
- 分页和类型严格性按笔记 04 §1.6、§2。

### 12.2 用户组（维护者 2026-10-22 定：Porta 也做用户组）
- 一个用户可以在多个组里（`group_member`）。共享簿可以授权给组（`ab_rule.group_id`），成员变动后权限立即跟着变。
- 组只用于授权和组面板可见范围；组的增删、成员管理走命令行。

### 12.3 组面板（`/api/users`、`/api/peers`、`/api/device-group/accessible`）
- 管理员：看到全部用户和全部设备。
- 普通用户：看到自己，加上和自己同在任一 `share_devices=1` 组里的用户；设备是这些用户名下的（`device.user_id`）。
- `/api/device-group/accessible` 回 `{"total":0,"data":[]}`。
- `status`（在线）按 `PeerMap` 的内存在线判定；字段和类型照笔记 03 §3。

## 13. 密码字段加密（`crypto.rs`）

- 工作目录下的 `porta_secret.key`（32 字节随机数，首次启动生成，权限 0600，和 `id_ed25519` 放在一起）。
- `sodiumoxide::crypto::secretbox`；存储格式 `sb1:` + base64(nonce ‖ 密文)。
- 加密的字段：`ab_peer.hash_enc`、`ab_peer.password_enc`。服务端运维者本人仍能解开，目的是防数据库文件和备份泄露。
- 备份数据库时要连同 `porta_secret.key` 一起备份，丢了这个文件，地址簿里的密码就解不开了。

## 14. 命令行（`src/cli/`）

`porta-server <子命令>`，直接读写同一个数据库（`DB_URL`），启动时执行迁移。需要运行时状态的子命令走本机控制台（127.0.0.1:`port-1`）。密码一律从标准输入读一行，不放在参数里。
- `user add <name> [--admin] [--display-name …] [--email …]`、`user passwd <name>`、`user list`、`user disable|enable <name>`、`user admin <name> on|off`、`user del <name>`
- `group add <name> [--share-devices]`、`group del <name>`、`group list`、`group member add|rm <group> <user>`
- `ab list`、`ab create <name> --owner <user> [--note …]`、`ab rename <name> <new>`、`ab del <name>`、`ab grant <book> --user <u>|--group <g> ro|rw|full`、`ab revoke <book> --user <u>|--group <g>`
- `device list [--legacy]`：id、主机名、账号、客户端类型和版本、最后上报时间；`--legacy` 只列原版客户端（退出兼容时用）
- `strategy show [<device>]`、`strategy set <device|'*'> <key> <value>`、`strategy unset <device|'*'> <key>`、`strategy repush <device|'*'>`（递增 epoch）
- `device pin-relay <device> <host|none>`
- `relay status`（控制台 `rs`）、`route test <ipA> <ipB>`（控制台 `tg`）
- `geo lookup <ip>`（直接读本地 mmdb：国家、经纬度、ASN、运营商组）、`geo update`（立即下载）
- `stats [--days N]`：中继回落率和各结果计数（§8）
- `import rustdesk-api <db 路径> [--dry-run]`（§15）
- 名字校验：用户名、组名、簿名不能为空；共享簿名唯一且不能是 `My address book`。

## 15. 从 rustdesk-api 导入（`src/import.rs`）

- 只读打开 rustdesk-api 的 SQLite，按笔记 05 §8 的 SQL 读取；Porta 库里已有用户时拒绝执行（只支持往空库导入一次）。`--dry-run` 只打印将导入的数量和冲突。
- 导入：用户（密码哈希原样，登录时升级）、用户组（`groups.type=2` → `share_devices=1`）和成员、个人簿、共享簿、授权规则（个人规则和组规则分别导入）、条目、标签、设备归属（`peers.user_id`，可选）。令牌、登录日志、审计不导入。
- 清洗：`CAST(tags AS TEXT)` 后解析，`null`/坏数据 → `[]`；重复条目、重复标签、孤儿标签按笔记 05 的规则处理；共享簿重名或叫 `My address book` 时改名并打印；`forceAlwaysRelay` 转成字符串 `"true"`/`"false"` 存进 `data`；密码和哈希加密后存。
- 只能靠 OAuth/LDAP 登录的用户（密码为空）照样导入，打印清单，提示用 `user passwd` 设密码。
- 导入在一个事务里完成。

## 16. 测试与验收

- 构建、测试都在 Linux 测试机上跑（`cargo build`、`cargo test`）。每个模块要有单元测试；行为以笔记里的客户端代码为准，不以 rustdesk-api 为准。
- HTTP 契约测试：用 axum `Router` + 临时 SQLite（`tower::ServiceExt::oneshot`），逐条断言 §9.1 的约定（状态码、Content-Type、空 body、字段类型），以及地址簿权限、级联、合并更新、心跳下发规则。
- 会合测试：在回环地址上起真实监听，模拟客户端做 KeyExchange（v0 和 v1 都测）后发 `PunchHoleRequest`，断言 v6 地址被转发、强制中继时被清空、选中的中继符合路由规则（可参照客户端 `src/common.rs` 里的 `rendezvous_stub` 测试写法）。
- 第一期验收（部署后由维护者用原版客户端做）：登录、地址簿、设备列表、审计正常；被控端本地写死的中继能被远程清掉；中继按双方位置选择；控制端勾选 IPv6 后两端都有 IPv6 时能直连。

## 17. 工程约定

- 如非必要，勿增实体：不加兜底代码、没人要的配置项、防御性检查；校验只针对会变的东西（用户输入、外部数据、下载的库文件）。
- 新依赖选发布满两周的版本；能用已有依赖就不加新的。
- 提交信息用中文，直接 `git commit`（签名身份已自动配置）；每个模块做完再提交，不 push，由主会话统一推送。
- 工作区保持 LF（本仓库设了 `core.eol=lf`）。
