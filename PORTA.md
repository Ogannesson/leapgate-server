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
| `src/strategy.rs` | 生效选项与版本号计算（§10），设备模块和命令行共用 | 骨架 |
| `src/crypto.rs` | 密码字段加密（§13） | 骨架 |
| `src/api/mod.rs` | axum 路由表、通用响应和请求体解析、Bearer 认证提取器、静态说明页 | 骨架 |
| `src/rendezvous_server.rs`、`src/kx.rs`、`src/peer.rs`、`src/common.rs` | 会合逻辑和挂钩（§6） | 会合 |
| `src/router/` | 路由第一级、健康检查、GeoIP 加载与更新（§7） | 路由 |
| `src/conn_tracker.rs` | 连接结果记录与统计（§8） | 结果记录 |
| `src/api/account.rs`、`src/api/group.rs` | 账号接口、组面板（§9.2、§11、§12.3） | 账号 |
| `src/api/ab.rs` | 地址簿 12 个接口（§12） | 地址簿 |
| `src/api/device.rs`、`src/api/audit.rs` | sysinfo、心跳下发、审计（§9.3、§10） | 设备 |
| `src/cli/`、`src/import.rs` | 命令行与导入（§14、§15） | 命令行 |

骨架实现的 `Router`（只按配置列表轮询）和 `ConnTracker`（各挂钩方法为空操作）是能跑的最小版本，让会合模块在并行阶段就能调用和测试；路由、结果记录模块再替换内部实现，不改签名。骨架阶段为后面各模块建好空文件和函数签名（`todo!()` 只允许出现在并行模块名下的文件里，且不允许留到合并后），并行模块在签名内实现。签名需要调整时，改动方在汇报里写清楚，由集成阶段统一。

依赖由骨架一次加齐，并行模块不改 `Cargo.toml`：`axum` 0.8、`argon2`、`bcrypt`、`md-5`、`sha2`、`maxminddb` 0.32（`mmap`）、`toml`、`flate2`（GeoIP 解压，之前当死依赖删了）、sqlx 补 `migrate` 特性，dev 依赖 `tower`（`ServiceExt::oneshot`）。版本选发布满两周的。

删掉：`src/mod.rs`（孤儿文件）、`database::tests::test_insert`（出错不报、等于空跑，`peer_roundtrip` 已覆盖）、`common::check_software_update`（向 RustDesk 官方外呼）。

## 3. 进程结构与共享状态

- 入口 `main.rs`：第一个参数是已知子命令（§14）时进入命令行模式，否则照原样解析 hbbs 参数、启动服务。
- `RendezvousServer::start_with_bind` 自己建 tokio 运行时；API（axum）、路由健康检查、GeoIP 更新、结果记录的落库任务都在这个运行时里 `spawn`。
- `AppState`（`Clone`，内部全是 `Arc`/池句柄），同一份交给 `RendezvousServer` 和 axum：
  - `db: SqlitePool`（主池，§4.1）
  - `pm: PeerMap`（原有，在线状态 = 内存里有且 `last_reg_time` 不到 30 秒，笔记 02 §2.5；查库写库用自己的会合池，§4.1）
  - `router: Arc<Router>`（替代原来每个 clone 一份的 `relay_servers`/`relay_servers0` 快照，笔记 02 §1.6、§3.5）
  - `tracker: Arc<ConnTracker>`
  - `secret: Arc<SecretBox>`（§13）
  - `cfg: Arc<Config>`
  - `get_server_sk` 的结果（KeyExchange 和 `IdPk` 签名用的私钥）不进 `AppState`，只存在 `RendezvousServer` 的 `inner.sk` 一份；API 侧以后要签名时再挪进来，不要两边各存一份。
- 模块自己的小状态（登录失败计数、审计 nonce 去重表）放在模块内的 `static`，不进 `AppState`。
- Porta 新增的代码（路由、结果记录、API、GeoIP、新表）里，IP 在比较、查库、落库前先规范化：`::ffff:a.b.c.d` → IPv4（`to_canonical()` 或 `try_into_v4`）。原版会合逻辑里已有的地址处理保持原样（`same_intranet`、`update_addr`/`RegisterPk` 的 ip 比较、`peer.info.ip` 落库、`tcp_punch` 的键），也不要在 accept 处统一改写地址，否则同公网 IP 的设备拿不到局域网直连，或升级后每台设备都被判成"IP 变了"。

## 4. 存储

### 4.1 连接池与迁移
- 主池 `sqlx::SqlitePool`（API、命令行、后台任务用）：WAL、`synchronous=NORMAL`（提交不等 fsync，只有 checkpoint 才刷盘；不会损坏库，掉电最多丢最后几个事务）、`busy_timeout` 5 秒、`foreign_keys` 打开，池大小 `MAX_DATABASE_CONNECTIONS`（默认改为 8），取连接最多等 3 秒（sqlx 默认 30 秒；API 被灌时宁可几秒内失败，审查 C-21）。路径仍是 `DB_URL`，默认 `./db_v2.sqlite3`。
- 会合池：`PeerMap` 单独一个池，连同一个库（`database::rendezvous_pool`，由 `AppState::new` 建）：2 个连接，取连接最多等 200 毫秒，`busy_timeout` 200 毫秒，其余设置同主池。`io_loop` 里查库、写库都走它，不和未认证的 API 请求排同一个公平队列（审查 C-21/C-11：API 被灌时，`io_loop` 每查一次库就要排几秒，UDP 收包和三个 TCP 端口的 accept 一起卡住）。等不到就放弃这次处理，客户端下一轮注册会重试；查库失败不能当成"没有这个 id"（§6 第 7 条）。
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

`conn_attempt` 表照笔记 02 §4.4 的 DDL 原样放进 `0001`，`signal` 列注释补上 `'relay_only'`（§8）。

## 5. 配置

- hbbs 原有参数（`-p`、`-k`、`-r`、`--mask`、`DB_URL`、`.env`、`-c` 指定的 INI…）全部照旧。
- Porta 自己的结构化配置放在 `porta.toml`：路径取参数 `--porta-config`（环境变量同名规则照 `get_arg`），默认工作目录下的 `porta.toml`；文件不存在就全用默认值。改了要重启。
- 中继列表：`porta.toml` 里有 `[[relay]]` 就用它；没有就用 `-r` 的列表（权重 1，无覆盖）。控制台 `rs a,b,c` 仍可在运行时临时替换。载入时只去掉空串和重复项，**不做 DNS 过滤**（不用原版 `get_servers` 里的 `test_if_valid_server`）：解析不了的主机由健康检查判为不可达，恢复后自动回到候选里。

```toml
[api]
listen = ""                       # 留空 = 0.0.0.0:{port-2}（-p 默认 21116，所以默认 21114），和客户端由会合地址推 API 地址的规则一致
                                  # HTTPS 交给前面的反向代理

[geo]
dir = "geoip"                     # 放 mmdb 的目录（相对工作目录）
source = "dbip"                   # dbip：自动下载 DB-IP Lite，文件名固定 dbip-{city,asn}-lite-YYYY-MM.mmdb，取目录里月份最大的
                                  # manual：只读目录里已有的文件（MaxMind 走这条），每天看一次 mtime，变了就重新加载
city_file = "GeoLite2-City.mmdb"  # 只在 manual 时生效，相对 dir（默认值是 geoipupdate 的文件名）
asn_file = "GeoLite2-ASN.mmdb"
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
1. **KeyExchange v1**：21116/TCP 每条连接 accept 后、有 `sk` 时先发 `KeyExchange`（v1：签名的临时公钥 + `signed_params`），读第一帧：是 `KeyExchange` 且 `keys.len()==2` 就建立加密，之后收发都加解密；第一帧不是 `KeyExchange` 就按明文 `RendezvousMessage` 处理。写半边存进 `tcp_punch` 时要带上加密器（`Sink` 改型）。完整步骤和客户端测试里的服务端替身见笔记 02 §6.2。21118（WebSocket）**不做** KeyExchange、服务端也不先发：客户端 `use_ws()` 时 `secure_tcp`/`secure_tcp_required` 都直接跳过（客户端 `src/common.rs` `secure_tcp_impl`），`Sink::Ws` 不带加密器。`sk` 为 None（`-k` 传的是公钥）时，启动时打一条 error 日志："没有私钥，无法做 KeyExchange，登录过的客户端会连接失败；请用 `-k -` 或 `-k <base64 私钥>`"。
2. **IPv6 信令转发**：按笔记 02 §6.5 的表补 `socket_addr_v6`（以及 `PunchHole` 的 `force_relay`、`PunchHoleResponse` 的 `upnp_port`）。不转发 `udp_port` 和 WebRTC 字段。hbbs 强制中继（`ALWAYS_USE_RELAY` 或 mask 异或）时清空转发的 v6 地址并置 `force_relay`（笔记 02 §6.4）。
3. **路由挂钩**：`handle_punch_hole_request` 里调 `router.select(&RouteQuery{a_ip, b_ip, b_id, a_token, conn_type}).await`；`RelayResponse` 分支和控制台 `tg` 也改调 router（`b_id` 传空串）。新增控制台命令 `gu`：让路由模块立即执行一次 GeoIP 下载/重新加载并回显结果（§14 `geo update` 用）。`io_loop` 的中继定时器分支、`Data::RelayServers` 删掉，健康检查挪进 router（笔记 02 §3.5）。控制台 `rs` 无参数时打印 `router.status_text()`。
4. **结果记录挂钩**：H1~H5 五处调用 `tracker`（笔记 02 §4.4），只取字段、不阻塞（tracker 内部用通道异步落库）。
5. 修掉控制台 `aur` 把中继列表清空的那一行（笔记 02 §3.4）。
5a. 21118（WebSocket）只在 TCP 对端是回环地址时才信任 `X-Real-IP`/`X-Forwarded-For`，否则用 TCP 对端地址（原版对任何来源都信任，直连 21118 就能伪造来源 IP，影响按 IP 选中继、限流和记录；笔记 02 §5）。反向代理和 porta-server 同机部署时行为不变。
6. 删掉 `check_software_update` 及其调用。
7. 注册语义不改（`UUID_MISMATCH` 逻辑、每来源每分钟 30 次和每天 300 个新 id 的限额、mask/local_ip、`test_hbbs` 自检照旧），只补边界（审查 A-1/A-5/A-10）：
   - `RegisterPk` 进任何分支之前先校验：`pk` 必须正好 32 字节（客户端发的是 ed25519 公钥 `Config::get_key_pair().1`），`uuid` 非空且不超过 96 字节（客户端发 `get_uuid()`：机器 id，Windows/macOS 36 字节、Linux 32 字节，没有时用 32 字节公钥；96 是 API 那边 128 字节 base64 的原始长度，能注册的设备一定能通过 §9.3 的 uuid 校验）；不合格的静默丢弃：不回包、不写库、不打日志。
   - `IP_BLOCKER` 按来源计数：IPv4 按地址，IPv6 按 /64（和 §8 的 `source_key` 一致；双栈套接字上的 `::ffff:a.b.c.d` 先还原成 IPv4）。控制台 `ib <地址>` 输入任一地址都能查到它所在的来源。检查分两步：先查每来源每分钟约 30 次；查明是新 id（`PeerMap` 和库里都没有）后，再查每来源每天 300 个新 id（超出回 `TOO_FREQUENT`，和原版一样）和全局上限，都通过才把 id 记进该来源的集合。已存在的 id 不进集合。天窗口固定从建条目或上次清空时算起，到期清空，所以所有来源的集合合计不超过一天的全局上限（20 × 1440 个）。
   - `IP_BLOCKER` 最多 65536 个条目（来源）。满了以后，没有条目的新来源不建条目、不受每来源限额，直接交给全局新 id 上限（有意 fail-open，库的增长由全局上限兜住），每分钟最多打一条 warn。
   - 全局新 id 上限：所有来源合计每分钟最多 20 个新 id，超出的丢弃、不回包，每分钟最多打一条 warn。个人部署一天新增的设备只有个位数，批量部署时客户端会在后续注册周期里重试。已知 id 不受影响。
   - 库里的 `peer` 行不做自动清理（表里没有最后在线时间）：持续被灌时每天最多新增约 2.9 万行（20 × 1440）。
   - `RegisterPk` 的 id 不在内存里时要查库：查库前先过一个全局令牌桶（每秒 200 次、突发 1000 次），超出的静默丢弃（不回包、每分钟最多一条 warn）。被丢的客户端下一轮 `RegisterPeer` 会再被要求 `RegisterPk`（审查 C-12）。
   - 查库出错不等于"没有这个 id"（审查 C-22/U-1）：`PeerMap::get` 返回 `Result<Option<_>>`。`RegisterPk` 出错就丢包，不进新 id 检查、不建条目；TCP 打洞请求不回包；`get_pk` 返回空、不签名。确认库里没有才在内存里建空条目（`insert_new`），不再查第二次库。
   - `update_pk` 先写库、成功后才改内存，写库失败时内存条目保持原样；`RegisterPk` 回真实结果，写库失败回 `SERVER_ERROR`（客户端只记一行日志，下一轮重试）。不能回 `UUID_MISMATCH`：客户端收到它会换一个新 id（rustdesk `rendezvous_mediator.rs` `handle_uuid_mismatch` → `Config::update_id`）。插入撞上 id 唯一索引（查库之后别处加了这个 id，比如命令行导入）时，从库加载这一行、回 `SERVER_ERROR`，客户端重试时按库里的 uuid 判断。
   - `io_loop` 里的 5 分钟定时器（和 `handle_udp` 串行，不会插进 `RegisterPk` 的查找和 `update_pk` 之间）：`IP_BLOCKER` 清空天窗口到期的集合，删掉分钟窗口已过且集合为空的条目；`IP_CHANGES` 删掉 360 秒前开始的记录；`PeerMap` 删掉 `last_reg_time` 超过 24 小时的条目。被淘汰的设备回来时，下一次 `RegisterPeer`（只查内存）会被要求重新 `RegisterPk`，`RegisterPk` 再从库里加载条目、照常校验 uuid，受每来源每分钟约 30 次的限额；淘汰时间取 24 小时，是为了让过夜离线的设备不走这一轮（审查 C-3：一个出口后面的上百台机器早上一起回来，要分几分钟才能全部在线）。只存在内存里的 `socket_addr`、`last_reg_time`、`reg_pk`（6 秒内的注册计数）对闲置一天的设备都没有意义，在线判断本来就要求 `last_reg_time` 在 30 秒内。TCP 侧的 `get` 从库里加载条目时只在内存里没有时才插入，不覆盖已有条目（审查 C-25）。
   - 日志不打 uuid/pk 原文，只打 id、来源 IP 和长度。未认证、每个包都能触发的日志（info 及以上）一律用 hbb_common `throttled_log!`，每分钟最多各打一条：uuid 不匹配、ip/pk 不匹配、许可证不符的 `PunchHoleRequest`、`RegisterPeer` 的 "IP change"、`update_pk` 的两行，以及会合模块查库、写库失败（审查 A-5、C-1/C-7/C-8/C-17）。攻击者给的 id 先截到 253 字节（按字符边界）再打：TCP 打洞请求的 id 不校验长度，最长一帧。以后在这类路径上加日志照此办理。
   - 查库、写库仍在 `io_loop` 里做：有了上面的上限，写库次数有界；每次最多等会合池的 200 毫秒取连接加 200 毫秒写锁（§4.1），不再随 API 负载变长。
8. 会合端口的资源上限（审查 A-2/A-3/A-4；常量写死，不做配置）：
   - 帧长：21116/TCP 单帧和 21118/WebSocket 单条消息、单帧最多 16 KB（最大的合法消息是带 WebRTC offer 的 `PunchHoleRequest`：新客户端不带候选，约 1 KB；老客户端带全部候选，几 KB）。21115 单帧最多 128 KB：`OnlineRequest` 客户端不分批，界面把当前标签页的全部 id 一次发出（`peers_view.dart` `_queryOnlines` → `client.rs` `query_online_states_`）；地址簿每本最多 5000 台，即使每个 id 16 个字符也只有约 90 KB。超过帧上限的连接直接断开。
   - `OnlineRequest.peers` 超过 16384 条（128 KB 按每个 id 至少 6 字节加 2 字节标签和长度能放下的条数）的整条丢弃，不回包。
   - WebSocket：握手 10 秒超时；握手完成前最多读 8 KB，超过就断开（tungstenite 握手阶段自己最多缓冲 64 KB，每读一次都从头重新解析；客户端和同机 nginx 转发的升级请求只有 1~2 KB，审查 C-2）；读缓冲 4 KB（tungstenite 默认每条连接预先分配 128 KB）。
   - 并发连接：21116、21118 各最多 2048 条，21115 最多 256 条；每个端口上每个来源（IPv4 地址 / IPv6 /64）最多 32 条，回环来源只计入总数（同机反代承载所有 WSS 客户端）。超限的连接在 accept 后直接关闭，21116 上不发 KeyExchange、不做签名；每分钟最多打一条 warn。
   - 最坏情况下的缓冲（审查 C-2/C-15/C-27，按 Linux 实测修正）：21116 每条约 26 KB（`Framed` 写缓冲 8 KB + 读缓冲涨到 16 KB 一帧 + 任务），合计约 53 MB；21118 握手完成前每条最多 8 KB + 4 KB 读块，握手后每条约 4 KB 读缓冲 + 16 KB 帧 + 最多 16 KB 正在拼接的分片消息，合计约 74 MB；21115 每条约 136 KB，合计约 35 MB；三者合计约 160 MB。攻击结束后 glibc 不会把峰值 RSS 还给系统，选部署机时按峰值留余量。另有 `PUNCH_REQS`（默认最多 10 万条，约 21~45 MB），只记录带对 key、目标在线的打洞请求，不算在上面。
   - 发往 UDP 的消息（转发给 B 的 `PunchHole`、`RequestRelay` 等）进一个最多 4096 条的有界队列，连接任务不等、队列满了就丢弃（每分钟最多一条 warn），`io_loop` 卡住时内存不随攻击带宽增长。`RequestRelay` 不校验任何东西就转给 B，所以：每条连接最多 12 条，超过就断开（客户端每次尝试一条，最多 3 次）；转发时只带客户端会设的字段（`id`、`uuid`、`relay_server`、`secure`、`conn_type`、`token`、`switch_code`，加服务端填的 `socket_addr`），`uuid`、`token`、`switch_code` 截到 64 字节、`relay_server` 截到 253 字节，不带 `licence_key`；`PunchHoleRequest` 转发的 `socket_addr_v6` 超过 18 字节（`AddrMangle` 编码的 IPv6 地址长度）就清空（审查 C-13）。

## 7. 路由第一级（`src/router/`）

- 接口：`async fn select(&self, q: &RouteQuery<'_>) -> RouteDecision { relay: String, reason: &'static str }`。返回单个中继字符串（原版客户端只认一个）；空串语义照旧（被控端退回"hbbs 主机:21117"）。`reason` 取值为 `fixed`（固定中继）、`geo`（双方都有位置）、`geo_a`/`geo_b`（只有 A 或只有 B 有位置）、`rr`（轮询）、`none`（没有配置中继）。
- 固定中继：每次调用按 `b_id` 查一次 `device_policy.relay_pin`（主键查询，不缓存），所以命令行 `device pin-relay` 写库后下一次连接就生效。有固定中继时直接用它，不看健康状态（运维的明确意图）。`b_id` 为空串时跳过这一步。中继列表、健康状态、GeoIP 都在内存里。
- 候选：健康检查判为可达的中继。
- 代价：`cost(R) = (rtt(A,R) + rtt(B,R)) × weight(R)`，取最小。`rtt` 按笔记 06 §4：大圆距离 × 2 × `detour` / 200 km/ms，加每段的跨运营商组、跨境惩罚；`multi_bgp` 的中继不算跨运营商。
- 回退：有位置的候选按代价排序、取最小；没有位置的中继不参加排序。一方位置未知时用 `2 × rtt(已知方, R) × weight(R)`。只有双方位置都未知，或候选里一台有位置的都没有时，才在全部候选里轮询。私网、回环、链路本地、ULA 来源地址按 `server_location` 算，`100.64/10` 当作未知（笔记 06 §5.2）。
- 惩罚的精确算法：运营商组键统一用字符串，内置表里有的用组名，没有的用 `AS<号>`；配置里的 `carrier` 可写组名或 `AS<号>`。跨运营商惩罚只在一段两端国家相同时计算，取该国覆盖值，没有覆盖用全局值；任一端组未知不加。跨境惩罚取两端国家覆盖值里较大的，都没有覆盖用全局值；任一端国家未知不加。`[[relay]]` 和 `server_location` 的覆盖按字段生效，空串或不写等于不覆盖：中继没覆盖的字段仍然查库，`server_location` 没写的字段视为未知。
- 中继位置：配置覆盖优先，否则解析主机名后查库。启动时、每次换库热切换后、`rs` 替换中继列表后都重新计算；DNS 解析失败或库里查不到就当作没有位置，下一轮健康检查时再试，不当成永久结果缓存。客户端 IP 不做缓存，每次直接查 mmap。
- 健康检查：配置载入时（启动、控制台 `rs` 替换）把全部中继视为可达；之后每 3 秒对每台中继做一次 TCP 建连（3 秒超时），只有一台也要查；记录是否可达和建连耗时；某一轮全部失败时保留上一轮的可达集合（和原版一致）。
- GeoIP：`maxminddb`（开 `mmap`），文件名规则见 §5。没有库时路由退回轮询，不阻塞启动。
  - `source = "dbip"` 且 `auto_update`：启动后在后台检查、此后每天检查一次。want = 当前 **UTC** 年月；本地 city 和 asn 都 ≥ want 就跳过。否则下载 `dbip-{city,asn}-lite-YYYY-MM.mmdb.gz`；当月 404 时，本地没有库或本地库比上月还旧才下载上月，本地已有上月文件就保持不动、次日再试。解压到 `*.part`、用 maxminddb 打开并抽查几个 IP 通过后原子改名并热切换。下载用已有的 `reqwest` + `flate2`（笔记 06 §3）。
  - `source = "manual"`：每天检查一次两个文件的 mtime，变了就按同样的打开、抽查流程重新加载并热切换；抽查失败保留旧库。每次加载都先把文件复制成私有副本、映射副本，运维用 cp、curl -o 原地覆盖文件也不会让进程因 SIGBUS 崩溃。副本放在服务工作目录下的 `.porta-geoip/<文件名>`（和数据库、密钥文件同处，服务一定能写；先写临时名 `<文件名>.part` 再改名），不放在 `geo.dir` 里：`geo.dir` 可以是 geoipupdate 的 root 目录或只读挂载，服务对它只读不写。
  - 清理：服务进程启动时删除残留的 `*.part`（dbip 在 `geo.dir` 里，manual 在 `.porta-geoip/` 里）；热切换成功后删除旧月份的 mmdb（删不掉就忽略，下次启动再删）；任何一步失败都删掉本次的 `*.part`，保留旧库，次日重试。只有服务进程做清理。
  - 命令行 `geo lookup` 按同样的规则找文件，不写任何文件：dbip 直接映射（这些文件只会被改名替换），manual 读进内存（不做私有副本）。
- 每次决策打一行 debug 日志：双方国家/运营商组、候选代价、选中的中继和 `reason`。
- 运营商组：内置中国三大运营商的主要 ASN 表（写代码前到 bgp.he.net 或 PeeringDB 核对），查不到时按"ASN 相等算同组"。不用 AS 名称做字符串匹配。

## 8. 连接结果记录（`src/conn_tracker.rs`）

- 按笔记 02 §4.4 实现：内存跟踪器（键 `try_into_v4(A:p1)`、`(A 公网 IP, B id)`、`try_into_v4(A:p3)`），每 5 秒扫一遍把到期的记录定稿写入 `conn_attempt`，定稿规则照笔记，下面几条是对笔记的补充和更正。热路径（H1~H5）只做内存操作，不 await 数据库。
- `a_user`/`a_device_id`：H1 只把 `PunchHoleRequest.token` 原串存进内存记录，反查放在后台（定稿写库时）调 `auth::token_owner`（async）；`a_user` 存 `user.name`，`a_device_id` 存 `token.device_id`；未登录或令牌已失效时两者都是 NULL。
- `outcome` 取值全集：`rejected`、`no_reply`、`relay`、`relay_or_v6`、`relay_failed`、`relay_unmatched`、`direct_lan`、`direct_tcp`、`direct_tcp_or_v6`。
- 窗口（命名常量，标注"待实测"）：直连判定窗口 `W = max(45 秒, 6 × (reply_at − started_at) + 20 秒)`（A 的直连超时 = 打洞耗时 × 6，没有封顶；客户端的打洞耗时还包含连 hbbs 和 KeyExchange 的时间，hbbs 看不到，20 秒余量约能覆盖 3 秒，实测时要专门覆盖慢建连）；H5 匹配时要求 `RequestRelay` 落在 `reply_at + W` 以内；一条记录最多合并 3 次 `RequestRelay`（客户端最多回落 3 次），而且只在它第一次 `relay_req_at` 之后 60 秒内合并，超出的另起一条 `relay_only`；匹配到 `RequestRelay` 的记录，等最后一次 `relay_req_at` + 20 秒后才定稿，那时有 `relay_resp_at` 记 `relay`，没有记 `relay_failed`。
- H5 没匹配到打洞记录：写一行 `signal='relay_only'`：`started_at`、`relay_req_at` 取收到的时刻；`a_ip`/`a_port` 取 A:p3；`via` 照实；`b_id = rf.id`；`conn_type`、`a_nat_type`、`a_force_relay`、`a_has_v6`、`server_forced_relay` 填 0；`a_user` 照常反查。有 `relay_resp_at` 记 `relay_unmatched`，没有记 `relay_failed`。
- 防滥用（这些请求都不认证；常量写死，不做配置）：许可证不符（`LICENSE_MISMATCH`）的请求不记录，所以不会出现 `signal='fail_license'`；`b_id`、中继地址和 `a_device_id`（来自令牌行，登录时已限长，§11）截到 253 字节，版本号、令牌、uuid 截到 64 字节；同一来源每分钟最多新建 60 条记录（IPv4 按单个地址算，IPv6 按 /64 前缀算：一台主机至少分到一个 /64），所有来源合计每分钟最多新建 120 条，超出的丢弃并计数（被丢弃的不占两种额度）；写库队列最多 1 万条，满了丢弃并计数，这几种丢弃每分钟最多打一条 warn 日志；队列里的定稿记录成批（每批最多 1000 条）在一个事务里写入；每小时删除一次 `started_at` 早于 90 天的行，并且只保留最新的 20 万行。上限估算（实测，SQLite 4 KB 页）：最坏的一行（文本列都到截断上限，且带有效令牌、`a_user`/`a_device_id` 非空）记录约 1.6 KB，一页只放得下两行，加上 `idx_ca_b` 索引里 `b_id` 的副本，磁盘上约 2.4 KB；两次修剪之间最多新增 120 × 60 = 7200 行（另加修剪时还没定稿的几分钟记录），所以持续被灌时表最多约 20.7 万行、约 0.5 GB，删掉的页会被复用，文件停在这个大小；不带有效令牌的请求单行约 1.4 KB，约 0.29 GB。90 天删除和修剪共用一个每小时的定时器：前者是 `idx_ca_started` 上的范围删除，多数时候什么都删不到，不值得单开定时器。审计表的保留期和 `device` 表的行数上限（§9.3）也在这个定时器里做（服务启动时先跑一次），各表删了多少行合成一条日志，什么都没删时不打。
- 统计查询（给命令行）：按时间范围算中继回落率 = count(outcome IN (`relay`,`relay_or_v6`)) / count(outcome IN (`relay`,`relay_or_v6`,`direct_lan`,`direct_tcp`,`direct_tcp_or_v6`))；`rejected`、`no_reply`、`relay_failed`、`relay_unmatched` 不进分子分母，只在分项计数里列出。另列 `relay_offered` 非空、`b_relay` 非空且两者不相等的次数（被控端本地写死了中继）。

## 9. HTTP API 通则

### 9.1 必须遵守（任何一条写错，原版客户端都会走错分支）
1. **任何接口都不回 5xx**：客户端遇到 5xx 或连不上会改走 hbbs 的 TCP 代理（第一期不做），白等最长 36 秒，心跳也跟着卡住。内部错误：审计接口回 200 + `{"error":"…"}`（客户端会重试）；`/api/currentUser` 回 200 + `{"error":"…"}`（客户端收到 400 会清本地令牌、401 会全部重置，一次临时错误不能把用户登出）；其他接口回 400 + `{"error":"…"}`。
2. 请求体一律用 `Bytes` 收、自己解析 JSON；不用 axum 的 `Json` 提取器（出错回 415/422 纯文本）。JSON 响应带 `Content-Type: application/json; charset=utf-8`；`SYSINFO_UPDATED` 用 `text/plain; charset=utf-8`；空 body 的响应（sysinfo 403、审计成功、地址簿写接口成功）不要求 Content-Type。axum 自己产生的错误也回 JSON：用错 HTTP 方法回 405 + `{"error":"Method Not Allowed"}`，请求体超过 2 MB（`Bytes` 的默认上限）回 413 + `{"error":"Request body too large"}`。
3. 令牌无效、过期、账号禁用 → **401**（客户端据此清登录态）。
4. `/api/login-options` 回 `[]`（没有第三方登录）。
5. 用户信息里 `name` 必须是非空字符串；登录成功必须带 `user`；`info`、`is_admin`、`status` 不能是 null（笔记 03 §2.5）。
6. 列表接口回 `{"total": int, "data": [...]}`，`total` 必须是整数；分页参数 `current`、`pageSize`，不能把每页压到客户端要的条数以下。例外：`POST /api/ab/tags/<guid>` 回顶层 JSON 数组 `[{"name":string,"color":int}]`，没有标签回 `[]`，按 name 排序，不带 total、不分页。
7. sysinfo 成功回纯文本 `SYSINFO_UPDATED`（逐字节，不带换行和引号）；**不回 `ID_NOT_FOUND`**（会让客户端每 3 秒重传）。
8. 审计成功回 200 + **空 body**。`nonce` 是可选字段：1.5.0 起才有，1.4.x 的审计不带、也不重试。带 nonce 的按 nonce 去重 5 分钟（重复的也回空 body）；不带的直接入库、不去重；不能把空串当去重键，也不能因为缺 nonce 回 4xx。nonce 只在记录写库成功后才登记进去重表，写库失败回 200 + `{"error":"…"}`，保证客户端重试时能入库。
9. 地址簿：7 个写接口成功只认 200 + 空 body（12 个接口 = 5 个读 + 7 个写）；读接口按笔记 04 §1.2 的三种解析器回；`/api/ab/personal` 永远回 200 + 非空 `guid`（个人簿不存在就当场建）；`settings`、`shared/profiles` 正常实现（不回 404）。
10. JSON 里不给 null；字符串字段不能给数字（SQLite 读出的纯数字字符串要保持字符串）。
- 详细字段和每个接口的推荐回包：账号/组/设备/审计看笔记 03，地址簿看笔记 04。

### 9.2 账号接口（`account.rs`）
`GET /api/login-options`、`POST /api/login`（只做 `type=account`）、`POST /api/currentUser`、`POST /api/logout`。见 §11。`currentUser` 忽略请求体，不因请求体缺字段或解析失败回 400；只有令牌无效、过期、账号禁用时回 401。

### 9.3 设备上报（`device.rs`、`audit.rs`）
`POST /api/sysinfo`、`POST /api/heartbeat`、`POST /api/audit/conn`、`POST /api/audit/file`、`POST /api/audit/alarm`。不带认证（兼容债务），**只接受已在 hbbs 注册过的设备**：`peer` 表里必须有这个 id，body 必须带 `uuid`，且 base64 解码后与 `peer.uuid` 逐字节相等（真实客户端的心跳、sysinfo、被控端审计总是带 uuid）。`peer` 表里没有这个 id、缺 uuid、uuid 不符，一律按不符处理：sysinfo 回 403 空 body（客户端 120 秒后重试）、心跳回 `{}`、审计回 200 空 body 但不入库。这个校验只挡住没在 hbbs 注册过的 id，挡不住刻意造设备的人：注册本身不认证，`RegisterPk` 的 id、uuid 都由请求方自定，限流在会合模块（按来源 IPv4 地址或 IPv6 /64 计数，另有全局上限）。所以 `device` 表和审计表的总量靠下面的行数上限兜住，不靠校验。
- 真实客户端的心跳跑在向会合服务器注册的那个进程里，总是先注册再上报；首次心跳偶尔早于注册完成，回 `{}` 后下一次心跳（15 秒后）就会成功。
- id 超过 253 字节（`MAX_PEER_ID_LEN`）或 uuid 超过 128 字节的请求直接按不符处理，不查库。
- sysinfo 原文（请求体）超过 8 KB 时同样回 403 空 body（真实 sysinfo 只有几百字节；原文整段存进 `device.sysinfo`）。从中拆出来另存的 `hostname`、`username`、`os`、`version` 各截到 253 字节。
- `device` 表最多 1 万行（最坏一行约 10.5 KB，合计约 0.1 GB）：每小时的清理（§8 的定时器）发现超出时，按 `last_seen_at` 从老到新删掉超出的行数，只删没有主人（`user_id IS NULL`）、`device_policy` 里没有这个 id、`strategy_option` 里也没有 `scope` = 这个 id 的行；不符合条件的行即使超出上限也保留。这两张表和 `device` 之间没有外键，删设备行不会连带删掉策略。被删的设备再上报时，心跳重新建行，并因为 `sysinfo = ''` 重新索取 sysinfo（§10）。
- 审计字段限长：超长的值按 UTF-8 字符边界截断后入库，照样回 200 空 body（不回 400）。`audit_conn` 的 `ip` ≤ 64 字节、`peer_id` ≤ 253、`peer_name` ≤ 256、`note` ≤ 4 KB（不认证的备注请求也一样）、`auth` 序列化后 ≤ 4 KB（超出时只留已知字段 `primary_auth`、`two_factor`、`conn_audit_ref`，还超就截断文本）；`audit_file` 的 `peer_id` ≤ 253、`path`、`info` 各 ≤ 4 KB；`audit_alarm` 的 `info` ≤ 4 KB。`device_id` 就是校验过的 id（≤ 253）。
- 审计表行数上限：三张表各最多 2 万行，每次插入前删掉 id 比最新一行小 2 万 - 1 及以上的行（主键上的范围删除）。不放进每小时的清理：审计上报不限速，一小时内能写进的行数没有上界。实测最坏一行（文本列都到上限，SQLite 4 KB 页，含索引）：`audit_conn` 约 9.5 KB、`audit_file` 约 8.8 KB、`audit_alarm` 约 4.6 KB，2 万 ×（9.5 + 8.8 + 4.6）KB ≈ 0.46 GB。另外每小时删掉 `created_at` 早于 180 天的行。

唯一免校验的是控制端会话结束写备注那条 `/api/audit/conn`：判别条件是"有 `note` 键且没有 `uuid` 键"（不能用"没有 nonce"判别，1.4.x 的审计都不带 nonce）。它只更新已有记录、从不插入新行，所以不会增加行数。

`audit_conn` 的关联规则：
- `action:"new"`：插入一行，`session_id` 存 `''`。
- 认证成功（没有 action）：找 `device_id = body.id`、`conn_id = body.conn_id`、`closed_at IS NULL` 的记录里 id 最大的一条，更新 `peer_id`、`peer_name`、`conn_type`、`session_id`（u64 十进制字符串）、`auth`、`authed_at`；找不到就新插一条（`created_at = authed_at = now`）。
- `action:"close"`：同样的条件找到后写 `closed_at`，找不到就忽略。
- 备注：按 `device_id = body.id` 且 `session_id = body.session_id` 更新所有匹配记录的 `note`（同一会话可能有远程桌面和文件传输两条），一条都匹配不到就忽略。

### 9.4 其他
- `GET /`：静态说明页（HTML）：服务名 Porta、源代码地址（AGPL-3.0 第 13 条：链接到公开仓库）、"IP Geolocation by DB-IP" 署名并链接 https://db-ip.com 。客户端"在 Web 控制台管理"菜单打开的就是这里。
- 其余未知路径回 404。

## 10. 心跳与策略（`strategy.rs`、`device.rs`）

- 生效选项 = 全局（`scope='*'`）⊕ 设备（`scope=<id>`，同键覆盖）。
- 版本号 `rev`：对（生效选项按键排序的规范 JSON、全局 epoch、设备 epoch）做 sha256，取前 8 字节转 `i64` 后与 `i64::MAX` 按位与，结果为 0 时取 1。任何生效选项变化或 epoch 递增都会换版本；不用自增计数器。
- 下发规则（笔记 01 §2.2）：**仅当 `req.modified_at != rev` 时**，响应同时带 `"modified_at": rev` 和 `"strategy": {"config_options": {…全部生效选项…}}`；否则两者都不带。值一律是字符串，不给 null。这样"设备首次接入或策略变更时清一次 `relay-server`"自然成立，之后用户在本地改了也不会每次被覆盖。
- 客户端是**增量合并**：只改下发里出现的键，空值表示删键（笔记 01 §3）。所以"撤销"一个推过的键不能删行，要把值写成 `''`（墓碑，下发时客户端删掉这个键）。删掉设备级的同名行，生效值回到全局值；全局也没有这个键时，客户端上的旧值不会被清掉。
- 设备级值为 `''` 时照样覆盖全局值（也就是让这台设备删掉这个键）。
- 编码：`modified_at` 是 JSON 整数（i64），不能写成字符串；"值一律是字符串"只指 `config_options` 里的值。
- `sysinfo` 键只在设备还没有 sysinfo（`device.sysinfo = ''`）时出现，值固定为 `true`；其余情况必须完全省略这个键，不能发 `false` 或 `null`（客户端只看键在不在，带了就会重传 sysinfo）。响应结构体的可选键一律用 `Option` + `skip_serializing_if`。
- 每次心跳更新 `device.last_seen_at`、`ver`、`last_ip`；设备行不存在就建。心跳和 sysinfo 写完设备行后，`user_id` 为 NULL（含刚建的行）时按 §11 延迟补绑。
- 客户端 IP（`last_ip` 等）：TCP 对端是回环地址时取 `X-Real-IP`，没有就取 `X-Forwarded-For` 的最后一个地址；否则直接用 TCP 对端地址；取到后规范化（§3）。反代和 porta-server 不在同一台机器的情况第一期不支持。
- sysinfo：存原文，拆出 `hostname`、`username`、`os`、`version`；`client_type` 第一期一律 `rustdesk`（Porta 客户端以后在上报里加专门的键来区分，见笔记 01 §6）。

## 11. 账号、令牌、密码（`auth.rs`、`account.rs`）

- 密码：argon2id（`argon2` crate 默认参数）。校验时按前缀识别 `$argon2id$`、`$2a$/$2b$/$2y$`（bcrypt）、`md5:`（rustdesk-api 旧格式 `md5(明文+"rustdesk-api")`，笔记 05 §3）；旧格式校验通过后当场改存 argon2id，只在库里仍是刚校验的旧哈希时才写（期间 `user passwd` 改过的不覆盖，这次登录回 401）；库里已被另一个并发登录升级成 argon2id、且本次明文能通过它时照常签令牌。`password_hash = ''` 的账号不能密码登录。
- 令牌：32 字节随机数的 base64url（无填充），库里只存 sha256 hex。没有过期时间，但每个用户最多保留 50 条：登录时在插入新令牌的同一个事务里，删掉该用户按 `last_used_at` 降序（相同再按 rowid 降序）排在 50 名以外的令牌，也就是淘汰最久没用的（否则知道密码的人反复登录就能无限攒令牌行）；改密码、禁用账号时删掉该用户的全部令牌，登出删哪些见下。每次使用更新 `last_used_at`。
- 登录时把请求体里的设备 `id`/`uuid` 记进令牌行；再做 §9.3 同样的校验：只有 `peer` 表里有这个 id 且 uuid 相符时，才把 `device.user_id` 设成这个用户（设备行不存在就建）；uuid 不符时登录照常成功但不改 `device.user_id`（防止别人把你的设备挂到自己名下）；`peer` 表里没有这个 id 时登录照常成功，不建设备行、不绑定（令牌行照样记 id/uuid）。
- 延迟补绑：登录时还没在 hbbs 注册的设备（例如开着 stop-service 登录、之后才启动服务），由之后的心跳或 sysinfo 补上归属：请求通过 §9.3 的 uuid 校验、且 `device.user_id` 为 NULL（含刚建的行）时，取 `token` 表里 `device_id` = 这个 id、`device_uuid` = 请求里的 uuid、账号 `status = 1` 的令牌中 `last_used_at` 最新的一行，把它的 `user_id` 写进 `device.user_id`。安全性和登录时绑定相同：令牌行的 uuid 要等于刚和 `peer.uuid` 比对过的那个。已有主人的设备不改。已知边角：A 在设备上登录过、登出请求没送到，B 再登录接管后又登出，下一次心跳会把设备补绑回 A（A 的旧令牌还在）。不处理：登出时连别人的同设备令牌一起删，会让伪造 `device_id` 的人能删掉别人的令牌；归属只决定设备在组面板（§12.3）里列在谁名下，不影响策略和连接权限，而 A 本来就在这台设备上登录过，补错的后果有限。
- 登出时删掉当前令牌，连同本人 `device_id` 相同的其他令牌（客户端只持有最新一枚，更早的已经是废令牌；留着的话下一次心跳就会把设备补绑回来）；`device_id` 为空的令牌不受影响。之后若 `device.user_id` 是本人则清空。
- 走代理或 WebSocket 的客户端在 hbbs 注册不了（会合模块的 TCP 路径不做注册，§1），`peer` 表里没有它们，所以既不会被绑定，心跳也只拿到 `{}`，收不到策略。
- 登录请求里的 `id` 超过 253 字节（`MAX_PEER_ID_LEN`）或 `uuid` 超过 128 字节时回 400 + `{"error": "…"}`，不写令牌行（和用户名超长一样，在查库前拒绝）。令牌行的 `device_id` 会被结果记录模块复制进每一行 `conn_attempt`（§8），不限长度时登录一次就能让之后每条连接记录都带着任意长的文本。
- 账号可用的判定写死为 `status = 1`。
- 登录失败限流：只按用户名，15 分钟内失败 5 次后，15 分钟内直接拒绝（回 `{"error": "…"}`）。不按来源 IP 限：API 在反向代理后面时看到的全是代理地址，按 IP 限会把所有人一起锁住。
- 密码校验（argon2，不存在的用户名也算一次）同时最多核数个，其余排队；排队的最多 4 × 核数个（常量写死），再来的直接回 429 + `{"error": "…"}`，不无限排队。不存在的用户名不受上面的限流，没有这个上限时，不带凭据的请求就能让正常登录无限期排在后面。
- `async fn auth::token_owner(db, token) -> Option<(user_id, user_name, device_id)>` 给结果记录模块用（在后台调用，不在会合热路径上 await）。

## 12. 地址簿、权限、用户组（`ab.rs`、`group.rs`）

### 12.1 地址簿
- 个人簿：每个用户一本，`personal=1`，名字固定为客户端认的 `My address book`（客户端按名字认个人簿，笔记 04 §6）。
- 共享簿：命令行创建；名字全局唯一，且不能叫 `My address book` 或 `Legacy address book`（客户端把两者都当个人簿，后者还会让客户端切进旧版模式）。`shared/profiles` 列出当前用户能看到的共享簿（主人或有规则），`owner` 填主人的用户名，`rule` 填该用户的有效权限，`info` 回 `{}`。个人簿不出现在 profiles 里。
- 有效权限 = 主人为 3；否则取"直接授给本人的规则"和"授给本人所在任一组的规则"中的最大值；都没有就是无权访问（读写一律 403 + `{"error"}`）。
- 权限语义（维护者 2026-10-22 定）：1 只读；2 读写，可以增删改簿内的设备和标签；3 在 12 个接口里和 2 相同，管理簿本身（改名、成员）走命令行。只读簿收到写请求要拒绝（客户端多选模式下仍会发，笔记 04）。
- 写入上限（常量写死，不做配置）：任何登录用户对自己的个人簿天生有写权限，不限的话一个账号就能写满磁盘。超出一律回 400 + `{"error"}`，客户端把它当失败提示（`_jsonDecodeActionResp` 取 `error` 文本弹 toast），不会走错分支。
  - 每条设备：`id` ≤ 253 字节（`MAX_PEER_ID_LEN`）；`data` 按落盘的 JSON 序列化后 ≤ 8 KB，且 JSON 节点总数 ≤ 64（每个键、每个值都算一个，嵌套的数组和对象里的元素、键、值递归计入；客户端 `Peer.toJson` 只有 11 个 data 键，即 22 个节点），两项都在 `peer/update` 合并之后再查（每次 update 都可能往同一行加键），超了整个请求不生效；`tags` ≤ 64 个、每个 ≤ 64 字节；本簿要存的 `hash`/`password`（客户端上传的明文，加密前）≤ 1 KB，另一个键照旧忽略、不查。
  - 节点数上限的理由：`/api/ab/peers` 要把一整页解析成 JSON 对象，键值很短时内存约是原文的十倍；限住每条的节点数，一页 1000 条解析后约 10 MB。不靠调小 `pageSize` 上限来压内存：客户端翻页循环是 `while (current * pageSize < total)`，用的是它自己请求的 `pageSize`，服务端上限低于它请求的值时客户端会提前停止翻页、静默丢数据。
  - 标签名（`tag/add`、`tag/rename` 的新名字，设备 `tags` 里的每个元素）≤ 64 字节，且不能含控制字符（`char::is_control`），否则回 400。理由：serde_json 把控制字符写成 6 字节的 `\u00XX`，级联改写一次读出的 tags 最多会膨胀到字节数的 6 倍；禁掉后最坏约 21 MB（5000 个设备 × 64 个 64 字节的标签；标签全是引号、反斜杠时每字节转义成 2 字节，约 42 MB），这一步在写锁事务里串行执行，可以接受。
  - 每本簿最多 5000 个设备、1000 个标签：计数和插入在同一条语句里，并发添加也不会超。簿满时 `peer/add` 新 id 回 400，簿里已有的 id 照旧回 200 空 body、不改字段；`tag/add` 同理（已有的名字照旧成功）。
  - 5000 是按在线状态查询定的：客户端把一个标签页的全部 id 放进一条 `OnlineRequest` 发到 21115，那里单帧上限 128 KB（§6 第 8 条）；5000 个 16 字符的 id 约 90 KB，簿满时在线状态也能查出来。
  - `max_peer_one_ab` 回 5000（和设备上限一致）。客户端拿到后，本地缓存的条数到了这个数就不再发添加请求，直接提示 `exceed_max_devices`（`Ab.isFull`，笔记 04 §3.2）。
  - `/api/ab/tags` 不分页、`tag/rename`/`DELETE tag` 的级联改写一次读出本簿所有带该标签的设备，两者靠上面的标签数、设备数和每条 tags 的上限封顶。
  - 从 rustdesk-api 导入（§15）不查这些上限。
- 设备：
  - `peer/add` 遇到簿内已存在的 id：**不改任何字段**，直接回 200 空 body。客户端只按本地缓存查重；目标簿没拉取过时，重复的 id 会带着被清空的 tags 和空的 alias/note 发过来，按合并处理会把现有数据清掉（笔记 04 §3.6、§4.4）。
  - `peer/update` 只合并请求里出现的字段；id 不在簿里回 404 + error，不新建。
  - `DELETE peer`：一个事务里删掉存在的、忽略不存在的，回 200 空 body。
  - 个人簿存 `hash`、共享簿存明文 `password`，两者都加密落盘。`tags` 存字符串数组。其余字段存进 `data`：写入时丢掉值为 null 的键（当作没给）；`alias、note、username、hostname、platform、rdpPort、rdpUsername、loginName、device_group_name、forceAlwaysRelay` 不是字符串、`same_server` 不是 bool 时回 400 + error。
  - `peers` 回包每条 = `data` 的全部键 + `id` + `tags`（数组）+ 个人簿的 `hash` 或共享簿的 `password`（解密后）；`hash_enc`/`password_enc` 为 `''` 时不解密、省略这个键；客户端传来 `hash:""`/`password:""` 时存成 `''`。
- 标签：
  - `tag/add` 遇到同名标签：不改颜色，回 200 空 body（`on conflict do nothing`）。
  - `tag/rename`：old 不存在回 404，new 已存在回 409；成功时同一事务里改 `ab_tag`，并把本簿所有设备 `tags` 里的 old 换成 new、去重。
  - `tag/update`：name 不存在回 404。
  - `DELETE tag`：忽略不存在的名字，同一事务里删标签并从本簿所有设备的 `tags` 中移除，回 200 空 body。
  - `color` 按 i64 存取。
- 分页和类型严格性按笔记 04 §1.6、§2。`pageSize` 最大 1000，超过的按 1000 截断，`total` 照样是全部条数（客户端写死每页 100，按 `total` 翻页；`/api/ab/peers` 一页要整页读进内存解析）。这个上限对所有分页接口（含 §12.3 组面板）都生效。

### 12.2 用户组（维护者 2026-10-22 定：Porta 也做用户组）
- 一个用户可以在多个组里（`group_member`）。共享簿可以授权给组（`ab_rule.group_id`），成员变动后权限立即跟着变。
- 组只用于授权和组面板可见范围；组的增删、成员管理走命令行。

### 12.3 组面板（`/api/users`、`/api/peers`、`/api/device-group/accessible`）
- 管理员：看到全部用户和全部设备。
- 普通用户：看到自己，加上和自己同在任一 `share_devices=1` 组里的用户；设备是这些用户名下的（`device.user_id`）。
- 客户端拉列表时带 `status=1`：请求带 `status` 参数（数字）时，`/api/users` 在上面的可见范围里只返回 `user.status` 等于该值的用户；`/api/peers` 不按设备过滤（设备没有启用状态），但排除被这个条件滤掉的用户名下的设备（例如禁用用户的设备），没有归属的设备（管理员可见）照常列出。不带参数或参数不是数字时不过滤。
- `/api/device-group/accessible` 回 `{"total":0,"data":[]}`。
- `status`（在线）按 `PeerMap` 的内存在线判定；字段和类型照笔记 03 §3。

## 13. 密码字段加密（`crypto.rs`）

- 工作目录下的 `porta_secret.key`（32 字节随机数，权限 0600，和 `id_ed25519` 放在一起）。**只有服务模式**在缺失时生成；命令行（含 import）只读已有的文件，不存在就报错退出，提示到服务的工作目录下运行或先启动一次服务（否则在别处跑命令行会多生成一把密钥，导入的密码就解不开了）。服务模式发现文件不存在、库里却已有密文（`select 1 from ab_peer where hash_enc <> '' or password_enc <> '' limit 1` 查到行）时拒绝启动，报错提示恢复密钥文件，或有意清空这两列（已存的密码全部作废）；不生成新密钥。
- `sodiumoxide::crypto::secretbox`；存储格式 `sb1:` + base64(nonce ‖ 密文)。
- 加密的字段：`ab_peer.hash_enc`、`ab_peer.password_enc`。服务端运维者本人仍能解开，目的是防数据库文件和备份泄露。
- 备份数据库时要连同 `porta_secret.key` 一起备份，丢了这个文件，地址簿里的密码就解不开了。`/api/ab/peers` 遇到解不开的值只省略这条的 `hash`/`password` 键并记 warn 日志（簿 guid 和设备 id，不打密文），其余条目照常返回。

## 14. 命令行（`src/cli/`）

`porta-server <子命令>`，直接读写同一个数据库（`DB_URL`），打开时执行迁移。需要运行时状态的子命令走本机控制台（127.0.0.1:`port-1`）。密码一律从标准输入读一行，不放在参数里。
- `user add <name> [--admin] [--display-name …] [--email …]`、`user passwd <name>`、`user list`、`user disable|enable <name>`、`user admin <name> on|off`、`user del <name>`
- `group add <name> [--share-devices]`、`group del <name>`、`group list`、`group member add|rm <group> <user>`
- `ab list`、`ab create <name> --owner <user> [--note …]`、`ab rename <name> <new>`、`ab del <name>`、`ab grant <book> --user <u>|--group <g> ro|rw|full`、`ab revoke <book> --user <u>|--group <g>`
- `device list [--legacy]`：id、主机名、账号、客户端类型和版本、最后上报时间；`--legacy` 只列原版客户端（退出兼容时用），并同时列出 `conn_attempt` 里出现过、但 `device` 表里没有的 id（`b_id` 配 `b_version`；`a_device_id` 非空时配 `a_version`），标注"仅见于会合"。输出注明：从不发心跳、也从没参与过连接的设备统计不到。
- `strategy show [<device>]`（列出生效选项和 rev）、`strategy set <device|'*'> <key> <value>`、`strategy unset <device|'*'> <key>`（写成墓碑 `''`，让客户端删掉这个键）、`strategy forget <device|'*'> <key>`（删行，不再下发这个键；设备级删掉后回到全局值）、`strategy repush <device|'*'>`（递增 epoch）
- `device pin-relay <device> <host|none>`
- `relay status`（控制台 `rs`）、`route test <ipA> <ipB>`（控制台 `tg`）
- `geo lookup <ip>`（直接读本地 mmdb：国家、经纬度、ASN、运营商组）、`geo update`（走控制台 `gu`，由服务进程执行下载、校验和热切换并回显结果；连不上控制台即服务没在运行时，才在命令行进程里直接下载，不做目录清理）
- `stats [--days N]`：中继回落率和各结果计数（§8）
- `import rustdesk-api <db 路径> [--dry-run]`（§15）
- 名字校验：用户名、组名、簿名不能为空；用户名最长 128 字节（登录接口拒绝更长的名字）；共享簿名唯一且不能是 `My address book` 或 `Legacy address book`。
- 命令行不新建数据库：`DB_URL` 指向的库文件不存在时报错退出（提示到服务的工作目录下运行或设置 `DB_URL`；只有文件确实不存在才这样报，库文件存在但访问不了时（例如权限不足）如实报出路径和原因），写操作在输出末尾打印所用数据库的绝对路径。在错误目录下运行不会悄悄写进一个服务看不到的新库。
- `relay status`、`route test`、`geo lookup`、`geo update` 不读写数据库：不要求库文件存在，也不打开它（不执行迁移），在任何目录下都能运行。

## 15. 从 rustdesk-api 导入（`src/import.rs`）

- 只读打开 rustdesk-api 的 SQLite，按笔记 05 §8 的 SQL 读取（下面写明的地方除外）；Porta 库里已有用户时拒绝执行（只支持往空库导入一次）。`--dry-run` 只打印将导入的数量、冲突和被丢弃的数据。
- 导入：用户、用户组和成员、个人簿、共享簿、授权规则、条目、标签、设备归属（`peers.user_id`，可选）。令牌、登录日志、审计不导入。导入在一个事务里完成，结束时打印所用密钥文件的绝对路径。
- 用户：`username→name`、`nickname→display_name`、`email→email`、`remark→note`，avatar 丢弃。`status` 为 1 → 1，其他值（rustdesk-api 的 2=禁用）→ 0；`is_admin` 用 `CAST(is_admin AS INTEGER)`，非 0 → 1。`created_at` 按 `%Y-%m-%d %H:%M:%S%.f%:z` 解析成 unix 秒，NULL 或解析失败用导入时间；其余表的时间一律用导入时间。建立旧 user id → 新 id 的映射。用户名为空或超过 128 字节（§14，登录接口拒绝更长的名字）的用户不导入，写进报告；和其他没导入的用户一样，他们名下的个人簿、共享簿、条目、标签、授权规则一并丢弃，设备照常导入但不设归属。
- 密码：以 `$2a$`/`$2b$`/`$2y$` 开头的原样写入；恰好 32 位 `[0-9a-f]` 的写成 `md5:` + 原值；空串写 `''`；其他无法识别的非空值写 `''`。密码为 `''` 的用户（含只能靠 OAuth/LDAP 登录的）照样导入，打印清单，提示用 `user passwd` 设密码。登录时按 §11 升级。
- 用户组：组 = `groups` 表的行 ∪ `users.group_id` 里出现过、`groups` 表却没有的 id；后者建占位组 `rustdesk-api-group-<旧 id>`，`share_devices=0`。`groups.type=2` → `share_devices=1`。成员按 `users.group_id` 导入（每人一个组）。组名重复时第二个起追加 `-<旧 id>` 改名并打印。
- 授权规则：**不用笔记 05 §8.3 的展开 SQL**（它把组规则展开成个人规则，违背 §12.2），换成两条，都按 MAX 去重：
  - 个人规则 → `ab_rule.user_id`：`SELECT r.collection_id, r.to_id, MAX(r.rule) FROM address_book_collection_rules r JOIN address_book_collections c ON c.id=r.collection_id AND c.user_id=r.user_id JOIN users u ON u.id=r.to_id WHERE r.type=1 AND r.rule BETWEEN 1 AND 3 AND r.to_id<>c.user_id GROUP BY r.collection_id, r.to_id`
  - 组规则 → `ab_rule.group_id`（映射后的组 id）：`SELECT r.collection_id, r.to_id, MAX(r.rule) FROM address_book_collection_rules r JOIN address_book_collections c ON c.id=r.collection_id AND c.user_id=r.user_id WHERE r.type=2 AND r.rule BETWEEN 1 AND 3 GROUP BY r.collection_id, r.to_id`。`to_id` 既不在 `groups` 表、也没有用户用这个 `group_id` 的，在 rustdesk-api 里本来就不起作用，跳过并写进报告。
  - 笔记 05 §8.3 的"被丢弃的规则"报告 SQL 照用。
- 条目：写进 `ab_peer.data` 的键名一律用客户端 `Peer.fromJson` 的键：`username`、`hostname`、`platform`、`alias`、`rdpPort`、`rdpUsername`、`loginName`（字符串），`forceAlwaysRelay`（字符串 `"true"`/`"false"`）；不写 `same_server`、`online`、`note`。密码和哈希加密后存。
- 清洗：`CAST(tags AS TEXT)` 后解析，`null`/坏数据 → `[]`，只保留字符串元素；重复条目、重复标签、孤儿标签按笔记 05 的规则处理；共享簿重名、或叫 `My address book`/`Legacy address book` 时改名并打印。
- 设备（可选，来自 `peers`）：按 `MIN(row_id)` 去重；`user_id` 为 0 或映射不到 → NULL；`hostname/os/username/version/uuid` 原样；`first_seen_at`、`last_seen_at` 取 `last_online_time`，为 0 时用导入时间；`last_ip` 取 `last_online_ip`；`sysinfo` 留 `''`。导入时 `device` 表里已经有的行（服务启动后设备心跳写进来的）保留原数据，只补上空着的 `user_id`，并在报告里列出这类设备的数量。

## 16. 测试与验收

- 构建、测试都在 Linux 测试机上跑（`cargo build`、`cargo test`）。每个模块要有单元测试；行为以笔记里的客户端代码为准，不以 rustdesk-api 为准。
- HTTP 契约测试：用 axum `Router` + 临时 SQLite（`tower::ServiceExt::oneshot`，骨架提供测试辅助），逐条断言 §9.1 的约定（状态码、Content-Type、空 body、字段类型），以及地址簿权限、级联、写接口边界、心跳下发规则（含：sysinfo 已存在时响应里没有 `sysinfo` 键；`modified_at` 是 JSON number）。
- 会合测试：在回环地址上起真实监听，模拟客户端做 KeyExchange（v0 和 v1 都测）后发 `PunchHoleRequest`，断言 v6 地址被转发、强制中继时被清空、选中的中继符合路由规则（可参照客户端 `src/common.rs` 里的 `rendezvous_stub` 测试写法）。
- 第一期验收（部署后由维护者用原版客户端做）：登录、地址簿、设备列表、审计正常；被控端本地写死的中继能被远程清掉；中继按双方位置选择；控制端勾选 IPv6 后两端都有 IPv6 时能直连。

## 17. 工程约定

- 如非必要，勿增实体：不加兜底代码、没人要的配置项、防御性检查；校验只针对会变的东西（用户输入、外部数据、下载的库文件）。
- 新依赖选发布满两周的版本；能用已有依赖就不加新的。
- 提交信息用中文，直接 `git commit`（签名身份已自动配置）；每个模块做完再提交，不 push，由主会话统一推送。
- 工作区保持 LF（本仓库设了 `core.eol=lf`）。
