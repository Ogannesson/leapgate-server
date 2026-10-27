# leapgate-server：Leapgate 的服务端（第一期实施契约）

本仓库是 `rustdesk/rustdesk-server@873230e` 的**硬分叉**（不再合并上游，安全修复手工摘取），作为子模块挂在总仓库 `leapgate` 的 `server/` 下。总体方案见总仓库 `docs/architecture.md`，本文件是第一期（服务端）写代码时要遵守的契约：范围、模块边界、表结构、配置、各模块的行为规则；第三期的服务端改动验收后按代码的最终行为并入（设计记录在总仓库 `docs/第三期实施契约/`）。上游的 `AGENTS.md` 规则（不引入 `unwrap()`/`expect()`、不做纯格式化改动）照样适用。

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

第三期加了：
- **Leapgate 上报路径和设备签名**（`/api/leapgate/v1/`，第三期实施契约 01 块，§9.5）。Leapgate 客户端的心跳、sysinfo、被控端审计改走这条路径，每个请求用设备私钥签名，第一次验签通过就锁定这台设备的公钥；原版客户端照走 §9.3 的兼容接口。
- **路由第二级**（第三期实施契约 02 块，§7 第二级）：Leapgate 客户端测到各中继的 TCP 建连耗时，随 Leapgate 心跳上报；选中继时某一端有可用的实测就整端代替估算。
- **自研 ICE 的信令和 STUN**（第三期实施契约 05，§6 第 10、11 条）：Leapgate 控制端在上游路径之外再跑一条自研 ICE。服务端在加密的 21116 TCP 上转发两端的候选（转给被控端的 OFFER 加密给它锁定的设备公钥、再用会合私钥签名），在 21116/UDP 上回 STUN Binding 并附反射地址证明，控制端补报的结果记进 `ice_result`（§8）。

第四期加了（设计记录在总仓库 `docs/第四期实施契约/01-服务端出口目录.md`）：
- **出口目录与授权**（§12.4）：Leapgate 被控端在签名心跳里报 `exit`（此刻接受出口登录），只放内存；Leapgate 控制端凭用户令牌取"此刻能用的出口"列表（自己名下的，加命令行授权给本人或所在组的）。目录只是建议，不是关口，连接照旧由被控端的出口开关和上游认证决定。
- **设备主人加固**（§11）：已锁定公钥的设备，登录不再覆盖已有主人，延迟补绑只认锁定之前签发的令牌；命令行 `device owner` 由运维指定主人。
- hbbr 仍不改逻辑，只调部署参数（§5 末尾）。

不做（第一期）：OIDC 和第三方登录、邮箱验证码和 TOTP、Web 管理后台、路由第二级（客户端测速；第三期做，见 §7 第二级）、TCP 注册（走代理/WebSocket/禁 UDP 的被控端原版就显示离线，维持现状）、修改 ID（`RegisterPk.old_id`）、`HttpProxyRequest`（API 经 21116 回落）、WebRTC 信令转发、转发 `udp_port`（UDP 打洞）（第三期起直连走自研 ICE，这两项继续不做）、心跳下发 `disconnect`、`audit/conn/active`、`PUT /api/audit`、旧版地址簿 `GET/POST /api/ab`，以及总方案第 4 节列的全部"明确不做"。hbbr（`src/relay_server.rs`）不改逻辑；Leapgate 客户端的测速依赖它对非 `RequestRelay` 首帧静默关闭（§7 第二级）。

## 2. 代码布局与文件归属

平铺在 `src/` 下，和上游文件并列。第一期并行开发时，每个模块只改自己名下的文件；共享文件只由骨架阶段修改，并行阶段确需改动（例如加依赖）时单独提交、在汇报里说明。

| 文件 | 内容 | 归属 |
|---|---|---|
| `Cargo.toml`、`Cargo.lock`、`src/lib.rs`、`src/main.rs` | 依赖、模块声明、入口（服务模式 / 命令行模式分派） | 骨架 |
| `migrations/0001_init.sql` | 全部表（§4） | 骨架 |
| `migrations/0002_*.sql`、`migrations/0003_*.sql` | 只加、换索引（§4.2） | 设备 |
| `src/conn_limit.rs` | 会合端口和 21114 共用的连接数限流：总数加每来源（§6 第 8 条、§9.4） | 会合 |
| `src/api/listen.rs` | 21114 的 accept 循环：连接上限，请求头、整请求、读写无进度超时，写下限（§9.4） | API |
| `src/state.rs` | `AppState`：进程内共享的句柄（§3） | 骨架 |
| `src/config.rs` | `leapgate.toml` 解析（§5） | 骨架 |
| `src/database.rs` | 连接池、迁移、hbbs 原有的 peer 查询 | 骨架 |
| `src/auth.rs` | 密码哈希/校验、令牌生成/哈希/反查 | 骨架 |
| `src/strategy.rs` | 生效选项与版本号计算（§10），设备模块和命令行共用 | 骨架 |
| `src/crypto.rs` | 密码字段加密（§13） | 骨架 |
| `src/api/mod.rs` | axum 路由表、通用响应和请求体解析、Bearer 认证提取器、静态说明页 | 骨架 |
| `src/rendezvous_server.rs`、`src/kx.rs`、`src/peer.rs`、`src/common.rs` | 会合逻辑和挂钩（§6） | 会合 |
| `src/router/` | 路由第一级、健康检查、GeoIP 加载与更新（§7） | 路由 |
| `src/router/measure.rs` | 第三期：路由第二级的测量表（每台设备最近一轮测量，只在内存，§7 第二级） | 第三期 02 |
| `migrations/0005_route_legs.sql` | 第三期：`conn_attempt.route_a_ms`、`route_b_ms`（§4.2、§8） | 第三期 02 |
| `src/conn_tracker.rs` | 连接结果记录与统计（§8） | 结果记录 |
| `src/api/account.rs`、`src/api/group.rs` | 账号接口、组面板（§9.2、§11、§12.3） | 账号 |
| `src/api/ab.rs` | 地址簿 12 个接口（§12） | 地址簿 |
| `src/api/device.rs`、`src/api/audit.rs` | sysinfo、心跳下发、审计（§9.3、§10）；第三期加 Leapgate 心跳和审计（§9.5） | 设备 |
| `src/api/devauth.rs` | 第三期：Leapgate 路径的签名头解析、验签提取器 `SignedBody`、防重放表、首次锁定、响应签名（§9.5） | 第三期 01 |
| `migrations/0004_device_signing.sql` | 第三期：`peer.pk_pinned_at`（§4.2） | 第三期 01 |
| `src/ice_stun.rs` | 第三期：21116/UDP 上的 STUN Binding 解析和响应、FINGERPRINT、反射地址证明（§6 第 11 条） | 第三期 05 |
| `src/ice_signal.rs` | 第三期：ICE 候选的编码和过滤、会话表、FORWARD 的加密和签名、`forced_relay` 判据、§2.13 的固定文字（§6 第 10 条） | 第三期 05 |
| `migrations/0006_ice_result.sql` | 第三期：`ice_result` 表（P-A，§4.2、§8） | 第三期 05 |
| `src/api/exit.rs` | 第四期：出口目录接口 `GET /api/leapgate/user/v1/exits` 和可用判据 `available`（§12.4） | 第四期 01 |
| `migrations/0007_exit_grant.sql` | 第四期：`exit_grant` 表（§4.2、§12.4） | 第四期 01 |
| `src/cli/`、`src/import.rs` | 命令行与导入（§14、§15） | 命令行 |

骨架实现的 `Router`（只按配置列表轮询）和 `ConnTracker`（各挂钩方法为空操作）是能跑的最小版本，让会合模块在并行阶段就能调用和测试；路由、结果记录模块再替换内部实现，不改签名。骨架阶段为后面各模块建好空文件和函数签名（`todo!()` 只允许出现在并行模块名下的文件里，且不允许留到合并后），并行模块在签名内实现。签名需要调整时，改动方在汇报里写清楚，由集成阶段统一。

依赖由骨架一次加齐，并行模块不改 `Cargo.toml`：`axum` 0.8、`argon2`、`bcrypt`、`md-5`、`sha2`、`maxminddb` 0.32（`mmap`）、`toml`、`flate2`（GeoIP 解压，之前当死依赖删了）、sqlx 补 `migrate` 特性，dev 依赖 `tower`（`ServiceExt::oneshot`）。版本选发布满两周的。之后审查轮次补的：`hyper`（`server`、`http1`）、`hyper-util`（`tokio`、`service`）改为直接依赖，`tower` 从 dev 依赖挪进正式依赖，用于 21114 自写的 accept 循环（axum 0.8 的 `serve` 不给 hyper 配 timer，请求头超时不生效，§9.4）；这三个都是 axum 已经在编译的同一份，没有引入新包。

上表的"归属"是第一期并行开发时的分工；之后的审查修复按问题分组派活，不再受它约束。

删掉：`src/mod.rs`（孤儿文件）、`database::tests::test_insert`（出错不报、等于空跑，`peer_roundtrip` 已覆盖）、`common::check_software_update`（向 RustDesk 官方外呼）。

## 3. 进程结构与共享状态

- 入口 `main.rs`：第一个参数是已知子命令（§14）时进入命令行模式，否则照原样解析 hbbs 参数、启动服务。
- `RendezvousServer::start_with_bind` 自己建 tokio 运行时；API（axum）、路由健康检查、GeoIP 更新、结果记录的落库任务都在这个运行时里 `spawn`。
- `AppState`（`Clone`，内部全是 `Arc`/池句柄），同一份交给 `RendezvousServer` 和 axum：
  - `db: SqlitePool`（主池，§4.1）
  - `pm: PeerMap`（原有，在线状态 = 内存里有且 `last_reg_time` 不到 30 秒，笔记 02 §2.5；`io_loop` 查库写库用自己的会合池，连接任务的查库走主池，§4.1）
  - `router: Arc<Router>`（替代原来每个 clone 一份的 `relay_servers`/`relay_servers0` 快照，笔记 02 §1.6、§3.5）
  - `tracker: Arc<ConnTracker>`
  - `secret: Arc<SecretBox>`（§13）
  - `cfg: Arc<Config>`
  - `sk: Option<Arc<sign::SecretKey>>`：`get_server_sk` 的结果，KeyExchange、`IdPk` 签名、Leapgate 路径的响应签名（§9.5）和转给被控端的 ICE OFFER 签名（§6 第 10 条）共用这一份（第三期从 `RendezvousServer` 的 `inner.sk` 挪进来）。`-k` 传的是公钥时为 `None`。
- 模块自己的小状态（登录失败计数、审计 nonce 去重表、第三期 Leapgate 路径的防重放表、ICE 会话表、反射地址证明的内存密钥）放在模块内的 `static`，不进 `AppState`。
- `PeerMap` 条目上第三期多了两项内存状态：`pinned`（库里 `pk_pinned_at` 的副本，只用来省掉注定失败的写库，以库为准，§6 第 7 条）和 `leapgate_hb`（最近一次验签通过的 Leapgate 心跳的时刻、Leapgate 版本和第四期的 `exit`，只存内存，条目被淘汰就丢，下一次心跳整条重写；ICE 用它判被控端支不支持：新鲜度 180 秒、版本不低于 0.3.1，§6 第 10 条；出口目录用它判出口可不可用，§12.4。新鲜度是两者共用的常量 `peer::LEAPGATE_HB_FRESH`）。
- Leapgate 新增的代码（路由、结果记录、API、GeoIP、新表）里，IP 在比较、查库、落库前先规范化：`::ffff:a.b.c.d` → IPv4（`to_canonical()` 或 `try_into_v4`）。原版会合逻辑里已有的地址处理保持原样（`same_intranet`、`update_addr`/`RegisterPk` 的 ip 比较、`peer.info.ip` 落库、`tcp_punch` 的键），也不要在 accept 处统一改写地址，否则同公网 IP 的设备拿不到局域网直连，或升级后每台设备都被判成"IP 变了"。

## 4. 存储

### 4.1 连接池与迁移
- 主池 `sqlx::SqlitePool`（API、命令行、后台任务用）：WAL、`synchronous=NORMAL`（提交不等 fsync，只有 checkpoint 才刷盘；不会损坏库，掉电最多丢最后几个事务）、`busy_timeout` 5 秒、`foreign_keys` 打开，池大小 `MAX_DATABASE_CONNECTIONS`（默认改为 8），取连接最多等 3 秒（sqlx 默认 30 秒；API 被灌时宁可几秒内失败，审查 C-21）。路径仍是 `DB_URL`，默认 `./db_v2.sqlite3`。
- 会合池：`PeerMap` 单独一个池，连同一个库（`database::rendezvous_pool`，由 `AppState::new` 建）：2 个连接，取连接最多等 200 毫秒，`busy_timeout` 200 毫秒，其余设置同主池。只有 `io_loop` 用它（`RegisterPk` 的查库和写库），API 请求和 21116/21118 的连接任务都不碰它，所以 `io_loop` 不和任何未认证请求排同一个公平队列（审查 C-21/C-11：API 被灌时，`io_loop` 每查一次库就要排几秒，UDP 收包和三个 TCP 端口的 accept 一起卡住；审查 D-15：连接任务的查库洪水同样能把它卡住）。连接任务那边：`RelayResponse`、`PunchHoleSent`、`LocalAddr` 给 B 的 pk 签名只查内存（B 刚收到转发的请求，在线就一定在内存里；不在内存里就不签）；`PunchHoleRequest` 要区分 `OFFLINE` 和 `ID_NOT_EXIST`，目标不在内存里时经主池查库（`PeerMap::get_from_main`），和 API 请求在主池里排队。等不到就放弃这次处理，客户端下一轮注册会重试；查库失败不能当成"没有这个 id"（§6 第 7 条）。
- WAL 的上界（审查 D-11）：SQLite 自带的自动 checkpoint（`wal_autocheckpoint`）是 PASSIVE 的，读写一直交叠时（多个来源灌上报接口）总有读者停在旧快照上，日志永远回绕不了，`-wal` 只增不减（实测约 1.8 GB/分钟，主库始终不到 1 MB，停灌后也不回收）；而且它由每个超过 1000 页的提交触发，被灌时总有一个占着 checkpoint 锁，别的 checkpoint 一试就失败。所以：
  - 两个池都设 `wal_autocheckpoint=0`（关掉自动 checkpoint）和 `journal_size_limit` 64 MB（日志回绕时把 `-wal` 截回这个大小；SQLite 默认 -1，永不缩）。
  - 服务进程里只有一个 checkpoint 者：后台任务（`database::spawn_checkpoints`，由 `AppState::spawn_tasks` 启动）每 5 秒先跑一次 `PRAGMA wal_checkpoint(PASSIVE)`，再跑一次 `PRAGMA wal_checkpoint(TRUNCATE)`。PASSIVE 不挡写者，先把能拷的帧拷进主库并 fsync；TRUNCATE 拿写锁、拷完剩下的帧（只有这几百毫秒里新写的）、等还停在日志上的读者退出（之后来的读者直接读主库），把 `-wal` 截成 0 字节。只跑 TRUNCATE 时它要在写锁里拷几秒的积累并 fsync，实测挡写者中位 0.5 秒、最长 2 秒，会合写库因此失败；先跑 PASSIVE 后中位 60 毫秒、最长 0.37 秒（debug 构建，每秒约 2400 次审计写入，测试机磁盘）。
  - 它用自己的一个连接：不占会合池的 2 个连接，也不在主池里排队（主池被灌时取连接要等最多 3 秒，`busy_timeout` 5 秒）。它的 `busy_timeout` 是 50 毫秒：等写锁、等读者期间它挡着写者，所以要远短于会合池的 200 毫秒写锁等待；等不到就保留已拷的部分、下一轮再来，每分钟最多打一条 warn。拿到写锁以后拷帧和 fsync 的时间不受这个限制，慢盘上可能超过 200 毫秒，这时撞上的会合写库失败、客户端下一轮重试（只换 IP 的重新注册不受影响，§6 第 7 条）。
  - 命令行不跑这个任务，退出前（命令成功或失败都一样）在自己的池上跑一次 `PRAGMA wal_checkpoint(PASSIVE)`，再关闭连接池（审查 E-2/E-11：只 drop 池不等连接关完，关闭时的 checkpoint 和进程退出赛跑，`-wal` 每次都留下、越跑越大，只拷主库常拿到报"损坏"的库；只关池也不够，几个连接同时关闭时都拿不到独占锁，都跳过 checkpoint）。服务没跑时，这次 PASSIVE 把全部帧拷进主库并 fsync，主库单独拷走也完整。`-wal` 未必删掉（关闭时的 checkpoint 仍可能被并发关闭的连接跳过）：没删掉时下次打开会重放它、接着往后写，所以连续几次没删掉时它每次多几 KB，直到某次关闭时删掉或服务启动后被任务截断（实测连跑 20 次 `user add`：主库单独拷走 20 次都完整，`-wal` 删掉 9 次、最大 48 KB；修复前 20 次都没删、从 294 KB 单调涨到 447 KB，主库单独拷走 3 次报损坏、其余缺最近几次写入）。服务在跑时 PASSIVE 不挡写者，拷不完的留给服务的任务。不用 TRUNCATE：命令行池的 `busy_timeout` 是 5 秒，服务在跑时它等读者期间一直占着写锁，会合写库会因此失败。
- 磁盘上界：主库文件按各表的上限核算（`peer` 表 §6 第 7 条，`conn_attempt` §8，`device` 和审计表 §9.3，地址簿 §12.1）；`-wal` 另计，约为两次 checkpoint 之间（5 秒多）的写入量：上面的洪水下峰值约 160 MB（修复前同样的洪水 3 分钟涨到 5.6 GB），停灌后回到 0。写入速率越高峰值越大（大致按每秒写入量 × 5 秒 × 每次写入的页数算）；只有 checkpoint 一直拿不到锁时它才会继续长，这时每分钟有一条 warn。
- 迁移用 `sqlx::migrate!("./migrations")`（编译期嵌入文件，不需要数据库），服务和命令行启动时都执行。原来 `create_tables` 里的 `peer` 表 DDL 挪进 `0001`，保留 `if not exists`，这样能直接接管已有的 hbbs 数据库。
- 全部用运行时 `sqlx::query()`，不用编译期宏。
- 迁移文件必须是 LF（校验和按字节算）。已发布的迁移不再修改，第一期合并前可以直接改 `0001`。
- `0001` 的注释写于改名之前（项目 2026-10-24 由工作名 Porta 改名为 Leapgate）：里面的 `PORTA.md` 就是本文件，章节号不变（§4.2 表结构、§8 连接结果记录）；`device.client_type` 注释里的取值 `'porta'` 现在写作 `'leapgate'`。注释也算进校验和，改了会让已建库的实例启动时迁移校验失败，所以照旧保留。
- 时间一律存 unix 秒（`integer`），`conn_attempt` 按笔记 02 用毫秒。

### 4.2 表结构（`migrations/0001_init.sql` 照此实现，列名、类型、约束不得自行改动）

下面是 `0001` 的原样；之后的迁移除 `0004`、`0005` 加列、`0006`、`0007` 加表外只动索引，现行索引以迁移文件为准：
- `0002`：三张审计表各加 `created_at` 索引（保留期删除，§9.3）；`device_user` 换成 `device_user_seen(user_id, last_seen_at)`。
- `0003`：`audit_conn_session` 换成 `audit_conn_session_dev(session_id, device_id, conn_type)`（备注更新，§9.3）；`audit_conn_dev` 换成部分索引 `audit_conn_open(device_id, conn_id) where closed_at is null`（认证成功和 close 上报找未关闭的记录，§9.3）；加部分索引 `device_owned_seen(last_seen_at, user_id, id) where user_id is not null`（设备表淘汰）；`token_user` 换成 `token_user_device(user_id, device_id)`。
- `0004`（第三期）：`alter table peer add column pk_pinned_at integer`，锁定时间（unix 秒），NULL 表示未锁定。放 `peer` 不放 `device`，因为 `device` 行会被淘汰。笔记 02 预留的 `token.device_verified` 没加（第三期没人读写，等签名登录设计时再加）。
- `0005`（第三期）：`conn_attempt` 加 `route_a_ms real`、`route_b_ms real`：选中中继两段的延迟（毫秒，未乘权重），实测还是估计看 `route_reason`（§8）。`route_reason` 的取值因此多了 `rtt`、`rtt_a`、`rtt_b`（§7）。每行多约 16 字节，§8 的行大小估算不变。
- `0006`（第三期 05，P-A）：新表 `ice_result`，自研 ICE 的结果，一行一次 ICE（控制端补报的 RESULT，或会话"放弃"），不认证、只作统计，和 `conn_attempt` 分开记、不按 IP 硬合并。不存 session（每次随机、对统计没用；"只认第一条"由会话表挡住）；和 `conn_attempt` 按 `a_ip + b_id + at` 对照。写入、上限和修剪见 §8。

  ```sql
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
  ```
- `0007`（第四期 01）：新表 `exit_grant`，除主人以外谁能在出口目录里看到这台设备（§12.4），一行授权给一个用户或一个组，照 `ab_rule` 的二选一约束和两个部分唯一索引写。删用户、删组靠外键级联（连接池开着 `foreign_keys`）。`device_id` 不引用 `device`，也不进 §9.3 的淘汰条件：设备行被淘汰时授权不丢，设备再上报、重建行后目录照常列出。不加过期时间、授权人、创建时间列，也不加按 `user_id`、`group_id` 查的索引（表很小，目录查询扫全表）。服务端回退到第三期二进制之前，要先删掉 `exit_grant` 表和 `_sqlx_migrations` 里 0007 那一行（sqlx 拒绝"库里执行过、程序里没有"的迁移）。

  ```sql
  create table exit_grant (
    device_id text not null,
    user_id   integer references user(id) on delete cascade,
    group_id  integer references user_group(id) on delete cascade,
    check ((user_id is null) <> (group_id is null))
  );
  create unique index exit_grant_user  on exit_grant(device_id, user_id)  where user_id is not null;
  create unique index exit_grant_group on exit_grant(device_id, group_id) where group_id is not null;
  ```

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
  client_type   text not null default 'rustdesk',  -- 'rustdesk' | 'leapgate'
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
- Leapgate 自己的结构化配置放在 `leapgate.toml`：路径取参数 `--leapgate-config`（环境变量同名规则照 `get_arg`），默认工作目录下的 `leapgate.toml`；文件不存在就全用默认值。改了要重启。
- 中继列表：`leapgate.toml` 里有 `[[relay]]` 就用它；没有就用 `-r` 的列表（权重 1，无覆盖）。控制台 `rs a,b,c` 仍可在运行时临时替换。载入时只去掉空串和重复项，**不做 DNS 过滤**（不用原版 `get_servers` 里的 `test_if_valid_server`）：解析不了的主机由健康检查判为不可达，恢复后自动回到候选里。

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

**hbbr 部署参数**（第四期 E3，只改部署、不改代码）：
- 只加一个环境变量 `SINGLE_BANDWIDTH=256`：每对中继连接的限速，单位 Mb/s（这里 1 Mb = 2^20 bit），两个方向合计，默认 128。其余参数用默认值：`TOTAL_BANDWIDTH` 1024（整个进程所有会话合计）、`LIMIT_SPEED` 32、`DOWNGRADE_THRESHOLD` 0.66、`DOWNGRADE_START_CHECK` 1800 秒。
- 降速规则保留：会话从配对起算的平均速率超过 0.66 × 256 ≈ 169 Mb/s、且会话已超过 30 分钟时，降到 32 Mb/s，到会话结束不恢复。
- 变量名一律写全大写加下划线：本仓库 `873230e` 的 `get_arg` 不分大小写、横线下划线通用，但已发布的官方镜像 1.1.15、1.1.16 只认这一种写法。值必须大于 0，设 0 不能关掉限速，会回到默认值（`relay_server.rs` `check_params`）。
- 生效时机：随第一期部署那次 hbbr 重启生效。重启后在 hbbr 启动日志里核对 `SINGLE_BANDWIDTH: 256Mb/s` 这一行；同时把 hbbr 镜像钉到具体版本标签，不用 `latest`。
- 不做：只给出口会话放宽（hbbr 配对只认 uuid，看不到连接类型）、月流量机制。想少用贵的中继，用现成的 `[[relay]] weight`（§7）。

## 6. 会合模块（`rendezvous_server.rs` 等）

改动都按"只加挂钩、不重写流程"做，行为和原版保持一致，除非下面明确要求。
1. **KeyExchange v1**：21116/TCP 每条连接 accept 后、有 `sk` 时先发 `KeyExchange`（v1：签名的临时公钥 + `signed_params`），读第一帧：是 `KeyExchange` 且 `keys.len()==2` 就建立加密，之后收发都加解密；第一帧不是 `KeyExchange` 就按明文 `RendezvousMessage` 处理。写半边存进 `tcp_punch` 时要带上加密器（`Sink` 改型）。完整步骤和客户端测试里的服务端替身见笔记 02 §6.2。21118（WebSocket）**不做** KeyExchange、服务端也不先发：客户端 `use_ws()` 时 `secure_tcp`/`secure_tcp_required` 都直接跳过（客户端 `src/common.rs` `secure_tcp_impl`），`Sink::Ws` 不带加密器。`sk` 为 None（`-k` 传的是公钥）时，启动时打一条 error 日志："没有私钥，无法做 KeyExchange，登录过的客户端会连接失败；请用 `-k -` 或 `-k <base64 私钥>`"。
2. **IPv6 信令转发**：按笔记 02 §6.5 的表补 `socket_addr_v6`（以及 `PunchHole` 的 `force_relay`、`PunchHoleResponse` 的 `upnp_port`）。不转发 `udp_port` 和 WebRTC 字段；直连另走 ICE 的独立信令（第 10 条）。hbbs 强制中继（`ALWAYS_USE_RELAY` 或 mask 异或）时清空转发的 v6 地址并置 `force_relay`（笔记 02 §6.4）。
3. **路由挂钩**：`handle_punch_hole_request` 里调 `router.select(&RouteQuery{a_ip, b_ip, a_id, b_id, a_token, conn_type}).await`，`a_id` 是 `PunchHoleRequest.leapgate_from_id`（第三期，字段号 1000，发起方自报的设备 ID，不认证；超过 253 字节当空串），只用来查 A 的第二级测量（§7）；选中中继两段的延迟随结果记录写进 `conn_attempt`（§8）。`RelayResponse` 分支和控制台 `tg` 也改调 router（`RelayResponse` 的 `a_id`、`b_id` 都传空串）。新增控制台命令 `gu`：让路由模块立即执行一次 GeoIP 下载/重新加载并回显结果（§14 `geo update` 用）。`io_loop` 的中继定时器分支、`Data::RelayServers` 删掉，健康检查挪进 router（笔记 02 §3.5）。控制台 `rs` 无参数时打印 `router.status_text()`。
4. **结果记录挂钩**：H1~H5 五处调用 `tracker`（笔记 02 §4.4），只取字段、不阻塞（tracker 内部用通道异步落库）。
5. 修掉控制台 `aur` 把中继列表清空的那一行（笔记 02 §3.4）。
5a. 21118（WebSocket）只在 TCP 对端是回环地址时才信任 `X-Real-IP`/`X-Forwarded-For`，否则用 TCP 对端地址（原版对任何来源都信任，直连 21118 就能伪造来源 IP，影响按 IP 选中继、限流和记录；笔记 02 §5）。反向代理和 leapgate-server 同机部署时行为不变；这时反代转发到 21118 的 location 必须覆盖 `X-Real-IP`（和 21114 同一条硬性部署要求，见 §10），否则客户端自带的头会被原样采信。
6. 删掉 `check_software_update` 及其调用。
7. 注册语义不改（`UUID_MISMATCH` 逻辑、每来源每分钟 30 次和每天 300 个新 id 的限额、mask/local_ip、`test_hbbs` 自检照旧），只补边界（审查 A-1/A-5/A-10）：
   - `RegisterPk` 进任何分支之前先校验：`pk` 必须正好 32 字节（客户端发的是 ed25519 公钥 `Config::get_key_pair().1`），`uuid` 非空且不超过 96 字节（客户端发 `get_uuid()`：机器 id，Windows/macOS 36 字节、Linux 32 字节，没有时用 32 字节公钥；96 是 API 那边 128 字节 base64 的原始长度，能注册的设备一定能通过 §9.3 的 uuid 校验）；不合格的静默丢弃：不回包、不写库、不打日志。
   - `IP_BLOCKER` 按来源计数：IPv4 按地址，IPv6 按 /64（和 §8 的 `source_key` 一致；双栈套接字上的 `::ffff:a.b.c.d` 先还原成 IPv4）。控制台 `ib <地址>` 输入任一地址都能查到它所在的来源。检查分两步：先查每来源每分钟约 30 次；查明是新 id（`PeerMap` 和库里都没有）后，再查每来源每天 300 个新 id（超出回 `TOO_FREQUENT`，和原版一样）和全局上限，都通过才把 id 记进该来源的集合。已存在的 id 不进集合。天窗口固定从建条目或上次清空时算起，到期清空，所以所有来源的集合合计不超过一天的全局上限（20 × 1440 个）。
   - `IP_BLOCKER` 最多 65536 个条目（来源）。满了以后，没有条目的新来源不建条目、不受每来源限额，直接交给全局新 id 上限（有意 fail-open，库的增长由全局上限兜住），每分钟最多打一条 warn。
   - 全局新 id 上限：所有来源合计每分钟最多 20 个新 id，超出的丢弃、不回包，每分钟最多打一条 warn。个人部署一天新增的设备只有个位数，批量部署时客户端会在后续注册周期里重试。已知 id 不受影响。
   - 库里的 `peer` 行不做自动清理（表里没有最后在线时间）：持续被灌时每天最多新增约 2.9 万行（20 × 1440）。
   - `RegisterPk` 的 id 不在内存里时要查库：查库前先过一个全局令牌桶（每秒 200 次、突发 1000 次），超出的静默丢弃（不回包、每分钟最多一条 warn）。被丢的客户端下一轮 `RegisterPeer` 会再被要求 `RegisterPk`（审查 C-12）。
   - 查库出错不等于"没有这个 id"（审查 C-22/U-1）：`PeerMap::get`（会合池）和 `get_from_main`（主池）返回 `Result<Option<_>>`。`RegisterPk` 出错就丢包，不进新 id 检查、不建条目；TCP 打洞请求不回包。`get_pk` 只查内存，不在内存里就返回空、不签名（审查 D-15）。确认库里没有才在内存里建空条目（`insert_new`），不再查第二次库。
   - `update_pk` 先写库、成功后才改内存，写库失败时内存条目保持原样；`RegisterPk` 回真实结果，写库失败回 `SERVER_ERROR`（客户端只记一行日志，下一轮重试）。不能回 `UUID_MISMATCH`：客户端收到它会换一个新 id（rustdesk `rendezvous_mediator.rs` `handle_uuid_mismatch` → `Config::update_id`）。插入撞上 id 唯一索引（查库之后别处加了这个 id，比如命令行导入）时，从库加载这一行、回 `SERVER_ERROR`，客户端重试时按库里的 uuid 判断。例外是只换了 IP 的重新注册（条目有 guid，uuid、pk 都和内存里的一样，审查 D-12）：先改内存（`socket_addr`、`last_reg_time`、`info.ip`），再写库，写库失败只打一条限频日志、照样回 OK。这里没有 U-1 要防的情况（内存里的 uuid、pk 本来就是库里的），而先写库的话，库写不进时换了 IP 的在线设备要晚 15 秒（客户端下一轮注册）才在新地址上可连，连续失败会显示离线。库里留着旧 IP 的后果只是条目被淘汰后再加载时又判一次"IP 变了"、重写一遍。
   - **公钥锁定**（第三期，§9.5）：`peer.pk_pinned_at` 非空的 ID 只认库里那把公钥。锁定后只换 IP 的重新注册照常接受；同 ID、新 uuid、同公钥照旧回 `UUID_MISMATCH`；换公钥一律被拒。上面"不能回 `UUID_MISMATCH`"的例外就是这一种：锁定的设备本就该被拒，客户端随即换成随机 ID，要保住原 ID 得先在服务端解除锁定（§14 `device key reset`）。
     - 库这一层守住：`Database::update_pk` 是 `update peer set id=?, pk=?, info=? where guid=? and (pk_pinned_at is null or pk=?)`（最后一个参数是新公钥），返回影响行数。内存里的 `pinned` 只是副本，不管调用方手里的条目是什么状态，换公钥的写库在库里锁定时都影响 0 行。
     - 写库影响 0 行（两个分支都算，含只换 IP 的分支）统一走 `PeerMap::unwritten`：按库重载条目；库里有行就是被锁定挡下，回 `UUID_MISMATCH`（限频 warn）；行已经不在（`device key reset --forget` 删了），从内存移除条目、回 `SERVER_ERROR`，客户端下一轮按新设备注册；重载查库失败回 `SERVER_ERROR`。只换 IP 的分支不再对已删的行回 OK（否则这个条目会一直回 OK、库里却没有行）。
     - `RegisterPk` 在 uuid 判断之前先看内存：条目 `pinned` 且公钥不同时，内存可能落后于库（`device key reset` 只改库），所以不直接按内存回 `UUID_MISMATCH`，而是先扣全局查库令牌桶（上面那条的每秒 200 次，扣不到就丢包、不回包，每分钟最多一条 warn），再按库重载这个条目：仍锁定在别的公钥上回 `UUID_MISMATCH`；库里已解锁就照常走后面的注册规则；行已不在就移除条目、回 `SERVER_ERROR`；查库失败丢包。不在扣不到预算时退回"按内存回 `UUID_MISMATCH`"：管理员解锁后内存可能还没跟上，回它会让客户端换 ID。
   - `io_loop` 里的 5 分钟定时器（和 `handle_udp` 串行，不会插进 `RegisterPk` 的查找和 `update_pk` 之间）：`IP_BLOCKER` 清空天窗口到期的集合，删掉分钟窗口已过且集合为空的条目；`IP_CHANGES` 删掉 360 秒前开始的记录；`PeerMap` 删掉 `last_reg_time` 超过 24 小时的条目。被淘汰的设备回来时，下一次 `RegisterPeer`（只查内存）会被要求重新 `RegisterPk`，`RegisterPk` 再从库里加载条目、照常校验 uuid，受每来源每分钟约 30 次的限额；淘汰时间取 24 小时，是为了让过夜离线的设备不走这一轮（审查 C-3：一个出口后面的上百台机器早上一起回来，要分几分钟才能全部在线）。只存在内存里的 `socket_addr`、`last_reg_time`、`reg_pk`（6 秒内的注册计数）对闲置一天的设备都没有意义，在线判断本来就要求 `last_reg_time` 在 30 秒内。TCP 侧的 `get` 从库里加载条目时只在内存里没有时才插入，不覆盖已有条目（审查 C-25）。
   - 日志不打 uuid/pk 原文，只打 id、来源 IP 和长度。未认证、每个包都能触发的日志（info 及以上）一律用 hbb_common `throttled_log!`，每分钟最多各打一条：uuid 不匹配、ip/pk 不匹配、许可证不符的 `PunchHoleRequest`、`RegisterPeer` 的 "IP change"、`update_pk` 的几行，以及会合模块查库、写库失败（审查 A-5、C-1/C-7/C-8/C-17）。攻击者给的 id 先截到 253 字节（按字符边界），再用 `{:?}` 打（转义换行和控制字符，免得一个 id 伪造出整行日志，审查 D-2/D-21）：TCP 打洞请求的 id 不校验长度，最长一帧。以后在这类路径上加日志照此办理。
   - 查库、写库仍在 `io_loop` 里做：有了上面的上限，写库次数有界；每次最多等会合池的 200 毫秒取连接加 200 毫秒写锁（§4.1）。会合池只有 `io_loop` 用，取连接不随 API 或连接任务的负载变长；写锁和所有写者共用（包括 §4.1 的 checkpoint），最多等 200 毫秒。
   - STUN（第三期 05，第 11 条）也在 `io_loop` 里处理：不查库、除发送外不 await，但会被这里的写库停顿拖慢（每次最多约 0.4 秒）；FORWARD 走 UDP 发送队列，同样要等 `io_loop`。客户端那边 Binding 有两次重发、OFFER 有一次重发兜住。
8. 会合端口的资源上限（审查 A-2/A-3/A-4；常量写死，不做配置）：
   - 帧长：21116/TCP 单帧和 21118/WebSocket 单条消息、单帧最多 16 KB（最大的合法消息是带 WebRTC offer 的 `PunchHoleRequest`：新客户端不带候选，约 1 KB；老客户端带全部候选，几 KB）。21115 单帧最多 128 KB：`OnlineRequest` 客户端不分批，界面把当前标签页的全部 id 一次发出（`peers_view.dart` `_queryOnlines` → `client.rs` `query_online_states_`）；地址簿每本最多 5000 台，即使每个 id 16 个字符也只有约 90 KB。超过帧上限的连接直接断开。
   - `OnlineRequest.peers` 超过 16384 条（128 KB 按每个 id 至少 6 字节加 2 字节标签和长度能放下的条数）的整条丢弃，不回包。
   - WebSocket：握手 10 秒超时；握手完成前最多读 8 KB，超过就断开（tungstenite 握手阶段自己最多缓冲 64 KB，每读一次都从头重新解析；客户端和同机 nginx 转发的升级请求只有 1~2 KB，审查 C-2）；读缓冲 4 KB（tungstenite 默认每条连接预先分配 128 KB）。
   - 并发连接：21116、21118 各最多 2048 条，21115 最多 256 条；每个端口上每个来源（IPv4 地址 / IPv6 /64）最多 32 条，回环来源只计入总数（同机反代承载所有 WSS 客户端）。超限的连接在 accept 后直接关闭，21116 上不发 KeyExchange、不做签名；每分钟最多打一条 warn。
   - 最坏情况下的缓冲（审查 C-2/C-15/C-27，按 Linux 实测修正）：21116 每条约 26 KB（`Framed` 写缓冲 8 KB + 读缓冲涨到 16 KB 一帧 + 任务），合计约 53 MB；21118 握手完成前每条最多 8 KB + 4 KB 读块，握手后每条约 4 KB 读缓冲 + 16 KB 帧 + 最多 16 KB 正在拼接的分片消息，合计约 74 MB；21115 每条约 136 KB，合计约 35 MB；三者合计约 160 MB。攻击结束后 glibc 不会把峰值 RSS 还给系统，选部署机时按峰值留余量。另有 `PUNCH_REQS`（默认最多 10 万条，约 21~45 MB），只记录带对 key、目标在线的打洞请求，不算在上面。
   - 发往 UDP 的消息（转发给 B 的 `PunchHole`、`RequestRelay` 等）进一个最多 4096 条的有界队列，连接任务不等、队列满了就丢弃（每分钟最多一条 warn），`io_loop` 卡住时内存不随攻击带宽增长。`RequestRelay` 不校验任何东西就转给 B，所以：每条连接最多 12 条，超过就断开（客户端每次尝试一条，最多 3 次）；转发时只带客户端会设的字段（`id`、`uuid`、`relay_server`、`secure`、`conn_type`、`switch_code`，加服务端填的 `socket_addr`），`uuid`、`switch_code` 截到 64 字节、`relay_server` 截到 253 字节，不带 `licence_key`；控制端的 `token` 只用于服务端记连接、不转给 B（第四期决策 A3，2026-10-27），记录前同样截到 64 字节；`PunchHoleRequest` 转发的 `socket_addr_v6` 超过 18 字节（`AddrMangle` 编码的 IPv6 地址长度）就清空（审查 C-13）。
   - 自研 ICE（第三期 05，第 10、11 条）用到的资源都由已有上限或下面的常数兜住，不另设配置：

     | 东西 | 上限 | 兜在哪 |
     |---|---|---|
     | ICE 会话表 | 每来源（规范化后的 `source_key`）8 条，含已应答、留到 A 关连接的；全表不另设上限：一条连接最多登记一个，21116 并发连接最多 2048 条 | `Sessions::register`，满了 `REJECT{BUSY}` |
     | 每次 ICE 的信令 TCP | A 一条（活到 RESULT 或被竞速取消，正常 1~3 秒，最长约 16 秒；A 不关时 30 秒空闲读超时）、B 一条（发一条消息就关；B 为 ICE 同时开的最多 8 条） | 计入上面每来源 32 条并发 |
     | 转给 B 的 FORWARD | 和其它 UDP 下发共用 4096 条有界队列，满了丢；每条连接的 OFFER 最多转发 2 次（第一次加一次重发，`ICE_OFFER_SENDS`） | `send_udp` |
     | STUN 令牌桶 | 每秒 1000、突发 1000，全局；被灌满时那一刻所有人都拿不到映射地址和证明，只剩 host 候选 | `RendezvousServer.stun` |
     | 反射地址证明密钥 | 进程启动时随机、只在内存；重启后旧证明全部失效 | `ice_stun::PROOF_KEY` |
     | 会话条目的清理 | 被拒的当场删；其余随 A 的连接结束删，不设过期 | `drop_for_reject`、连接结束时 `close` |
     | `ice_result` 行 | 每来源 60 行/分钟、全局 120 行/分钟（和 `conn_attempt` 同样取值、单独计数）；90 天保留 + 20 万行封顶 | 复用 `conn_tracker` 的限额写法、写库队列和每小时修剪（§8） |

     `LookupBudget` 泛化成带速率和突发的通用令牌桶后有两份，各自取值：`lookups`（`RegisterPk` 查库，每秒 200、突发 1000，第 7 条）和 `stun`（上表）。两份都只在跑 `io_loop` 的那个实例上用，连接任务的克隆不碰。
9. **局域网多候选地址**（第三期，leapgate-cardo `375e2a3`）：`handle_local_addr` 把 `LocalAddr.leapgate_local_addrs`（字段号 1000，`repeated bytes`，Leapgate 被控端报的物理网卡局域网地址，`AddrMangle` 编码）原样放进发给控制端的 `PunchHoleResponse{is_local}` 的同名字段。只做限长，不解码、不打日志：超过 18 字节（`AddrMangle` 能编出的最长值，IPv6 地址 16 字节加 2 字节端口；IPv4 最多 11 字节）的丢掉，剩下的取前 8 个（Leapgate 客户端最多报 8 个）。原版客户端不发这个字段，响应和原来一样。用途和客户端两侧怎么用见 `client/LEAPGATE.md` §3。
10. **自研 ICE 的信令**（第三期实施契约 05 §2.3~§2.7、§3.3、§3.4；`ice_signal.rs`，`rendezvous_server.rs` 的 `handle_ice`）。A 是控制端，B 是被控端。消息挂在 `RendezvousMessage.leapgate_ice`（oneof 1000），`ver` 必须是 1。
    - **只在完成了 KeyExchange 的 21116 TCP 上收**（`handle_tcp` 新传 `encrypted`）：WebSocket（21118）和明文连接上收到任何 `LeapgateIce` 都不回包、直接断开；21116/UDP 上收到的丢掉；FORWARD 变体只由 S 发，收到就断开。
    - **OFFER**（A 新开的信令连接上的第一条）按顺序检查，第一条不过的决定 `REJECT` 原因，用这条连接自己的 sink 当场回、然后断开：① 格式（`session` 16 字节；`id` 非空、不超过 253 字节、不含 0x00；`licence_key` 照打洞的写法；ufrag 4~32、pwd 22~64 个 ice-char；候选、证明各不超过 16 条，候选都能解码）→ `BAD`；② B 在线（只查内存，`last_reg_time` 30 秒内）→ `OFFLINE`；③ 不强制中继（`ice_signal::forced_relay`，和打洞同一个函数）→ `RELAY`；④ B 支持 ICE（`leapgate_hb` 180 秒内、版本不低于 0.3.1、`pinned`、S 有私钥、B 的公钥能转成 X25519）→ `UNSUPPORTED`；⑤ 名额（A 的来源先 `try_into_v4` 再取 `source_key`，表里不满 8 条；session 已在表里按 ① 的 `BAD`，同一次加锁里判）→ `BUSY`。`BAD` 打限频日志，其余不打。
    - **候选过滤**：OFFER 用 A 的证明、ANSWER 用 B 的证明，同一个 `ice_signal::filter`：私网 IPv4、ULA 保留；公网 IPv4 必须有一条能打开、地址和端口都相等的证明；全局 IPv6 没证明的只留前 2 个；回环、链路本地、组播、`100.64/10`、`198.18/15`、`fdfe:dcba:9876::/48`、`::ffff:0:0/96` 等去掉；同地址只留第一条。证明只在 S 核对、不转发。过滤后为空也照常转发。
    - **FORWARD**（S → B，只走 UDP，发往 B 最近一次注册的地址）：`{session, 过滤后的 A 的参数}` 序列化后用 sealed box 加密给 B 锁定的设备公钥（Ed25519 转 X25519，转不了回 `UNSUPPORTED`，绝不退回明文），再用会合私钥对 `"leapgate-ice-offer-v1\0" ‖ B 的 ID ‖ 0x00 ‖ ts（8 字节大端）‖ sealed` 签名；外层只有 `ts`、`sealed`、`sig`，链路上看不到 session、A 的地址和口令。新域前缀和会合私钥签的其他四种东西互不为前缀，`msg` 解析不成 `IdPk`（测试钉住）。
    - **会话表**（进程级 static `ICE_SESSIONS`，std `Mutex`，锁里不 await，sink 先取出、出锁再发）：OFFER 全过才登记，持有 A 的 sink、缓存的 FORWARD、B 的 ID、A 的规范化地址；判重、判名额、插入在一次加锁里，只在成功时取走 sink；这条连接 `return true` 保住。一条连接最多登记一个 session，之后同一连接上相同 session 的 OFFER 是重发：按登记时的 B 的 ID 重读 B 的地址，原样再发缓存的同一份 FORWARD（B 按 FORWARD 去重），每条连接最多发 2 次，其余忽略。
    - **ANSWER**（B 新开的加密连接，发一条就断开）：session 在表里且未应答才处理，否则忽略；参数和证明按 OFFER 的规则检查和过滤，不合规给 A 发 `REJECT{BAD}`、删掉条目；`get_pk`（只查内存）为空给 A 发 `REJECT{UNSUPPORTED}`、删掉条目；都过了才标"已应答"、取出 A 的 sink，给 A 发过滤后的参数加 S 签过的 B 的 `IdPk`。不按来源 IP 校验 ANSWER（B 的 TCP 和 UDP 可能走不同出口），凭的是只在密文里出现的 session。B 的 **REJECT**：session 在表里且未应答就原样转给 A、删掉条目。
    - **条目和 A 的信令连接同寿**：被拒的当场整条删除、不记统计；其余留到 A 的连接结束（A 发完 RESULT 或收到 REJECT 后自己关、被竞速丢掉、出错、30 秒空闲读超时），在 `handle_listener_inner` 结尾删除。没有过期、没有全表上限（第 8 条）。
    - **RESULT**（P-A，A 在同一连接上补报，不认证、只作统计）：只认这条连接自己登记的 session、只认第一条，记一行 `ice_result`（§8）；`ver` 不对、session 不对、第二条一律忽略、连接保住。登记过、没被拒、连接结束时还没收到 RESULT 的，记一行 `abandoned`（被竞速取消或 A 异常退出）。
11. **STUN 和反射地址证明**（第三期实施契约 05 §2.8、§2.9.3、§3.2、§3.4.3；`ice_stun.rs`）。
    - `handle_udp` 在 `parse_from_bytes` 之前分流：长度不少于 20、首字节 0x00 或 0x01、偏移 4~8 是 magic cookie `21 12 A4 42` 的交给 `handle_stun`。protobuf 消息的首字节是字段标签，不会是 0x00/0x01（不能照搬客户端"最高两位为 0"：`RegisterPeer` 是 0x32）。
    - 只回 Binding 请求：前两字节 `00 01`、`20 + 长度字段 == 数据报长度`、长度字段是 4 的倍数、**整报不短于 100 字节**（客户端用 PADDING 凑够），不看属性内容。STUN 手写最小编解码，不引入 `stun_codec`。
    - 回包是 Binding 成功响应：原样带回事务号，XOR-MAPPED-ADDRESS（规范化后的来源，`try_into_v4`）→ `LEAPGATE-PROOF`（0xC1E9）→ FINGERPRINT（`crc32fast`），IPv4 来源 72 字节、IPv6 来源 96 字节，**放大比严格小于 1**（含 IP/UDP 头 0.78 和 0.97）。所以 leapgate-server 不是通用 STUN 服务器，上游的 `ice-servers` 不能指向它。回包发往原始来源地址，只走 `FramedSocket::Direct`；发送失败 `allow_err!` 记下，不用 `?`（`handle_udp` 返回错误会让 `io_loop` 重建整个 21116/UDP socket）。
    - 令牌桶每秒 1000、突发 1000，全局（`RendezvousServer.stun`），不计入 `IP_BLOCKER`；耗尽时丢包，每分钟最多一条 warn。
    - 证明：版本(1) ‖ ts（u32 大端）‖ 地址族(1) ‖ 地址(4|16) ‖ 端口（u16 大端）‖ `crypto_auth`（HMAC-SHA512-256）的前 16 字节，共 28 或 40 字节。密钥是进程启动时随机生成的模块 static，不落盘；有效期 30 秒（`ts ≤ now` 且 `ts ≥ now − 30`）。`open` 先判长度和地址族字节，再常数时间比较 MAC（`sodiumoxide::utils::memcmp`，截短的 MAC 不能用 `auth::verify`），再判版本和时间、解码地址（端口非 0、地址非未指定）。证明说明"S 30 秒内亲眼看到这个 UDP 地址，而且对方收到了回包"，所以公网 IPv4 候选必须带它（第 10 条），防有人让 B 往第三方地址发检查。

## 7. 路由（`src/router/`）

- 接口：`async fn select(&self, q: &RouteQuery<'_>) -> RouteDecision { relay: String, reason: &'static str, a_ms: Option<f64>, b_ms: Option<f64> }`。返回单个中继字符串（原版客户端只认一个）；空串语义照旧（被控端退回"hbbs 主机:21117"）。`reason` 取值为 `fixed`（固定中继）、`rtt`（两端都用实测，第二级）、`rtt_a`/`rtt_b`（只有 A 或只有 B 用实测）、`geo`（双方都有位置）、`geo_a`/`geo_b`（只有 A 或只有 B 有位置）、`rr`（轮询）、`none`（没有配置中继）。`a_ms`/`b_ms` 是选中中继两段的延迟（毫秒，未乘权重；实测还是估计看 `reason`），`fixed`、`rr`、`none` 和没有值的那一段为 `None`。
- 固定中继：每次调用按 `b_id` 查一次 `device_policy.relay_pin`（主键查询，不缓存），所以命令行 `device pin-relay` 写库后下一次连接就生效。有固定中继时直接用它，不看健康状态（运维的明确意图）。`b_id` 为空串时跳过这一步。查库失败时当作没有固定中继，日志按 §6 第 7 条限频、id 截断后用 `{:?}` 打（每条打洞请求都会走到这里，审查 D-19）。中继列表、健康状态、GeoIP 都在内存里。
- 候选：健康检查判为可达的中继。
- 代价：`cost(R) = (rtt(A,R) + rtt(B,R)) × weight(R)`，取最小。`rtt` 按笔记 06 §4：大圆距离 × 2 × `detour` / 200 km/ms，加每段的跨运营商组、跨境惩罚；`multi_bgp` 的中继不算跨运营商。
- 回退：有位置的候选按代价排序、取最小；没有位置的中继不参加排序。一方位置未知时用 `2 × rtt(已知方, R) × weight(R)`。只有双方位置都未知，或候选里一台有位置的都没有时，才在全部候选里轮询。私网、回环、链路本地、ULA 来源地址按 `server_location` 算，`100.64/10` 当作未知（笔记 06 §5.2）。
- 惩罚的精确算法：运营商组键统一用字符串，内置表里有的用组名，没有的用 `AS<号>`；配置里的 `carrier` 可写组名或 `AS<号>`。跨运营商惩罚只在一段两端国家相同时计算，取该国覆盖值，没有覆盖用全局值；任一端组未知不加。跨境惩罚取两端国家覆盖值里较大的，都没有覆盖用全局值；任一端国家未知不加。`[[relay]]` 和 `server_location` 的覆盖按字段生效，空串或不写等于不覆盖：中继没覆盖的字段仍然查库，`server_location` 没写的字段视为未知。
- 中继位置：配置覆盖优先，否则解析主机名后查库。启动时、每次换库热切换后、`rs` 替换中继列表后都重新计算；DNS 解析失败或库里查不到就当作没有位置，下一轮健康检查时再试，不当成永久结果缓存。客户端 IP 不做缓存，每次直接查 mmap。
- 健康检查：配置载入时（启动、控制台 `rs` 替换）把全部中继视为可达；之后每 3 秒对每台中继做一次 TCP 建连（3 秒超时），只有一台也要查；记录是否可达和建连耗时；某一轮全部失败时保留上一轮的可达集合（和原版一致）。
- GeoIP：`maxminddb`（开 `mmap`），文件名规则见 §5。没有库时路由退回轮询，不阻塞启动。
  - `source = "dbip"` 且 `auto_update`：启动后在后台检查、此后每天检查一次。want = 当前 **UTC** 年月；本地 city 和 asn 都 ≥ want 就跳过。否则下载 `dbip-{city,asn}-lite-YYYY-MM.mmdb.gz`；当月 404 时，本地没有库或本地库比上月还旧才下载上月，本地已有上月文件就保持不动、次日再试。解压到 `*.part`、用 maxminddb 打开并抽查几个 IP 通过后原子改名并热切换。下载用已有的 `reqwest` + `flate2`（笔记 06 §3）。
  - `source = "manual"`：每天检查一次两个文件的 mtime，变了就按同样的打开、抽查流程重新加载并热切换；抽查失败保留旧库。每次加载都先把文件复制成私有副本、映射副本，运维用 cp、curl -o 原地覆盖文件也不会让进程因 SIGBUS 崩溃。副本放在服务工作目录下的 `.leapgate-geoip/<文件名>`（和数据库、密钥文件同处，服务一定能写；先写临时名 `<文件名>.part` 再改名），不放在 `geo.dir` 里：`geo.dir` 可以是 geoipupdate 的 root 目录或只读挂载，服务对它只读不写。
  - 清理：服务进程启动时删除残留的 `*.part`（dbip 在 `geo.dir` 里，manual 在 `.leapgate-geoip/` 里）；热切换成功后删除旧月份的 mmdb（删不掉就忽略，下次启动再删）；任何一步失败都删掉本次的 `*.part`，保留旧库，次日重试。只有服务进程做清理。
  - 命令行 `geo lookup` 按同样的规则找文件，不写任何文件：dbip 直接映射（这些文件只会被改名替换），manual 读进内存（不做私有副本）。
- 每次决策打一行 debug 日志：双方国家/运营商组、候选代价、选中的中继和 `reason`。
- 运营商组：内置中国三大运营商的主要 ASN 表（写代码前到 bgp.he.net 或 PeeringDB 核对），查不到时按"ASN 相等算同组"。不用 AS 名称做字符串匹配。

### 第二级（第三期，`measure.rs`、`cost.rs`）
设计依据是总仓库 `docs/第三期实施契约/02-路由第二级.md`（下称"契约 02"），这里按代码的最终行为写。Leapgate 客户端在服务进程里测到每台候选中继的往返（每台 3 次取最小，约 5 分钟一轮），随 Leapgate 心跳上报（§9.5）；服务端选中继时，某一端有可用的实测就用实测代替这一端的估计。客户端测速和真实中继连接走同一条路，不计握手，计中继关连接（2026-10-25 起，总仓库 `docs/第三期实施契约/02a-修订草案-TUN下的测速.md`；此前计 TCP 建连耗时）。上报格式和取值范围没变，服务端不因此改动。
- **测速依赖 hbbr 的一个行为**：`src/relay_server.rs` 的 `make_pair_` 收到能解析但不是 `RequestRelay` 的首帧（或解析不了的）就直接返回、关掉连接，不打日志、不查 key、不进 `PEERS`。客户端连上后发一个长度为 0 的帧，量到这次关连接。改 `relay_server.rs`、从上游摘取 hbbr 修复，或部署时换用别的 hbbr 版本（官方镜像 1.1.15、1.1.16 和本仓库的 `make_pair_` 逐字相同），都要确认这一点没变。改成等到 30 秒超时，客户端会把所有中继判成 `down`，服务端按"全 `down` 时忽略"退回估计；改成打日志，每台设备每 5 分钟会多出 3 × N 行。
- **下发的列表**：配置里的全部中继（含健康检查暂判不可达的）的前 32 台（`MAX_PROBED`）原串，和 `PunchHole.relay_server` 下发的是同一个字符串。超过 32 台时启动（和 `rs` 替换）打一条 warn：第 33 台起永远没有实测，它可达时两端都退回估计，等于第二级失效。版本号 `rev`：对"这些原串用 `\n` 连起来 + `\n` + 测速间隔（常量 300 秒，`PROBE_INTERVAL_SECS`）"做 sha256，取法同 §10 的策略 `rev`（`strategy::digest_rev`）；重启后同一份配置算出同一个 rev，`rs` 换了列表就变。`rev` 和列表放在同一把锁下，读到的总是配对的。
- **测量表**（`Measurements`，只在内存，不落库）：键是 Leapgate 心跳**验签得来**的设备 ID（伪造不了别人的测量），每台存最近一轮：列表版本、测量时刻（收到时刻 − `age_s`，不依赖两边时钟）、按列表下标排的每台结果（`Rtt(ms)` / `Down` / `Unknown`）。一条约 ID + 32 × 4 字节。
  - 写入：`probes` 形状不对（`routing_rev`、`age_s` 缺失或类型不对，`rtt` 不是"字符串 → 整数"，`down` 不是字符串数组）、`routing_rev` 不是当前版本、`age_s > 900` 的整轮丢弃，只打 trace，心跳照常处理。`rtt` 的键必须逐字等于列表里的原串、值在 1~10000，否则这一台留 `Unknown`；`down` 同样只认列表里的原串；同一台两边都有时以 `rtt` 为准。
  - 删除：Leapgate 心跳不带 `probes`（显式的 `null` 同样算不带）时当场删掉这台的记录（`Router::forget_probes`）。客户端在手里没有当前列表的有效一轮时省略它，例如：作废了一轮（契约 02 §4.2 第 4 步，作废时客户端同时清掉旧结果），最近一轮已超过 900 秒，服务进程刚启动、首轮还没跑完，刚换到新列表、新列表的首轮还没跑完，开了 Socks5 代理、WebSocket 或没配 Key。不删的话旧记录要等 15 分钟才过期，这段时间按开代理之前的延迟选路（2026-10-24 端到端发现，最初的实现漏了这一条）。代价：客户端服务进程重启后，第一次心跳就删掉服务端里还没过期的旧测量，首轮测完、下一次心跳上报之前（约 15~60 秒）这台按估计值选路；旧测量可能来自换网之前，删掉更稳妥。`probes` 带了但被上一条丢弃时不删旧记录；心跳没发出去（断网）时服务端什么也收不到，旧记录照常保留到过期。
  - 上限 1 万台（`MAX_MEASURED`，同 `device` 表）。已有这个 ID 就覆盖；满了先删所有过期的，仍满就删测量时刻最老的一条。不需要定时清理。
  - 读出：版本不是当前的、或测量时刻超过 15 分钟（`MEASURE_TTL`）的视为没有。`decide` 在一次加锁里取 A、B 两份。
- **整端替换**（`cost::score`）：
  1. 一端"用实测"的条件：这一端有可用的测量，并且对当前**每一台可达候选**都不是 `Unknown`。不满足就整端用估计。
  2. 用实测的一端标 `Down` 的中继从这一对的候选里去掉；去掉后一台不剩时，忽略这一端的 `down`、把它当作"不用实测"。先处理 A，再在 A 留下的候选上处理 B（A 只留下 B 标 `Down` 的中继时，B 退回估计）。
  3. 每台候选的一段：用实测的一端取实测值，否则取第一级的估计；代价沿用第一级：两段都有 `(a + b) × weight`，只有一段 `2 × 那一段 × weight`，都没有不参加排序。所以没有位置的中继在实测端也有值，和有位置的中继混排。
  4. `reason`：两端都用实测 `rtt`，只有 A `rtt_a`，只有 B `rtt_b`，都不用时同第一级（两端都没位置返回 `None` 走轮询）；一端用实测时即使两端都没位置也有代价，不轮询。
  5. 选中那台的两段放进 `RouteDecision.a_ms`/`b_ms`。
  - 固定中继仍然最先判断（`b_id` 非空时查 `device_policy`）。
- **两端的 ID**：B 的 ID 就是打洞请求的目标 ID；A 的 ID 来自 `PunchHoleRequest.leapgate_from_id`，不认证。A 冒用别人的 ID 只影响 A 自己这次连接的选路，不影响别人；但冒用者能从选路结果侧面推断被冒用设备到各中继的相对延迟，以及它最近一次心跳是否带了完整测量（也就是是否在线，在线时是否正在代理或 TUN 后面、刚重启；作废的一轮会让记录当场消失，粒度是一个心跳周期），被冒用的设备察觉不到。信息量不超过直接向它打洞拿到的公网 IP，接受。不把测量绑定到心跳的来源 IP：HTTP 和 21116 本来就可能从不同出口出去（例如路由器透明代理只代理部分流量）。原版客户端不发，A 段按估计。
- **`RelayResponse` 分支不走第二级**：那里 `a_id`、`b_id` 都是空串（只在 B 回报的中继等于 hbbs 自己的 `local_ip` 时才调路由）；它也不遵守固定中继，是第一期就有的问题（已知，未排期）。
- `relay status`（控制台 `rs`）末尾多一行 `measurements: <N> devices, <M> fresh`（表里的设备数、其中现在可用的数）。`route test --a/--b`（控制台 `tg` 的第 3、4 个参数）见 §14。

## 8. 连接结果记录（`src/conn_tracker.rs`）

- 按笔记 02 §4.4 实现：内存跟踪器（键 `try_into_v4(A:p1)`、`(A 公网 IP, B id)`、`try_into_v4(A:p3)`），每 5 秒扫一遍把到期的记录定稿写入 `conn_attempt`，定稿规则照笔记，下面几条是对笔记的补充和更正。热路径（H1~H5）只做内存操作，不 await 数据库。
- `a_user`/`a_device_id`：H1 只把 `PunchHoleRequest.token` 原串存进内存记录，反查放在后台（定稿写库时）调 `auth::token_owner`（async）；`a_user` 存 `user.name`，`a_device_id` 存 `token.device_id`；未登录或令牌已失效时两者都是 NULL。第三期不用不认证的 `leapgate_from_id` 填 `a_device_id`，也不另存它（契约 02 D2-1）：用没用上 A 的测量看 `route_reason`。
- `route_reason`、`route_a_ms`、`route_b_ms`（第三期，迁移 0005）：H1 时路由模块的 `reason`、`a_ms`、`b_ms`；`forced_relay` 时 `relay_offered` 被改成 `local_ip`，这三列仍记路由模块的原判断。重复请求合并进同一行时，三列和 `relay_offered` 一起跟着"B 回答之前最近一次成功的请求"走。
- `outcome` 取值全集：`rejected`、`no_reply`、`relay`、`relay_or_v6`、`relay_failed`、`relay_unmatched`、`direct_lan`、`direct_tcp`、`direct_tcp_or_v6`。
- 窗口（命名常量，标注"待实测"）：直连判定窗口 `W = max(45 秒, 6 × (reply_at − started_at) + 20 秒)`（A 的直连超时 = 打洞耗时 × 6，没有封顶；客户端的打洞耗时还包含连 hbbs 和 KeyExchange 的时间，hbbs 看不到，20 秒余量约能覆盖 3 秒，实测时要专门覆盖慢建连）；H5 匹配时要求 `RequestRelay` 落在 `reply_at + W` 以内；一条记录最多合并 3 次 `RequestRelay`（客户端最多回落 3 次），而且只在它第一次 `relay_req_at` 之后 60 秒内合并，超出的另起一条 `relay_only`；匹配到 `RequestRelay` 的记录，等最后一次 `relay_req_at` + 20 秒后才定稿，那时有 `relay_resp_at` 记 `relay`，没有记 `relay_failed`。
- H5 没匹配到打洞记录：写一行 `signal='relay_only'`：`started_at`、`relay_req_at` 取收到的时刻；`a_ip`/`a_port` 取 A:p3；`via` 照实；`b_id = rf.id`；`conn_type`、`a_nat_type`、`a_force_relay`、`a_has_v6`、`server_forced_relay` 填 0；`a_user` 照常反查。有 `relay_resp_at` 记 `relay_unmatched`，没有记 `relay_failed`。
- 防滥用（这些请求都不认证；常量写死，不做配置）：许可证不符（`LICENSE_MISMATCH`）的请求不记录，所以不会出现 `signal='fail_license'`；`b_id`、中继地址和 `a_device_id`（来自令牌行，登录时已限长，§11）截到 253 字节，版本号、令牌、uuid 截到 64 字节；同一来源每分钟最多新建 60 条记录（IPv4 按单个地址算，IPv6 按 /64 前缀算：一台主机至少分到一个 /64），所有来源合计每分钟最多新建 120 条，超出的丢弃并计数（被丢弃的不占两种额度）；写库队列最多 1 万条，满了丢弃并计数，这几种丢弃每分钟最多打一条 warn 日志；队列里的定稿记录成批（每批最多 1000 条）在一个事务里写入；每小时删除一次 `started_at` 早于 90 天的行，并且只保留最新的 20 万行。上限估算（实测，SQLite 4 KB 页）：最坏的一行（文本列都到截断上限，且带有效令牌、`a_user`/`a_device_id` 非空）记录约 1.6 KB，一页只放得下两行，加上 `idx_ca_b` 索引里 `b_id` 的副本，磁盘上约 2.4 KB；两次修剪之间最多新增 120 × 60 = 7200 行（另加修剪时还没定稿的几分钟记录），所以持续被灌时表最多约 20.7 万行、约 0.5 GB，删掉的页会被复用，文件停在这个大小；不带有效令牌的请求单行约 1.4 KB，约 0.29 GB。90 天删除和修剪共用一个每小时的定时器：前者是 `idx_ca_started` 上的范围删除，多数时候什么都删不到，不值得单开定时器。审计表的保留期（§9.3）也在这个定时器里做（服务启动时先跑一次），每张审计表开删前先停 20 毫秒，和批与批之间一样让出写锁，各表删了多少行合成一条日志，什么都没删时不打；`device` 表和审计表的行数上限在插入时守住（§9.3），不在这个定时器里。
- 统计查询（给命令行）：按时间范围算中继回落率 = count(outcome IN (`relay`,`relay_or_v6`)) / count(outcome IN (`relay`,`relay_or_v6`,`direct_lan`,`direct_tcp`,`direct_tcp_or_v6`))；`rejected`、`no_reply`、`relay_failed`、`relay_unmatched` 不进分子分母，只在分项计数里列出。另列 `relay_offered` 非空、`b_relay` 非空且两者不相等的次数（被控端本地写死了中继）。
- **ICE 的结果另记 `ice_result`**（第三期 05，P-A，迁移 0006，§6 第 10 条）。ICE 和上游路径并行，ICE 胜出时上游那次打洞请求在 `conn_attempt` 里照样按上游信令记成 `relay`、`direct_tcp`、`direct_lan`、`no_reply` 之一，所以**单看 `conn_attempt` 的中继回落率会偏高**，ICE 的实际直连看 `ice_result` 的 `connected`；两张表按"A 的公网 IP + B 的 ID + 时间"对照，不按 IP 硬合并。
  - 一行一次 ICE：A 的 RESULT（`outcome` 用契约 05 §2.13 的小写名字 `connected`、`no_answer`、`bad_answer`、`no_pair`、`kcp_failed`、`secure_failed`；0 值或不认识的数字记 `unknown`），或会话放弃时的 `abandoned`。`elapsed_ms` 取 RESULT 的值（`abandoned` 为 NULL）；`local_kind`、`remote_kind`（`host`/`srflx`/`prflx`）、`family`、`local_net`（`ethernet`/`wlan`/`other`）只在 `connected` 时记，枚举里没有的数字记 NULL。`at` 是 S 记录的时刻，`a_ip` 是规范化后的 A 信令连接地址。
  - 写入复用上面的通道：挂钩 `on_ice_result` 只锁内存、不 await，行进 `TrackerState.ice_results`，5 秒的收尾任务和到期的 `conn_attempt` 记录一起取走、进同一个写库队列（元素是两类），同一个事务里插入。RESULT 不认证，所以有和 `conn_attempt` 同样取值、单独计数的上限：每来源每分钟 60 行、全局每分钟 120 行，超出丢弃计数，和 `conn_attempt` 的丢弃写在同一条限频 warn 里。每小时的修剪也删 `at` 早于 90 天的行、只留最新 20 万行；最坏一行约 350 字节（`b_id` 最长 253 字节），加 `idx_ice_at` 约 80 MB【推测，没实测】。
  - `abandoned` 里混着"被竞速取消"和"控制端异常退出"两种；控制端可以乱报 RESULT，只影响统计，不参与任何决策。

## 9. HTTP API 通则

### 9.1 必须遵守（任何一条写错，原版客户端都会走错分支）
1. **任何接口都不回 5xx**：客户端遇到 5xx 或连不上会改走 hbbs 的 TCP 代理（第一期不做），白等最长 36 秒，心跳也跟着卡住。内部错误：审计接口回 200 + `{"error":"…"}`（客户端会重试）；`/api/currentUser` 回 200 + `{"error":"…"}`（客户端收到 400 会清本地令牌、401 会全部重置，一次临时错误不能把用户登出）；其他接口回 400 + `{"error":"…"}`。handler panic 和整请求超时（§9.4）都按内部错误回，同样遵守这三种分法。例外是第三期的 Leapgate 路径 `/api/leapgate/v1/`（§9.5）：只有 Leapgate 客户端调用，内部错误、超时、panic 回 503。
2. 请求体一律用 `Bytes` 收、自己解析 JSON；不用 axum 的 `Json` 提取器（出错回 415/422 纯文本）。JSON 响应带 `Content-Type: application/json; charset=utf-8`；`SYSINFO_UPDATED` 用 `text/plain; charset=utf-8`；空 body 的响应（sysinfo 403、审计成功、地址簿写接口成功）不要求 Content-Type。axum 自己产生的错误也回 JSON：用错 HTTP 方法回 405 + `{"error":"Method Not Allowed"}`，请求体超过该路由的上限（§9.4）回 413 + `{"error":"Request body too large"}`，审计接口也回 413（客户端对 4xx 直接放弃、对 200 + error 会重试，同一个超大请求体重发没有意义）。
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
`POST /api/sysinfo`、`POST /api/heartbeat`、`POST /api/audit/conn`、`POST /api/audit/file`、`POST /api/audit/alarm`。不带认证（兼容债务），**只接受已在 hbbs 注册过的设备**：`peer` 表里必须有这个 id，body 必须带 `uuid`，且 base64 解码后与 `peer.uuid` 逐字节相等（真实客户端的心跳、sysinfo、被控端审计总是带 uuid）。`peer` 表里没有这个 id、缺 uuid、uuid 不符，以及（第三期）这个 id 的公钥已被锁定（`peer.pk_pinned_at` 非空，§9.5：它已经走签名路径，不签名的上报正是降级攻击要退回的那条路），一律按不符处理：sysinfo 回 403 空 body（客户端 120 秒后重试）、心跳回 `{}`、审计回 200 空 body 但不入库。这个校验只挡住没在 hbbs 注册过的 id，挡不住刻意造设备的人：注册本身不认证，`RegisterPk` 的 id、uuid 都由请求方自定，限流在会合模块（按来源 IPv4 地址或 IPv6 /64 计数，另有全局上限）。所以 `device` 表和审计表的总量靠下面的行数上限兜住，不靠校验。
- 真实客户端的心跳跑在向会合服务器注册的那个进程里，总是先注册再上报；首次心跳偶尔早于注册完成，回 `{}` 后下一次心跳（15 秒后）就会成功。
- id 超过 253 字节（`MAX_PEER_ID_LEN`）或 uuid 超过 128 字节的请求直接按不符处理，不查库。
- 校验是 `device::uuid_matches`，一次查询（`select uuid, pk_pinned_at is not null from peer where id = ?`）返回三态 `Mismatch`/`Match`/`MatchPinned`：三个上报只认 `Match`；登录绑定（§11）`Match`、`MatchPinned` 都算相符。
- 审计请求体的 `id` 是 `serde(default)`：缺 `id` 不再回 400，得到空 ID、按不符回 200 空 body（原版客户端总带 `id`，看不到区别）。
- sysinfo 原文（请求体）超过 8 KB 时同样回 403 空 body（真实 sysinfo 只有几百字节；原文整段存进 `device.sysinfo`）。从中拆出来另存的 `hostname`、`username`、`os`、`version` 各截到 253 字节。
- 按来源限速：心跳、sysinfo、三个审计接口合计，每个来源每分钟最多 1000 次（固定一分钟窗口）。来源取客户端 IP（§10，经本机反代时是 `X-Real-IP`，反代必须覆盖这个头，见 §10 的硬性部署要求），IPv4 按单个地址、IPv6 按 /64 计。1000 的算式：NAT 后面 50 台设备都在会话中，每台每 3 秒一次心跳（空闲时 15 秒一次，每分钟 4 次）= 50 × 20 = 1000 次/分钟，sysinfo 和审计每次会话只有几条，落在不在会话的设备留下的余量里。为什么要限：表满时新建设备行是一个写事务（见下一条），不限速的话一个来源就能让写锁高频翻转，再经 `busy_timeout` 拖慢会合模块的注册写库。超出时：心跳回 `{}`（上游客户端对心跳响应只看键在不在，没有针对状态码或空对象的分支，15 秒后照常再发，rustdesk@bd92623:src/hbbs_http/sync.rs `start_hbbs_sync_async`）；sysinfo 回 403 空 body（120 秒后重试）；审计回 200 + `{"error":"…"}`，客户端当内部错误处理，10 秒、30 秒后重试，nonce 没登记，重试能入库。计数表最多记 65536 个来源（约 3 MB），满了而且没有已结束的窗口时，新来源不限速（同会合模块的 `IP_BLOCKER`：手里有这么多来源的人本来就有这么多份额度）。
- `device` 表最多 1 万行（最坏一行约 10.5 KB，合计约 0.1 GB），在上报新建行时守住，不靠定时清理（审查 C-10/C-18/C-26：原来每小时清理一次，两次清理之间被删的假设备随时能重建，行数只受累计注册数限制）。心跳、sysinfo 和登录绑定（§11）要新建行时，在一个 `begin immediate` 事务里数行数，到了 1 万就按 `last_seen_at` 从老到新删掉可淘汰的行，删到 1 万 - 1 行再插入，通常删一行。只有导入建行不经这道检查；表因此超出上限时，每次新建行最多删 64 行（`EVICT_BATCH`），删掉至少一行就允许插入，行数不会再涨，之后每次新建行再往下收敛（审查 D-7：原来一次删掉全部超额行，有账号的人靠登录建行能把表撑到几万行，一次删除在写锁里要几秒，超过 20 秒的整请求超时就整体回滚，之后每次新建行都重来；实测 64 行 8 KB 的行一批约 1.5~2.5 ms）。插入用 `on conflict do update`，同一设备两次首次心跳并发也不出错。
  - 可淘汰的行：没有主人（`user_id IS NULL`），或者主人在这台设备上已经没有令牌（审查 C-19）；`device_policy` 里有这个 id、或 `strategy_option` 里有 `scope` = 这个 id 的行一律不删（`device_policy` 行来自 `device pin-relay`、`strategy repush`，以及第四期起指定了主人的 `device owner`，§14）。这两张表和 `device` 之间没有外键，删设备行不会连带删掉策略。有主行的边界：登录会绑定任何注册过的 id（注册不认证），但每人最多 50 枚令牌，所以免删的有主行最多 50 × 用户数；靠登录挂到自己名下的假设备，令牌被淘汰后也会变成可淘汰。代价：主人在设备上没有令牌的有主设备，表满时都可能被淘汰，重新建行后没有归属（延迟补绑要找该设备的令牌，§11），要主人到设备上重新登录才能恢复。这包括三种情况（审查 D-8）：从 rustdesk-api 导入的归属（令牌不导入，§15，没人打开界面重新登录的无人值守机器一直没有令牌）；主人执行过 `user passwd` 或被 `user disable` 之后，他名下的全部设备（两者都删掉该用户的全部令牌）；令牌被挤出 50 枚上限的设备（每次登录都新插一枚，不按设备去重，同一台设备反复登录也占名额，所以不一定要真在 50 台设备上登录过）。有令牌的有主设备不受影响。
  - 没有可淘汰行时不建行：心跳照样回有效策略（全局 ⊕ 设备级），但不带 `sysinfo` 键；sysinfo 回 403 空 body（客户端 120 秒后重试）；登录照样成功（令牌照发），只是不建行、不绑定；已经有行的设备照常更新。
  - 被删的设备再上报时重新建行，并因为 `sysinfo = ''` 重新索取 sysinfo（§10）。真实设备每 15 秒心跳一次（`last_seen_at` 最多落后 60 秒，§10），所以正常情况下最老的行是已经不再上报的设备。但上报方能让自己的行一直保持最新（心跳的 `ver` 由上报方自己填，每次换一个就会写 `last_seen_at`），有人故意灌表时，在线的可淘汰设备（无主的，或上面几种没有令牌的有主设备）也可能先被挤掉，丢的是 `first_seen_at`、sysinfo 和那几种设备的归属；连接和策略下发不受影响。
  - 挑最老行不读表里排在 8 KB sysinfo 后面、落在溢出页的 `last_seen_at`（审查 C-16），两支都按 `last_seen_at` 顺序读索引，取够条数就停：无主的一支读迁移 0002 的 `(user_id, last_seen_at)` 索引；有主的一支读迁移 0003 的部分索引 `device_owned_seen(last_seen_at, user_id, id) where user_id is not null`，令牌检查是 0003 的 `token(user_id, device_id)` 索引上的一次查找，最多多读"主人仍有令牌"的有主行（每人最多 50 行），要写 `indexed by`（只有 0002 的索引时优化器对 `user_id IS NOT NULL` 选全表扫描）。审查 D-6：原来有主的一支在 0002 的索引上按 `user_id` 范围扫描后排序全部有主行，逐行回表取 id、逐行查主人的全部令牌；实测（测试机，debug 构建，热缓存）1 万行有主设备、各带 8 KB sysinfo、令牌在最老的 50 台上时，一次 `make_room` 从约 40~90 ms 降到约 0.3~1 ms。
- 审计字段限长：超长的值按 UTF-8 字符边界截断后入库，照样回 200 空 body（不回 400）。`audit_conn` 的 `ip` ≤ 64 字节、`peer_id` ≤ 253、`peer_name` ≤ 256、`note` ≤ 4 KB（不认证的备注请求也一样）、`auth` 只存已知字段 `primary_auth`、`two_factor`（整数）和 `conn_audit_ref`（字符串），序列化后 ≤ 4 KB（超出就截断文本）；请求体里的其他键不展开、不保存（审查 C-9：用通配 map 收"其余字段"时，2 MB 的数字数组在任何身份校验之前就展开成约 80 MB），`peer` 只取前两个元素；`audit_file` 的 `peer_id` ≤ 253、`path`、`info` 各 ≤ 4 KB；`audit_alarm` 的 `info` ≤ 4 KB。`device_id` 就是校验过的 id（≤ 253）。
- 审计表行数上限：三张表各最多 2 万行，每次插入前删掉 id 比最新一行小 2 万 - 1 及以上的行（主键上的范围删除）。不放进每小时的清理：审计上报只按来源限速，合计没有上界，一小时内能写进的行数也没有。实测最坏一行（文本列都到上限，SQLite 4 KB 页，含索引）：`audit_conn` 约 9.5 KB、`audit_file` 约 8.8 KB、`audit_alarm` 约 4.6 KB，2 万 ×（9.5 + 8.8 + 4.6）KB ≈ 0.46 GB。另外每小时删掉 `created_at` 早于 180 天的行：走迁移 0002 的 `created_at` 索引，每条语句最多删 1000 行，删完为止，还要接着删时批与批之间停 20 毫秒（`PURGE_PAUSE`）让出写锁（审查 D-10：等锁的写入者靠 busy handler 按 1、2、5…100 毫秒退避重试，不排队，几乎碰不上两条语句之间几十微秒的空档，不停的话整段积压期间写锁一直被占着，会合模块的写库（只等 200 毫秒）全部失败；实测停 20 毫秒后探测写入全部成功，最长等 79 毫秒。单批本身超过 200 毫秒时，恰好在批中途到达的会合写库仍会失败）（审查 C-16：`created_at` 排在 4 KB 文本列之后，没有索引时每次清理都要在写锁里读遍三张表的溢出页）。

唯一免校验的是控制端会话结束写备注那条 `/api/audit/conn`：判别条件是"有 `note` 键且没有 `uuid` 键"（不能用"没有 nonce"判别，1.4.x 的审计都不带 nonce）。它从不插入新行，所以不会增加行数；但"只更新已有记录"本身不等于没有放大：同一 `(device_id, session_id)` 的记录谁都能造（自注册一个假 id，换着 `conn_id` 发认证成功上报，最多造满 2 万行），不限条数时一条 4 KB 的备注请求要在写锁里把 2 万行整行重写一遍（实测约 1 秒、WAL 涨 177 MB，审查 D-5）。所以一条备注按连接类型分别取：`conn_type` 为 0 远程桌面、1 文件传输、2 端口转发、3 摄像头、4 终端（rustdesk@bd92623:src/server/connection.rs `AuthConnType`，被控端只报这五种），再加上 `conn_type` 为空（认证成功那条上报没带 type，原版客户端都会带；认证上报丢了的记录 `session_id` 是 `''`，备注本来就匹配不到）算一种，每种最多改该会话最新的 4 条记录（`NOTE_ROWS`）。一条语句、每种类型一个子查询、`union all` 合并，每个子查询走迁移 0003 的 `(session_id, device_id, conn_type)` 索引，精确范围倒序读 4 条就停，同一 session_id 挂在别的设备下的记录不会被逐行检查；其他 `conn_type` 值（没有客户端发）的记录永远拿不到备注。不用 `group by conn_type` 或 `conn_type is not 2` 这类写法：它们要读遍整个会话的记录，而这些记录谁都能造满 2 万行。
- 为什么按类型分：一个会话 id 由远程桌面连接和从它工具栏开出的文件传输、摄像头、TCP 隧道、终端共用（rustdesk@bd92623:src/client.rs `ConnToken`），每条连接重连一次多一条记录。原版客户端的 TCP 隧道不走多路复用时（1.4.x，或者任一端不支持），本地每接受一个 TCP 连接就单独连一次被控端、重新登录（rustdesk@bd92623:src/port_forward.rs `listen` 的 `Claim::Legacy`），各占一条同 session_id 的记录，浏览器经隧道访问网页很快就是十几条。不分类型时最新的几条全是隧道记录，远程桌面那条拿不到备注（审查 E-5）。分类型后代价只剩：同一类型超过 4 条记录时（重连，或者上面那种隧道的每个本地连接），这一类型较早的记录拿不到备注。
- 为什么是 4 而不是 8：一条备注最多在写锁里改 6 × `NOTE_ROWS` 行，每行写进 4 KB 的备注。取 4 是 24 行，是分类型之前（8 行）的 3 倍；取 8 是 48 行，6 倍。实测（测试机，debug 构建，2 万行 4 KB auth 分布在各类型里）一条 4 KB 备注的整个请求：取 4 约 2.1 ms，取 8 约 2.6~2.9 ms，没有匹配记录的请求约 0.9 ms。这条路径仍然不认证，上限只是把一条请求的写入量封顶。

`audit_conn` 的关联规则：
- `action:"new"`：插入一行，`session_id` 存 `''`。
- 认证成功（没有 action）：找 `device_id = body.id`、`conn_id = body.conn_id`、`closed_at IS NULL` 的记录里 id 最大的一条，更新 `peer_id`、`peer_name`、`conn_type`、`session_id`（u64 十进制字符串）、`auth`、`authed_at`；找不到就新插一条（`created_at = authed_at = now`）。
- `action:"close"`：同样的条件找到后写 `closed_at`，找不到就忽略。
- 认证成功和 close 找记录都走迁移 0003 的部分索引 `audit_conn_open(device_id, conn_id) where closed_at is null`，索引里只有未关闭的记录，已关闭记录再多也不会被读到（审查 E-6：原来走 `(device_id, conn_id)` 索引，要逐条回表看排在 4 KB `auth` 之后、落在溢出页的 `closed_at`；同一 conn_id 下造满 2 万条已关闭记录后，每条 close 上报在写锁里扫约 20 ms，三四个来源按限速发满就能让写锁饱和）。实测（测试机，debug 构建）同一 conn_id 下 2 万条已关闭记录、什么都不更新的 close 上报整个请求：原来约 30~39 ms，现在约 1.2 ms。
- 备注：按 `device_id = body.id` 且 `session_id = body.session_id` 找匹配记录，每种连接类型更新其中 id 最大的 4 条的 `note`（见上），一条都匹配不到就忽略。

### 9.4 其他
- `GET /`：静态说明页（HTML）：服务名 Leapgate、源代码地址（AGPL-3.0 第 13 条：链接到公开仓库）、"IP Geolocation by DB-IP" 署名并链接 https://db-ip.com 。客户端"在 Web 控制台管理"菜单打开的就是这里。
- 其余未知路径回 404。
- 连接保护（审查 C-9；常量写死，不做配置，`src/api/listen.rs`）：API 端口不用 `axum::serve`（它不给 hyper 设 timer，hyper 默认的 30 秒请求头超时因此不生效，实测发半个请求头的连接一直挂着），自己写 accept 循环：
  - 并发连接最多 512 条，每个来源（IPv4 地址 / IPv6 /64）最多 32 条，回环来源只计入总数（和会合端口同一套规则，§6 第 8 条）。超限的连接在 accept 后直接关闭，不回 HTTP 响应，每分钟最多打一条 warn；客户端把它当连不上处理（会尝试 TCP 代理回退）。
  - 请求头 10 秒内收完（从连接建立或上一个响应结束算起，所以也是 keep-alive 的空闲超时）；请求头最大 16 KB（hyper 默认约 400 KB），超出回 431。
  - 整个请求（含收请求体）20 秒内要产生响应，超时按内部错误回：审计接口和 `/api/currentUser` 回 200 + `{"error":"Request timeout"}`，其他接口回 400 + `{"error":"Request timeout"}`。上报类（`/api/heartbeat`、`/api/sysinfo`、`/api/sysinfo_ver`、`/api/audit/*`，第三期起还有 `/api/leapgate/v1/*`，`is_report` 含 `is_leapgate`）改为 10 秒（审查 D-13）：客户端只从 Rust 侧发这些请求，它的 HTTP 超时是 12 秒（含建连和 TLS 握手），过了 12 秒的答复没人收，客户端会转去 21116 做 TCP 代理回退（Leapgate 直接关掉），HTTPS 下还没缓存 TLS 设置的客户端会把同一个请求重发最多 4 次。其余接口保持 20 秒，2 MB 的 `DELETE /api/ab/peer` 按 100 KB/s 也收得完：这些请求默认走客户端的 Flutter 侧（每次 30 秒）；配了 SOCKS 代理或打开本地选项 `enable-flutter-http-on-rust` 的客户端改走 Rust 侧，和上报类一样每次尝试只等 12 秒，失败后会重试或做 TCP 回退（rustdesk@bd92623:flutter/lib/utils/http_service.dart `HttpService.sendRequest`、src/common.rs `get_http_response_async`；审查 E-7）。这部分客户端遇到 12~20 秒的请求收不到服务端的超时答复，只是早几秒报错，接受；2 MB 的 `DELETE /api/ab/peer` 对它们要 170 KB/s 以上才收得完。
  - 套接字上有读或写在等、且 30 秒没有任何字节进出就断开（防止客户端不读响应，一直占着已经组好的响应体）。这个值要大于整请求超时：handler 执行期间 hyper 会挂着一个读来探测对端关闭，慢 handler 要先拿到超时响应。
  - 写下限（审查 D-4/D-18，防慢慢读的客户端）：一个响应从发送缓冲写满、写被挡住的那一刻起，直到下一个请求开始处理，写出的字节数在 30 秒宽限之后要跟上平均 32 KB/s，跟不上就断开。只靠上一条挡不住慢读：内核在发送缓冲空出三分之一时就收下一次写，客户端把接收窗口压小时，公网上的发送缓冲只有几十 KB，每 30 秒读几 KB 就能让一页几 MB 的响应发几个小时。32 KB/s（256 kbit/s）远低于远程桌面本身需要的带宽；真实的一页（100 条、几十 KB）一次就进了套接字缓冲，碰不到这条。于是 S 字节的响应最迟约 30 秒 + S ÷ 32 KB/s 发完。计数按请求清零（审查 E-9）：每条连接有一个请求计数器，hyper 每把一个请求交给服务就加一，写的时候发现计数变了就重新计时；hyper 的 HTTP/1 一次只处理一个请求，前一个响应写完才交下一个，所以计数一变就是下一个响应开始了。不按"套接字读到数据"清零：客户端把几个请求放在一次写里发来（HTTP 流水线）时，它们第一次读就全进了 hyper 的读缓冲，之后整段都不再读套接字，前几页读得快攒下的字节会算进后一页的额度，能让后一页的名额占几个小时；响应写到一半时对端发来数据也不再让计时重来。判断放在套接字一层（`listen.rs` 的 `Guarded`），不放在响应体里：hyper 的写缓冲满时不会去取响应体，那里的计时触发不了。
  - 请求体上限按路由：默认 16 KB（登录、登出、currentUser、sysinfo、心跳、单个标签的写接口，以及不读请求体的接口）；审计 64 KB（超长字段要截断入库，§9.3；Leapgate 审计同样 64 KB）；Leapgate 心跳 32 KB（sysinfo 8 KB 加 02 块的测速结果，最多 32 台中继 × 约 270 字节）；`peer/add`、`peer/update` 64 KB（合法的单条最大约 18 KB）；`DELETE /api/ab/tag` 256 KB（一本簿最多 1000 个标签；去重后超过 1000 个名字回 400，§12.1）；`DELETE /api/ab/peer` 2 MB（客户端一次删除把全部 id 放进一个数组，满簿 5000 个 253 字节的 id 约 1.3 MB）。`DELETE /api/ab/peer` 的数组边读边数、不展开（审查 D-16）：超过 5000 个元素，读到那里就回 400；id 不按长度查（审查 E-4，见 §12.1）；通过后把原始请求体直接交给 SQLite 的 `json_each` 读 id，等库期间只占请求体本身（原先解析成字符串列表再转回 JSON，2 MB 的 `["","",…]` 每个请求约占 50 MB）。处理中的请求都要占着自己的请求体，所以连接本身之外，最坏还要加上"并发请求数 × 各自路由的上限"；这条路由没有单独的并发上限，只受连接上限约束。
  - 默认监听地址不变（`0.0.0.0:21114`）。推荐部署：同机反向代理终结 HTTPS，防火墙不对外开 21114；直接暴露时以上保护照样生效，但每来源上限按 TCP 对端地址算。

### 9.5 Leapgate 上报路径（第三期，`devauth.rs`、`device.rs`、`audit.rs`）
设计依据是总仓库 `docs/第三期实施契约/01-上报与认证.md`（下称"契约 01"），这里按代码的最终行为写。

**接口**：`POST /api/leapgate/v1/heartbeat`（请求体上限 32 KB）、`POST /api/leapgate/v1/audit/{conn,file,alarm}`（64 KB）。只有 Leapgate 客户端调用，所以不受 §9.1 第 1 条约束：
- 错误体统一是 `{"error": <码>, "message": <说明>}`：400 `bad_request`（JSON 解析失败、`uuid` 超过 128 字节、字段类型不对）、401（见下面的验签链）、413 `too_large`（超过路由上限或 sysinfo 超过 8 KB）、429 `too_many_requests`、503 `internal`（查库或写库失败、整请求超时、handler panic）、404（未知路径照旧）、405 `method_not_allowed`。axum 自己产生的 413、405 在 `json_rejections` 里换成这个格式。
- 日志：超时不打日志（和兼容路径一致）；数据库错误和 panic 经 `leapgate_internal`，每分钟最多一条 error（签名请求能按上报额度的速率触发它）。

**请求签名头**：`Leapgate-Device-Auth: v1 id=<base64url(设备ID)>, t=<unix 秒>, s=<base64url(签名 64 字节)>`。base64url 不带填充，严格解码（只接受字节的规范写法）；字段顺序和 `, ` 分隔固定。被签内容（字节直接拼接）：`"leapgate-device-v1\0" ‖ 方法 ‖ "\0" ‖ 接口名 ‖ "\0" ‖ 设备ID ‖ "\0" ‖ t 的十进制 ‖ "\0" ‖ sha256(请求体)`，接口名是 `/api/leapgate/v1/` 之后的部分（`heartbeat`、`audit/conn`）。Ed25519 detached，公钥是 `peer.pk`（设备注册时报的那把）。身份只从这个头来，请求体里的 `id` 一律忽略；`uuid` 只用于延迟补绑（§11），不参与认证。签名向量和客户端测试共用一组常量（`devauth.rs` `signature_vector`）。

**验签链**（提取器 `SignedBody`，放在 handler 最后一个参数，按顺序，任一步失败直接回）：
1. 头格式：ID 解码后 1~253 字节 UTF-8、签名正好 64 字节、`t` 是 i64。不符 → 401 `bad_auth`，不签名、不带 `time`（没有可绑定的请求签名；客户端也不接受"请求签名段为空"的验法，否则截下的 `bad_auth` 能被重放来拨歪时钟偏移）。
2. 来源限速：`report_allowed`，和 §9.3 的兼容上报共用每来源每分钟 1000 次的额度。超出 → 429。
3. 读请求体，路由上限照样生效 → 413。
4. 时间窗：`|t − now| ≤ 60` 秒（`fresh`），否则 401 `stale_time`。
5. 取公钥：`pm.get_from_main`（先内存，再主池）。查库出错 → 503；没有这个 ID，或 `pk` 为空（`insert_new` 的占位条目）→ 401 `unknown_device`。
6. 验签：`pk` 不是 32 字节或签名不过 → 401 `bad_signature`。
7. 防重放：→ 401 `replay`（见下）。
8. 首次锁定：条目 `pinned` 为假时执行 `update peer set pk_pinned_at = ? where id = ? and pk = ? and pk_pinned_at is null`（主池，绑定刚才验签用的 `pk`）。影响 1 行：条目里的 `pk` 仍是这把时把 `pinned` 置真。影响 0 行（公钥已换、或别处已锁）或写库失败（限频 warn）：请求照常放行，下一个请求再试。内存和库对不上没关系，库是唯一依据（§6 第 7 条）。

第 4~7 步的 401 由提取器组好并签名，体里带服务器的 `time`；每种拒绝原因每分钟最多一条 info 日志，ID 截断后用 `{:?}` 打，不打签名和公钥。

**防重放表**（模块内 `static`，不落库）：键是设备 ID，最多 4096 台，每条约 1.5 KB（合计约 6 MB）。每台记最近 64 个 `(t, 签名前 16 字节)`；接受条件是 `t ≥ max_ts − 30`（同一设备最多乱序 30 秒）、`t > floor`、不在环里。环超过 64 条弹出最早那条，`floor` 抬到它的 `t`。新建条目 `floor = now − 30`，所以服务重启后，重启前截获的请求最多还能重放 30 秒。只有验签通过的请求才建条目；表满时扫一遍删掉 `last_seen` 最小的。Ed25519 签名是确定的，同一请求重发就是同一签名：客户端重试必须重新签名（换 `t`）。

**响应签名**：`Leapgate-Server-Sig: <base64url(签名 64 字节)>`，被签内容 `"leapgate-server-v1\0" ‖ 请求的签名(64 字节) ‖ sha256(响应体)`，用 `AppState.sk`。2xx 和 `bad_auth` 以外的 401 带签名；`bad_auth`、400、404、405、413、429、503 不带。服务端没有私钥（`-k` 传公钥）时都不带。

**心跳**（`device::leapgate_heartbeat`）：请求体 JSON 对象，键不出现表示没有：`uuid`、`ver`、`leapgate`（客户端 `libs/leapgate` 的版本）、`strategy_rev`、`sysinfo_hash`（标准 base64 的 sha256）、`sysinfo`（对象，按原始字节收）、`routing_rev`（第三期 02 块：客户端手里那份中继列表的版本，没有为 0）、`probes`（02 块：最近一轮测速，`{routing_rev, age_s, rtt: {原串: 毫秒}, down: [原串]}`，契约 02 §2.2）、`exit`（第四期：布尔值，被控端此刻接受出口登录；客户端为真时带 `"exit": true`、为假时不带，服务端不出现当 false，`true`/`false` 两种写法都收；不落库，也不收放行网段）。`conns` 不读，serde 跳过。`probes` 先收成任意 JSON 值，形状不对只丢这轮测量（§7 第二级），不回 400。流程：
1. 解析；`uuid` 超长 400；`sysinfo` 原文超过 8 KB 413；`sysinfo` 里 `hostname`、`username`、`os`、`version` 类型不对 400；`routing_rev` 不是整数 400；`exit` 出现了但不是布尔值（含 `null`）400。
2. 写 `Peer.leapgate_hb = { at: now, leapgate_ver, exit }`（整条替换，所以一次不带 `exit` 的心跳就把它改回假），`leapgate_ver = get_version_number(leapgate)` 限到 u32（解析不出为 0）。400、413 的心跳和 Leapgate 审计都不写它。带了 `probes`：`router.record_probes(签名头里的 ID, probes)`；没带（或是 `null`）：`router.forget_probes(签名头里的 ID)`（§7 第二级）。
3. 带了 `sysinfo`：`store_sysinfo(…, "leapgate")`，原文按请求里的字节原样存。
4. `touch(…, "leapgate")` 写设备行，得到库里现存的 sysinfo 原文。
5. 有设备行，且库里 sysinfo 为空或 `base64(sha256(原文)) != sysinfo_hash` → 响应带 `need_sysinfo: true`；没能建行时不带这个键。
6. `strategy::effective`，`rev != strategy_rev` 时带 `strategy: {rev, options}`（全部生效选项，值一律字符串，空串表示删键）。
7. `routing_rev` 不等于路由模块当前的列表版本时带 `routing: {rev, probe_interval_secs: 300, relays: [前 32 台原串]}`（§7 第二级；没有配置中继时 `relays` 为 `[]`，客户端停止测速）；相等时不带。
8. 签名回 200：`{"api": 1, "features": ["ice", "exit"], "time": <服务器 unix 秒>, …}`。`features` 是常量数组：`"ice"` 是自研 ICE（05 块，没有会合私钥时照样宣告；02 块不加特性项，客户端看响应里有没有 `routing`）；`"exit"`（第四期）只表示这台服务端有出口目录接口（§12.4），不表示有可用的出口，客户端靠它决定要不要请求目录。第三期客户端把 `features` 当任意字符串列表存，不认识 `"exit"` 也不受影响。查库失败一律 503。

哈希只算在 sysinfo 这个 JSON 值的原始字节上；服务端原样存那段字节，比对时当场算，不加列。兼容路径存的是整个兼容请求体，哈希必然不同，所以设备从兼容路径切到 Leapgate 路径后会重传一次 sysinfo。

**审计**（`audit::leapgate_conn/file/alarm`）：请求体同兼容接口，`id` 取签名头里的；和兼容 handler 共用结构体、截断规则和写库函数（`conn_inner`、`file_inner`、`alarm_inner` → `report`，身份参数 `Identity::Verified` 不查身份），nonce 去重表两条路径共用，同一条审计从哪条路径到达都只记一次。没有会话备注分支（`conn` 里的 `note` 键忽略，按普通上报处理）。成功（含 nonce 重复）签名回 200 + `{"api":1}`；写库失败 503，nonce 不登记，客户端重试时能入库。

### 9.6 两个 Leapgate 前缀的分工（第四期）
- `/api/leapgate/v1/`：设备签名的上报接口（§9.5）。错误体 `{"error": <码>, "message": …}`，可以回 503，整请求超时 10 秒（`is_report`），2xx 签名。
- `/api/leapgate/user/v1/`：Leapgate 客户端凭用户令牌（`Authorization: Bearer`）调的接口，现在只有出口目录 `GET /api/leapgate/user/v1/exits`（§12.4）。照 §9.1 的通则：不回 5xx，错误体 `{"error": …}`，令牌无效、没带、账号禁用回 401 `{"error":"Unauthorized"}`，认证那一步查库失败回 200 `{"error":"Server error"}`（提取器 `CurrentUser` 的现有行为），之后的查库失败回 400 `{"error":"Server error"}`，用错方法 405 `{"error":"Method Not Allowed"}`，整请求超时 20 秒（回 400 `{"error":"Request timeout"}`），请求体上限用默认的 16 KB。响应不签名：现有的响应签名绑定设备的请求签名，套不到用户接口上。`is_leapgate`、`is_report` 按 `devauth::PREFIX` = `/api/leapgate/v1/` 判断，这个前缀不以它开头，所以都不算。
- 以后再加用户令牌接口，都放后一个前缀。

## 10. 心跳与策略（`strategy.rs`、`device.rs`）

- 生效选项 = 全局（`scope='*'`）⊕ 设备（`scope=<id>`，同键覆盖）。
- 版本号 `rev`：对（生效选项按键排序的规范 JSON、全局 epoch、设备 epoch）做 sha256，取前 8 字节转 `i64` 后与 `i64::MAX` 按位与，结果为 0 时取 1。任何生效选项变化或 epoch 递增都会换版本；不用自增计数器。
- 下发规则（笔记 01 §2.2）：**仅当 `req.modified_at != rev` 时**，响应同时带 `"modified_at": rev` 和 `"strategy": {"config_options": {…全部生效选项…}}`；否则两者都不带。值一律是字符串，不给 null。这样"设备首次接入或策略变更时清一次 `relay-server`"自然成立，之后用户在本地改了也不会每次被覆盖。
- 客户端是**增量合并**：只改下发里出现的键，空值表示删键（笔记 01 §3）。所以"撤销"一个推过的键不能删行，要把值写成 `''`（墓碑，下发时客户端删掉这个键）。删掉设备级的同名行，生效值回到全局值；全局也没有这个键时，客户端上的旧值不会被清掉。
- 设备级值为 `''` 时照样覆盖全局值（也就是让这台设备删掉这个键）。
- 编码：`modified_at` 是 JSON 整数（i64），不能写成字符串；"值一律是字符串"只指 `config_options` 里的值。
- `sysinfo` 键只在设备还没有 sysinfo（`device.sysinfo = ''`）时出现，值固定为 `true`；其余情况必须完全省略这个键，不能发 `false` 或 `null`（客户端只看键在不在，带了就会重传 sysinfo）。响应结构体的可选键一律用 `Option` + `skip_serializing_if`。
- 心跳更新 `device.last_seen_at`、`ver`、`last_ip`：`ver` 或 `last_ip` 变了、或者库里的 `last_seen_at` 已有 60 秒时才写库，其余心跳只读（心跳 15 秒一次、会话中 3 秒一次，每次写库都要拿写锁，会合模块的注册写库也在等这把锁），所以 `last_seen_at` 最多落后 60 秒。设备行不存在就建，受 §9.3 的行数上限约束。心跳和 sysinfo 写设备行时，`user_id` 为 NULL（含刚建的行）的按 §11 延迟补绑，补绑和写设备行是同一条语句。
- 客户端 IP（`last_ip` 等）：TCP 对端是回环地址时取 `X-Real-IP`，没有就取 `X-Forwarded-For` 的最后一个地址；否则直接用 TCP 对端地址；取到后规范化（§3）。反代和 leapgate-server 不在同一台机器的情况第一期不支持。
  - **硬性部署要求**（审查 D-9）：同机反代转发到 21114（API）和 21118（WebSocket 会合）的每一段 location 都必须用客户端的真实地址覆盖 `X-Real-IP`：nginx 写 `proxy_set_header X-Real-IP $remote_addr;`，Caddy 写 `header_up X-Real-IP {remote_host}`。nginx 默认把客户端自带的请求头原样转发，常见配置只设 `X-Forwarded-For`；Caddy 的 `reverse_proxy` 默认也只设 `X-Forwarded-*`。不覆盖时，客户端每个请求都能自填一个 `X-Real-IP`，leapgate-server 会照单采信：上报的每来源限速（§9.3）、会合端口的 `IP_BLOCKER`、每来源新 id 限额和按位置选中继（§6、§7）全部能被一个真实 IP 绕开。服务端不做"信任哪个头"的配置项：先取哪个头都不是在所有反代配置下都安全（先取 `X-Forwarded-For` 最后一项时，只设 `X-Real-IP` 的 nginx 会原样透传客户端自带的 `X-Forwarded-For`），所以约束放在部署上。部署后从外网带 `X-Real-IP: 192.0.2.1` 发一次心跳，确认记下的 `last_ip` 是真实地址。
- sysinfo：存原文，拆出 `hostname`、`username`、`os`、`version`。第三期起 Leapgate 客户端没有单独的 sysinfo 接口，sysinfo 并进 Leapgate 心跳（§9.5）。
- 写设备行的逻辑只有一份（第三期抽出），兼容和 Leapgate 两条路径都调用：`touch`（心跳写行：上面的"变了才写、`last_seen_at` 60 秒一写"、行数上限、延迟补绑，返回库里现存的 sysinfo 原文）和 `store_sysinfo`（存 sysinfo 的事务）。`client_type` 记的是**最近一次走的路径**：兼容路径写 `rustdesk`，Leapgate 路径写 `leapgate`；`touch` 的"什么都没变"条件包括 `client_type` 相同，所以换了路径会立即写一次。
- 策略永远不下发 `leapgate-` 开头的键（那是 Leapgate 客户端自己的选项，例如能力缓存 `leapgate-api-caps`）：`strategy set`、`strategy unset` 拒收这类键（§14），客户端合并下发时也跳过它们。

## 11. 账号、令牌、密码（`auth.rs`、`account.rs`）

- 密码：argon2id（`argon2` crate 默认参数）。校验时按前缀识别 `$argon2id$`、`$2a$/$2b$/$2y$`（bcrypt）、`md5:`（rustdesk-api 旧格式 `md5(明文+"rustdesk-api")`，笔记 05 §3）；旧格式校验通过后当场改存 argon2id，只在库里仍是刚校验的旧哈希时才写（期间 `user passwd` 改过的不覆盖，这次登录回 401）；库里已被另一个并发登录升级成 argon2id、且本次明文能通过它时照常签令牌。`password_hash = ''` 的账号不能密码登录。
- 令牌：32 字节随机数的 base64url（无填充），库里只存 sha256 hex。没有过期时间，但每个用户最多保留 50 条：登录时在插入新令牌的同一个事务里，删掉该用户按 `last_used_at` 降序（相同再按 rowid 降序）排在 50 名以外的令牌，也就是淘汰最久没用的（否则知道密码的人反复登录就能无限攒令牌行）；改密码、禁用账号时删掉该用户的全部令牌，登出删哪些见下。每次使用更新 `last_used_at`。
- 登录时把请求体里的设备 `id`/`uuid` 记进令牌行；再做 §9.3 同样的校验：只有 `peer` 表里有这个 id 且 uuid 相符时，才把 `device.user_id` 设成这个用户（设备行不存在就建，建行和上报一样受 §9.3 的行数上限约束：表满且没有可淘汰行时登录照常成功，只是不建行、不绑定，审查 D-7）；uuid 不符时登录照常成功但不改 `device.user_id`（防止别人把你的设备挂到自己名下）。第四期起（A1）：公钥已锁定（`peer.pk_pinned_at` 非空，§9.5）的设备只在没有主人时绑定，另一个账号 uuid 相符的登录不再覆盖已有主人；锁定与否在写设备行的同一条语句里读（`case when exists(… pk_pinned_at is not null) then coalesce(user_id, excluded.user_id) else excluded.user_id end`）。已锁定的设备要换主人：原主人在设备上登出（登出清掉本人的绑定，见下），或者运维用 `device owner`（§14）；所以多人轮流登录的共用机器，换人前要先登出上一个账号，登出请求没送到时要运维改。没锁定的设备（原版客户端走兼容路径，永远不会锁定）照旧由后登录的覆盖，`device owner` 设的主人也会被下一次登录换掉。已锁定、此刻没有主人的设备（新装还没人登录过、主人登出后、`device owner <ID> none` 后、设备行被淘汰重建后）登录先到先得：第一个用匹配的 ID 和 uuid 登录的账号成为主人，后果只在归属（组面板、出口目录里的 `own`），能不能用出口仍要过被控端的认证；要固定主人用 `device owner`。表满、没能建行时已锁定设备的登录不绑定，之后有了空位延迟补绑也不会补（令牌签发晚于锁定），要在设备上重新登录。`peer` 表里没有这个 id 时登录照常成功，不建设备行、不绑定（令牌行照样记 id/uuid）。
- 延迟补绑：登录时还没在 hbbs 注册的设备（例如开着 stop-service 登录、之后才启动服务），由之后的心跳或 sysinfo 补上归属：请求通过 §9.3 的 uuid 校验、且 `device.user_id` 为 NULL（含刚建的行）时，取 `token` 表里 `device_id` = 这个 id、`device_uuid` = 请求里的 uuid、账号 `status = 1` 的令牌中 `last_used_at` 最新的一行，把它的 `user_id` 写进 `device.user_id`。查令牌和写归属在写设备行的同一条语句里完成（`user_id = coalesce(user_id, (select … from token …))`），中间插不进登出（审查 C-24）；心跳只在写库时补绑（§10，最多晚 60 秒）。安全性和登录时绑定相同：令牌行的 uuid 要等于刚和 `peer.uuid` 比对过的那个。已有主人的设备不改。
  - 第四期起（A1）：已锁定的设备只认锁定之前签发的令牌（`not exists (select 1 from peer p where p.id = ?1 and p.pk_pinned_at < t.created_at)`，比较的是 unix 秒，同一秒签发的算"之前"）。理由：锁定以后设备一定已在会合服务器注册，真主人在它上面登录时由登录直接绑定，用不着补绑；锁定之后签发、却还要靠补绑的令牌，只可能来自"登录时设备已有主人、没绑上"的人。不加这条，知道设备 ID 和 uuid 的人登录一次就留下令牌，真主人一登出，下一次心跳就把设备补到他名下，设备随之以 `own: true` 出现在他的出口目录里（§12.4）。"先登录、后注册"的新装设备照常补绑：令牌签发时设备还没注册，早于锁定；第一次签名心跳在 `SignedBody` 第 8 步先锁定，handler 里的 `touch` 再补绑。不选"已锁定设备整个关掉补绑"：那样先登录、后注册的新装设备就没有补绑了。这条只防被动补绑，挡不住设备没有主人时的主动登录（见上一条）。`device owner <ID> none` 之后，已锁定的设备只会被锁定之前签发的令牌补回，没锁定的会被这台设备上最近用过令牌的人补回。
  - 已知边角（只剩没锁定的设备）：A 在设备上登录过、登出请求没送到，B 再登录接管后又登出，下一次心跳会把设备补绑回 A（A 的旧令牌还在）。不处理：登出时连别人的同设备令牌一起删，会让伪造 `device_id` 的人能删掉别人的令牌；没锁定的设备通常是原版客户端（当不了出口；Leapgate 设备第一次签名心跳就锁定），归属只决定它在组面板（§12.3）里列在谁名下，不影响策略和连接权限，而 A 本来就在这台设备上登录过，补错的后果有限。已锁定的设备上，归属还决定它以 `own: true` 出现在谁的出口目录里，后果不再"有限"，所以才有上面那条。
- 登出时删掉当前令牌，连同本人 `device_id` 相同、签发不晚于当前令牌（`created_at <= 当前令牌的 created_at`）、而且当前令牌签发以来没再用过（`last_used_at <= 当前令牌的 created_at`）的令牌：一个客户端只持有最新一枚，更早签发又没再用过的是废令牌，留着的话下一次心跳就会把设备补绑回来。签发更晚的（登出请求还在路上时用户重新登录拿到的）和签发后还用过的保留（审查 C-5、C-20）。`device_id` 为空的令牌不受影响。之后若 `device.user_id` 是本人则清空。
  - 已知边角：同一台机器上多个系统账户登录同一个 Leapgate 账号时，它们上报的 id、uuid 相同，各自存自己的令牌，服务端分不清。一方登出时，另一方的令牌只要在登出那枚签发之后用过就保留（之后写库的心跳会把设备补绑回这个账号，这是对的）；从那以后一直没用过的会被一起删掉，那个系统账户下次调用接口时收到 401、被客户端登出，重新登录即可。
  - 另一个边角：用户重新登录的瞬间，还在路上的旧令牌请求晚于新令牌到达，会把旧令牌的 `last_used_at` 推后，让它逃过之后那次登出的删除，并把设备补绑回本人，和延迟补绑那条里的"补绑回 A"同类。
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
  - 每条设备：`id` ≤ 253 字节（`MAX_PEER_ID_LEN`）；`data` 按落盘的 JSON 序列化后 ≤ 8 KB，且 JSON 节点总数 ≤ 64（每个键、每个值都算一个，嵌套的数组和对象里的元素、键、值递归计入；客户端 `Peer.toJson` 只有 11 个 data 键，即 22 个节点），两项都在 `peer/update` 合并之后再查（每次 update 都可能往同一行加键），超了整个请求不生效；`peer/update` 还在开事务之前先查一次请求自带的 data，超限的不带进事务（所以请求自带的 data 超限时，id 不在簿里也回 400 而不是 404）；`tags` ≤ 64 个、每个 ≤ 64 字节；本簿要存的 `hash`/`password`（客户端上传的明文，加密前）≤ 1 KB 且不能含控制字符（理由同标签名，见下），另一个键照旧忽略、不查。
  - 节点数上限的理由：解析成 JSON 对象后，键值很短时内存约是原文的十倍；`peer/update` 要把库里的一行解析出来合并。`/api/ab/peers` 逐行解析、马上序列化进响应缓冲，不建整页的对象树。一页的内存（实测，1000 条最坏的行：id 253 字节，data 约 8 KB，64 个全是引号的 64 字节标签序列化后约 8.4 KB，hash 1 KB 加密后约 1.4 KB）：查出的原文约 18 MB 加响应缓冲约 18 MB，handler 内峰值约 36 MB；返回后响应体约 18 MB，客户端读完或连接断开才释放。原版客户端每页只要 100 条，约是十分之一。所有用户合计同时最多 8 页在组装或发送中，每个用户同时最多 2 页（审查 D-4，客户端一次只取一页；常量写死），再来的排队等（先等自己的名额，再等总名额），排队受整请求 20 秒超时约束（超时回 400 + error）。名额和整页缓冲同生共死（审查 D-3）：页缓冲的最后一块字节写进内核、或连接断开，内存释放的同时名额才归还；hyper 取走最后一帧时就丢掉响应体，那时还有最多约 80 KB 排在它的写队列里。所以这一项最坏约 8 × 36 MB ≈ 0.3 GB。名额最长占多久：组页受整请求 20 秒约束；发送阶段，完全不读的连接 30 秒断开，慢慢读的连接受写下限约束（§9.4），S 字节的页约 30 秒 + S ÷ 32 KB/s（1000 条最大行约 18 MB 是 10 分钟左右；计数按请求清零，流水线发来的几页各算各的，审查 E-9）。一个账号最多占住 2 个名额，其他用户照常取页；要占满 8 个名额得有 4 个账号同时这样做（账号由管理员建）。推荐部署里 nginx 默认开着 proxy_buffering，会全速把响应读进自己的缓冲，名额很快归还。不靠调小 `pageSize` 上限来压内存：客户端翻页循环是 `while (current * pageSize < total)`，用的是它自己请求的 `pageSize`，服务端上限低于它请求的值时客户端会提前停止翻页、静默丢数据。
  - 标签名（`tag/add`、`tag/rename` 的新名字，设备 `tags` 里的每个元素）≤ 64 字节，且不能含控制字符（`char::is_control`），否则回 400。理由：serde_json 把控制字符写成 6 字节的 `\u00XX`，级联改写一次读出的 tags 最多会膨胀到字节数的 6 倍；禁掉后最坏约 21 MB（5000 个设备 × 64 个 64 字节的标签；标签全是引号、反斜杠时每字节转义成 2 字节，约 42 MB），这一步在写锁事务里串行执行，可以接受。
  - 每本簿最多 5000 个设备、1000 个标签：计数和插入在同一条语句里，并发添加也不会超。簿满时 `peer/add` 新 id 回 400，簿里已有的 id 照旧回 200 空 body、不改字段；`tag/add` 同理（已有的名字照旧成功）。
  - 5000 是按在线状态查询定的：客户端把一个标签页的全部 id 放进一条 `OnlineRequest` 发到 21115，那里单帧上限 128 KB（§6 第 8 条）；5000 个 16 字符的 id 约 90 KB，簿满时在线状态也能查出来。
  - `max_peer_one_ab` 回 5000（和设备上限一致）。客户端拿到后，本地缓存的条数到了这个数就不再发添加请求，直接提示 `exceed_max_devices`（`Ab.isFull`，笔记 04 §3.2）。
  - `/api/ab/tags` 不分页、`tag/rename`/`DELETE tag` 的级联改写一次读出本簿所有带该标签的设备，两者靠上面的标签数、设备数和每条 tags 的上限封顶。`DELETE tag` 请求里的名字在开事务之前先去重，去重后超过 1000 个回 400；名字不按上面的标签名规则查（导入的超长标签要能直接删，§15；不存在的名字匹配不到，集合查找的开销只取决于个数）；级联时逐个标签按集合查找（审查 D-14：原先不限个数、逐个线性比较，256 KB 能塞约 6.5 万个名字，满簿时在写锁里卡几十秒）。客户端一次只删簿里选中的标签，不受影响。
  - 从 rustdesk-api 导入（§15）不查这些上限，超限的标签、id 超过 253 字节的条目、条目超过 5000 个的簿只写进报告，后果见 §15。
- 设备：
  - `peer/add` 遇到簿内已存在的 id：**不改任何字段**，直接回 200 空 body。客户端只按本地缓存查重；目标簿没拉取过时，重复的 id 会带着被清空的 tags 和空的 alias/note 发过来，按合并处理会把现有数据清掉（笔记 04 §3.6、§4.4）。
  - `peer/update` 只合并请求里出现的字段；id 不在簿里回 404 + error，不新建。
  - `DELETE peer`：一个事务里删掉存在的、忽略不存在的，回 200 空 body。请求体必须是字符串数组，最多 5000 个，否则回 400（§9.4）；个数限的是 `json_each` 在写锁里处理的元素数。id 不按长度查（审查 E-4，和 `DELETE tag` 不查名字同理）：导入的 id 超过 253 字节的条目 `peer/update` 改不了，至少要能删；超长 id 的开销已经被 2 MB 的请求体上限封住，库里也只可能匹配到导入的行。
  - 个人簿存 `hash`、共享簿存明文 `password`，两者都加密落盘。`tags` 存字符串数组。其余字段存进 `data`：写入时丢掉值为 null 的键（当作没给）；`alias、note、username、hostname、platform、rdpPort、rdpUsername、loginName、device_group_name、forceAlwaysRelay` 不是字符串、`same_server` 不是 bool 时回 400 + error。
  - `peers` 回包每条 = `data` 的全部键 + `id` + `tags`（数组）+ 个人簿的 `hash` 或共享簿的 `password`（解密后）；`hash_enc`/`password_enc` 为 `''` 时不解密、省略这个键；客户端传来 `hash:""`/`password:""` 时存成 `''`。
- 标签：
  - `tag/add` 遇到同名标签：不改颜色，回 200 空 body（`on conflict do nothing`）。
  - `tag/rename`：old 不存在回 404，new 已存在回 409；成功时同一事务里改 `ab_tag`，并把本簿所有设备 `tags` 里的 old 换成 new、去重。
  - `tag/update`：name 不存在回 404。
  - `DELETE tag`：忽略不存在的名字，同一事务里删标签并从本簿所有设备的 `tags` 中移除，回 200 空 body。
  - `color` 按 i64 存取。
- 分页和类型严格性按笔记 04 §1.6、§2。`pageSize` 最大 1000，超过的按 1000 截断，`total` 照样是全部条数（客户端写死每页 100，按 `total` 翻页；`/api/ab/peers` 一页的原文和回包都在内存里，见上面的估算）。这个上限对所有分页接口（含 §12.3 组面板）都生效。

### 12.2 用户组（维护者 2026-10-22 定：Leapgate 也做用户组）
- 一个用户可以在多个组里（`group_member`）。共享簿可以授权给组（`ab_rule.group_id`），成员变动后权限立即跟着变。
- 组只用于授权和组面板可见范围；组的增删、成员管理走命令行。

### 12.3 组面板（`/api/users`、`/api/peers`、`/api/device-group/accessible`）
- 管理员：看到全部用户和全部设备。
- 普通用户：看到自己，加上和自己同在任一 `share_devices=1` 组里的用户；设备是这些用户名下的（`device.user_id`）。
- 客户端拉列表时带 `status=1`：请求带 `status` 参数（数字）时，`/api/users` 在上面的可见范围里只返回 `user.status` 等于该值的用户；`/api/peers` 不按设备过滤（设备没有启用状态），但排除被这个条件滤掉的用户名下的设备（例如禁用用户的设备），没有归属的设备（管理员可见）照常列出。不带参数或参数不是数字时不过滤。
- `/api/device-group/accessible` 回 `{"total":0,"data":[]}`。
- `status`（在线）按 `PeerMap` 的内存在线判定；字段和类型照笔记 03 §3。

### 12.4 出口目录（第四期，`exit.rs`）
`GET /api/leapgate/user/v1/exits`，头 `Authorization: Bearer <用户令牌>`，没有请求体、查询参数，不分页。错误按 §9.6 的后一个前缀。成功回 200 `{"exits": [{"id", "hostname", "owner", "own"}, …]}`，一个都没有时 `{"exits": []}`：
- `id` 设备 ID；`hostname` 是 `device.hostname`，没有设备行或还没收到 sysinfo 时为 `""`；`owner` 是主人的用户名，没有主人为 `""`；`own` 表示主人就是请求者。每条恰好这四个键，不给 IP、系统用户名、系统版本、离线设备。
- 列谁：主人是我的设备（`device.user_id`），加上 `exit_grant` 里授权给我本人、或授权给我所在任一组的设备（查询时按 `group_member` 展开，成员变了当场生效；授权写完立即生效，不需要控制台通知运行中的服务）。同一台设备满足几条也只列一次。先列 `own` 为真的，再按 `id` 排序。管理员和普通用户一样，没有全局视图，要看全部授权用 `exit list`（§14）。
- 只列此刻可用的（`exit::available`），三条同时成立：UDP 注册在 30 秒内（`last_reg_time`，和组面板的在线判断同一个 `ONLINE_TIMEOUT`）；最近一次验签通过的 Leapgate 心跳在 180 秒内（`LEAPGATE_HB_FRESH`，§3）；那次心跳的 `exit` 为真（§9.5）。在线状态只查内存（`get_in_memory`），不经主池加载：不在内存里的设备 30 秒内没注册过，本来就不可用。不要求公钥已锁定、不看 Leapgate 版本：带 `exit` 的心跳只有第四期客户端会发；设备谎报 `exit` 只影响它出现在谁的目录里（它的主人和被授权的人），不扩大谁能连。
- 授权给已删除设备、还没上报过的设备时，`left join` 得到空的主机名和主人；它们在线时照样列出。候选是"自己名下的设备行"（受设备表 1 万行约束）加"授权行"（管理员手工维护），所以不分页、不另设上限。
- 目录只是建议，不是关口：授权表只影响目录，撤销授权不断开已有会话，也挡不住知道设备密码的人（不在目录里的设备照样能手填 ID 使用）。要切断某人，在被控端关掉出口开关。响应不签名，靠部署的 HTTPS 防篡改；控制端只在打开目录时取一次，不轮询。
- 延迟：开关切换后最多一个心跳周期（空闲时 15 秒）才反映到目录；心跳停了以后 UDP 注册 30 秒过期，最多晚 30 秒消失。服务端重启后，要等设备的下一次注册和心跳才回到目录。走 WebSocket 或代理、在会合服务器注册不了的被控端不会出现在目录里（§1：TCP 注册不做）。
- 服务端策略下发不了出口开关：`strategy set`、`unset` 本来就拒收 `leapgate-` 开头的键（§14）。

## 13. 密码字段加密（`crypto.rs`）

- 工作目录下的 `leapgate_secret.key`（32 字节随机数，权限 0600，和 `id_ed25519` 放在一起）。**只有服务模式**在缺失时生成；命令行（含 import）只读已有的文件，不存在就报错退出，提示到服务的工作目录下运行或先启动一次服务（否则在别处跑命令行会多生成一把密钥，导入的密码就解不开了）。服务模式发现文件不存在、库里却已有密文（`select 1 from ab_peer where hash_enc <> '' or password_enc <> '' limit 1` 查到行）时拒绝启动，报错提示恢复密钥文件，或有意清空这两列（已存的密码全部作废）；不生成新密钥。
- `sodiumoxide::crypto::secretbox`；存储格式 `sb1:` + base64(nonce ‖ 密文)。
- 加密的字段：`ab_peer.hash_enc`、`ab_peer.password_enc`。服务端运维者本人仍能解开，目的是防数据库文件和备份泄露。
- 备份数据库时要连同 `leapgate_secret.key` 一起备份，丢了这个文件，地址簿里的密码就解不开了。`/api/ab/peers` 遇到解不开的值只省略这条的 `hash`/`password` 键并记 warn 日志（簿 guid 和设备 id，不打密文），其余条目照常返回。

## 14. 命令行（`src/cli/`）

`leapgate-server <子命令>`，直接读写同一个数据库（`DB_URL`），打开时执行迁移。需要运行时状态的子命令走本机控制台（127.0.0.1:`port-1`）。密码一律从标准输入读一行，不放在参数里。
- `user add <name> [--admin] [--display-name …] [--email …]`、`user passwd <name>`、`user list`、`user disable|enable <name>`、`user admin <name> on|off`、`user del <name>`
- `group add <name> [--share-devices]`、`group del <name>`、`group list`、`group member add|rm <group> <user>`
- `ab list`、`ab create <name> --owner <user> [--note …]`、`ab rename <name> <new>`、`ab del <name>`、`ab grant <book> --user <u>|--group <g> ro|rw|full`、`ab revoke <book> --user <u>|--group <g>`
- `device list [--legacy]`：id、主机名、账号、客户端类型和版本、最后上报时间；`--legacy` 只列原版客户端（退出兼容时用），并同时列出 `conn_attempt` 里出现过、但 `device` 表里没有的 id（`b_id` 配 `b_version`；`a_device_id` 非空时配 `a_version`），标注"仅见于会合"。输出注明：从不发心跳、也从没参与过连接的设备统计不到。
- `device key <device>`（第三期，只读）：公钥指纹（小写 hex，每 4 个字符空一格，和客户端 `pk_to_fingerprint` 同格式）、锁定时间或"未锁定"、uuid 字节数、同一 uuid 下的其他 ID（重装后换了 ID 的设备由此能看出来）。新设备装好后用它和设备界面上的指纹核对一次（锁定是首次使用即信任）。
- `device key reset [--forget] <device>`（第三期，§9.5 的公钥锁定）：**只由命令行改库**，能打开数据库文件就是授权；控制台不认证（本机任一进程都能连），所以不提供改库的命令。
  - 默认只清锁定：`update peer set pk_pinned_at = null where id = ?`，保留 uuid 和公钥。用途是卸载时删了配置的重装：uuid 来自机器、不变，重装后的设备按现有规则（同 uuid、同 IP 可以换公钥）保住原 ID。要在旧安装停止运行之后、重装的设备重新注册之前执行：旧安装还在跑时，它下一次签名心跳就把旧公钥重新锁上。已经因 `UUID_MISMATCH` 换成随机 ID 的，reset 后在设备上把 ID 改回原来的。
  - `--forget`：`delete from peer where id = ?`，给 uuid 也变了的情况（换硬件、重装系统）。删行后这个 ID 谁都能注册、抢到的人发一次签名心跳就锁定了自己的公钥，所以只在新设备已经在线（已换成随机 ID）时执行，执行后立刻在设备上把 ID 改回原 ID。`device`、`device_policy`、`strategy_option`、`exit_grant` 里按 ID 存的行不受影响：这些行（含设备主人和出口授权）会被下一个注册这个 ID 的设备继承。
  - 改完库后连控制台发 `kl <id>`，让运行中的服务按库重载这个条目。回复以 `<id>: ` 开头（服务端的三种正常回复）才算成功，把回复接在输出后面，退出码 0。连不上控制台、或回复是别的（`Failed: …`、空串），库已改好、不回滚，报错说明服务端没有重载、附上回复原文，提示"服务若在运行，需要重启 leapgate-server 才会生效"，退出码非零。没重载时，解锁也会在设备下一次用新公钥注册时生效（§6 第 7 条：注册前先按库重载锁定的条目）；删行则由服务端在下一次注册时发现行不在、移除条目。
  - 库里没有这个 ID 时报错，并提示"如果上次重置时服务端没有重载，请重启 leapgate-server"。ID 为空或含空白（控制台按空格拆命令）时报错。
- 控制台 `kl <id>` / `key-reload <id>`（第三期）：只按库重载内存，谁都能触发，效果只是让内存和库对齐。条目在内存里：库里有行就把内存刷成库里的值（含 `pinned`），回 `<id>: reloaded from the database`；库里没有行就移除条目，回 `<id>: not in the database, dropped from memory`。不在内存里回 `<id>: not in memory, nothing to reload`。走主池（连接任务，不占会合池）。
- `strategy show [<device>]`（列出生效选项和 rev）、`strategy set <device|'*'> <key> <value>`、`strategy unset <device|'*'> <key>`（写成墓碑 `''`，让客户端删掉这个键；`set`、`unset` 拒收 `leapgate-` 开头的键，§10）、`strategy forget <device|'*'> <key>`（删行，不再下发这个键；设备级删掉后回到全局值）、`strategy repush <device|'*'>`（递增 epoch）
- `device pin-relay <device> <host|none>`
- `device owner <device> <user|none>`（第四期 A1）：在一个 `begin immediate` 事务里 `update device set user_id = ? where id = ?`，`none` 写 NULL。只写 `device.user_id`，不另存"命令行指定"的标记：组面板、`device list`、登出清主人、延迟补绑和出口目录读的都是这一列。要求设备行已存在（在线的出口设备一定有行），影响 0 行时报错 `<device> has no device row (it has not reported to this server, or its row was evicted)`，什么都不写；不替设备建行，免得绕过设备表上限。没有这个用户时报错（名叫 `none` 的用户不能用这个命令指定，同 `pin-relay` 的 `none`）。指定了用户时同一事务里 `insert into device_policy(device_id) values(?) on conflict do nothing`：只为借用 §9.3 的淘汰保护，新行的 `relay_pin` 默认 `''`、`strategy_epoch` 默认 0，和没有这一行等价，策略 rev 不变；已有的行不动。`none` 不删这一行（它可能带着 `pin-relay` 的设置）。输出：设了主人时 `<device> is now owned by <user>`，设备没锁定时追加一行 `<device> has no pinned key yet: the next login on it replaces the owner`；`none` 时 `<device> has no owner now; a login on it, or a login token left on it (late binding), may bind it again`。
- `exit grant|revoke <device> --user <u>|--group <g>`、`exit list`（第四期，§12.4）：
  - `grant`：先查 `peer` 表有没有这个 ID，没有时报错 `<device> is not registered with this server`（挡手误，也挡"先授权、后被人抢注这个 ID"）；不查在线和出口开关。用户、组查不到时报错；`--user`、`--group` 恰好给一个。重复授权不报错、只留一行；给主人本人授权不拒绝（目录里去重）。输出 `user:bob may use exit <device>: it shows in their exit directory while it is online with the exit on`。
  - `revoke`：不查 `peer` 表（已删除设备的授权也能撤）。没有这条授权时输出 `user:bob had no grant on exit <device>`，否则输出 `Revoked user:bob on exit <device>. This only changes the exit directory: sessions already open stay, and anyone who knows the device's password can still use it`。
  - `exit list`（只读）：一台设备一行，列 `DEVICE`、`OWNER`、`GRANTED TO`（`user:bob, group:ops`，用户在前）；没有授权时输出 `(no exit grants)`。末尾固定一行 `Owners always see their own devices. Whether an exit is online and on is known only to the running server.`：命令行进程读不到服务进程的内存，所以没有"此刻哪些出口在线"的命令。
  - 授权每次查目录时都现查库，写完立即生效，不需要控制台通知运行中的服务。
- `relay status`（控制台 `rs`；第三期末尾多一行 `measurements: <N> devices, <M> fresh`，§7 第二级）、`route test <ipA> <ipB> [--a <device>] [--b <device>]`（控制台 `tg <ipA> <ipB> <idA|-> <idB|->`，`-` 表示没有；ID 为空、是 `-` 或含空白时报错）。带 ID 时用这两台设备的第二级测量，每台可达中继后面标出两段用的是实测（`rtt 23ms` / `down`）还是估计（`est 21.3ms`，没有位置为 `est ?`），被实测 `down` 去掉的标 `no cost (measured down)`，这一行里用估计的那一端显示 `-`（没参加计算，没有值）；不带 ID 时输出和第一级一样。
- `geo lookup <ip>`（直接读本地 mmdb：国家、经纬度、ASN、运营商组）、`geo update`（走控制台 `gu`，由服务进程执行下载、校验和热切换并回显结果；连不上控制台即服务没在运行时，才在命令行进程里直接下载，不做目录清理）
- `stats [--days N]`：中继回落率和各结果计数（§8）；第三期 05 起另列一张 `ICE OUTCOME | COUNT` 表（`ice_result` 按 `at` 取同一时间范围），并注明"ICE 胜出的连接在上面仍按上游信令记成 relay/direct_tcp，上面的回落率会偏高，ICE 的实际直连看这里的 `connected`"。不加 `relay status` 的会话数一行，也不加别的命令：ICE 没有需要运维改的运行时状态
- `import rustdesk-api <db 路径> [--dry-run]`（§15）
- 名字校验：用户名、组名、簿名不能为空；用户名最长 128 字节（登录接口拒绝更长的名字）；共享簿名唯一且不能是 `My address book` 或 `Legacy address book`。
- 命令行不新建数据库：`DB_URL` 指向的库文件不存在时报错退出（提示到服务的工作目录下运行或设置 `DB_URL`；只有文件确实不存在才这样报，库文件存在但访问不了时（例如权限不足）如实报出路径和原因），写操作在输出末尾打印所用数据库的绝对路径。在错误目录下运行不会悄悄写进一个服务看不到的新库。
- `relay status`、`route test`、`geo lookup`、`geo update` 不读写数据库：不要求库文件存在，也不打开它（不执行迁移），在任何目录下都能运行。

## 15. 从 rustdesk-api 导入（`src/import.rs`）

- 只读打开 rustdesk-api 的 SQLite，按笔记 05 §8 的 SQL 读取（下面写明的地方除外）；Leapgate 库里已有用户时拒绝执行（只支持往空库导入一次）。`--dry-run` 只打印将导入的数量、冲突和被丢弃的数据。
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
- 超出 §12.1 上限的标签（审查 C-6）：超过 64 字节或含控制字符的标签名（标签表和条目的 tags 里出现的都算），以及标签超过 64 个的条目，原样导入，报告（`--dry-run` 也输出）逐条列出，孤儿标签另外注明。后果：带这类标签的设备，改标签时只要还保留它（或仍超过 64 个），`peer/update` 就回 400；把这台设备加进同样有该标签的簿，`peer/add` 也回 400。导入后用客户端标签菜单的 Rename 把它改短（`tag/rename` 只查新名字，会级联改掉设备上的旧名），或者直接 Delete（`DELETE tag` 不查名字，§12.1）；孤儿标签不在簿的标签列表里，客户端既改不了名也取消不了勾选。
- 超出 §12.1 上限的条目和簿（审查 E-4）：id 超过 253 字节的条目、条目超过 5000 个的簿，同样原样导入，报告（`--dry-run` 也输出）逐条列出。后果：id 超长的条目 `peer/update` 回 400，改不了，只能删除（`DELETE peer` 不查 id 长度，§12.1）。条目超过 5000 个的簿，客户端不再添加（`max_peer_one_ab` 是 5000，服务端对新 id 的 `peer/add` 也回 400）；全选删除会把全部 id 放进一个请求，超过 5000 个回 400、一条都不删，需要分批删除，每批不超过 5000 个。
- `data` 只由上面列出的固定键组成，不会出现 `id`、`tags`、`hash`、`password`，`/api/ab/peers` 拼回包时不会和这几个键冲突。
- 设备（可选，来自 `peers`）：按 `MIN(row_id)` 去重；`user_id` 为 0 或映射不到 → NULL；`hostname/os/username/version/uuid` 原样；`first_seen_at`、`last_seen_at` 取 `last_online_time`，为 0 时用导入时间；`last_ip` 取 `last_online_ip`；`sysinfo` 留 `''`。导入时 `device` 表里已经有的行（服务启动后设备心跳写进来的）保留原数据，只补上空着的 `user_id`，并在报告里列出这类设备的数量。令牌不导入，所以导入的归属在设备表满时不受保护：这些设备可能被淘汰，重建后没有归属，要主人到设备上重新登录才能恢复（§9.3，审查 D-8）。

## 16. 测试与验收

- 构建、测试都在 Linux 测试机上跑（`cargo build`、`cargo test`）。每个模块要有单元测试；行为以笔记里的客户端代码为准，不以 rustdesk-api 为准。
- HTTP 契约测试：用 axum `Router` + 临时 SQLite（`tower::ServiceExt::oneshot`，骨架提供测试辅助），逐条断言 §9.1 的约定（状态码、Content-Type、空 body、字段类型），以及地址簿权限、级联、写接口边界、心跳下发规则（含：sysinfo 已存在时响应里没有 `sysinfo` 键；`modified_at` 是 JSON number）。
- 会合测试：在回环地址上起真实监听，模拟客户端做 KeyExchange（v0 和 v1 都测）后发 `PunchHoleRequest`，断言 v6 地址被转发、强制中继时被清空、选中的中继符合路由规则（可参照客户端 `src/common.rs` 里的 `rendezvous_stub` 测试写法）。
- 第三期 01 块（Leapgate 上报路径）的测试：签名向量和客户端共用一组常量（请求头和响应签名逐字节一致）；验签链每种拒绝原因一条（`bad_auth` 不签名不带 `time`，其余 401 带签名和 `time`）；时间窗用固定 now 测 ±60 接受、±61 拒绝；防重放（乱序 30 秒、64 条后 `floor` 抬升、4096 台时淘汰最久未见）；锁定（首个合法请求后库和内存都锁定、从库重新加载的条目也是锁定、公钥已换时条件更新 0 行请求仍成功、库层守卫挡住旧快照换公钥、只换 IP 照常、行已删回 `SERVER_ERROR`）；会合层（锁定后换公钥回 `UUID_MISMATCH`、换 IP OK、不经控制台改库后注册以库为准、锁定条目的重载计入查库预算、已删行的换 IP 注册回 `SERVER_ERROR`）；防降级（锁定后兼容心跳 `{}`、sysinfo 403、审计不入库、登录照样绑定）；Leapgate 心跳（`need_sysinfo`、sysinfo 逐字节存、哈希、按 rev 下发策略、`client_type` 切换、响应签名可验、坏请求体、`leapgate_hb`）；Leapgate 审计（nonce 两路共用、写库失败 503 且 nonce 不登记、体里 `id` 被忽略、`note` 不走备注分支）；中间件（413/405 的 Leapgate 格式、超时和 panic 回 503、未知路径 404）；命令行（`device key` 输出、`device key reset` 改库加 `kl` 重载、回复校验、连不上控制台时报错）；迁移 0004 在第一期的库上执行。
- 第三期 02 块（路由第二级）的测试：`cost::score` 的整端替换（两端、单端、测量没覆盖全部候选退回估计、`down` 去掉候选、全部 `down` 忽略、先 A 后 B、两端都没位置但一端有实测仍有代价、选中那台的两段）；测量表（版本不符、`age_s > 900`、不认识的原串、毫秒越界、形状不对都不影响别的条目，15 分钟按测量时刻过期，满 1 万条先删过期再删最老）；列表版本（同一列表同一值、`rs` 换列表变、空列表非 0、超过 32 台只算前 32）；`select` 用两端测量、固定中继仍优先、换列表后旧测量不用；Leapgate 心跳（`routing_rev` 相同不带 `routing`、不同带，坏 `probes` 照常 200，测量记在验签得到的 ID 下，之后被丢弃的 `probes` 不删它、不带 `probes` 的心跳当场删掉它）；打洞请求带 `leapgate_from_id` 时 `conn_attempt` 记 `rtt` 和两段、超长按空串；控制台 `tg` 和命令行 `route test` 带不带 ID；迁移 0005 在第一期的库上执行。关键断言做过变异验证。
- 第三期 05 块（自研 ICE）的测试（契约 05 §6.1）。和客户端共用的向量（候选 c1、c2 §2.6；证明 §2.8；Binding 请求和 IPv4 响应 §2.9.3；FORWARD 的 `inner`/`sealed`/`msg`/`sig` §2.5）按十六进制原样写进测试，逐字节相等：
  - `ice_stun`：证明 `seal`/`open` 往返（IPv4、IPv6），改任一字节、过期、未来时间、长度 0/27/29/41 都打不开，两条向量逐字节；Binding 请求的识别（短于 100、不是请求、magic 不对、长度不是 4 的倍数都不认）；IPv4 响应向量逐字节，RFC 5769 §2.2、§2.3 自检 XOR-MAPPED-ADDRESS 和 FINGERPRINT；编码器实际生成的 IPv4、IPv6 响应都严格短于门槛。
  - `ice_signal`：候选往返和各种不合规；`filter` 两种模式（公网 IPv4 证明、全局 IPv6 只留前 2 个、各丢弃类和相邻段、同地址去重）；FORWARD 按向量逐字节算出 `sig`、用 B 的种子解出 `inner`、`IdPk::parse_from_bytes(&msg)` 失败、小阶点公钥返回 `None`；`forced_relay`；心跳新鲜度、版本和锁定；会话表（局部的 `Sessions<u32>`：8 条后 `Busy` 且 sink 留在调用方、`Duplicate` 不覆盖、两个 `::ffff:` 映射的 IPv4 来源互不占名额、重发只一次、应答后忽略、`close` 的三种结果和计数复原）。
  - 会合集成（Harness，带 Key 的 `listener_as`、`online_ice`）：OFFER 转成 FORWARD（会合公钥验签、B 的私钥解密）；没做 KeyExchange 或 WebSocket 上发 OFFER 被断开；`OFFLINE`、`RELAY`、`UNSUPPORTED`（没锁定、心跳过期、版本 3009、小阶点）、`BUSY`（同一来源第 9 个）、`BAD`（Key 不对、15 字节 session、17 条候选）各一条；重发同字节、发往 B 的新地址、第三条忽略；ANSWER 带签过的 `IdPk` 到 A，A 不发 RESULT 就关 → 一行 `abandoned`；ANSWER 不合规、`get_pk` 为空 → A 收到 REJECT、A 关连接后没有 `abandoned`；B 的 REJECT 原样到 A；RESULT 只记第一条（版本不对、session 不对、第二条都忽略），之后关连接不再记 `abandoned`；STUN 回包、证明能打开、门槛和令牌桶、`::ffff:` 来源还原。
  - `conn_tracker`：RESULT 转成固定文字（`connected` 才记选中对的字段，不认识的数字记 `unknown`/NULL）；ICE 的两个上限单独计数、和 `conn_attempt` 互不占用；`ice_result` 的写入、90 天删除、20 万行修剪和 `stats` 计数。迁移 0006 在跑过 0001~0005、带数据的库上执行；`_sqlx_migrations` 条数等于 `migrations/` 的文件数（`migrates_existing_hbbs_database`）。
  - 变异验证：REJECT 各分支、公网 IPv4 证明、FORWARD 的签名和加密，以及 RESULT 的三条忽略规则、`abandoned` 的判定、ICE 上限单独计数，各改掉被测的那一行，测试都失败。
- 第四期 01 块（出口目录与设备主人，契约 01 §5.1）的测试：迁移 0007（二选一约束、两个唯一索引、删用户和删组级联、删设备行不影响授权；条数由 `migrates_existing_hbbs_database` 覆盖）；心跳 `exit`（不带为假、带 `true` 为真、之后不带改回假、非布尔值 400 且不改内存记录，`features` 为 `["ice", "exit"]`）；`available` 的三个条件各差一点（注册 29/31 秒、心跳 179/181 秒、`exit` 假、没有心跳记录）；目录接口（401 的三种、405 和库关掉后 200 `{"error":"Server error"}` 的通则格式，主人、授权给本人、授权给组、组员移除和删组、去重、没有设备行的 ID、管理员没有全局视图、恰好四个键、排序，以及真实签名心跳带 `exit` 后在 UDP 注册时列出）；登录绑定（已锁定有主不改、已锁定无主照绑、原主人登出后下一个登录绑定）；延迟补绑（`touch` 的更新、插入和 `store_sysinfo` 三条路径上锁定之后签发的令牌不补绑、同一秒的照补，没锁定照旧，先登录后注册的设备第一次签名心跳既锁定又补绑）；`device owner`（写主人和默认 `device_policy` 行、已有行不变、rev 不变、`none`、报错时不写、没锁定时的提示行、之后别人的登录不改主人、组面板和目录里是新主人、表满时不被淘汰）；`exit grant|revoke|list`（各种报错、重复授权一行、输出文案、表格和末尾行、撤销不查 `peer`）；`changes_database` 对 `exit list` 为假、对 `exit grant`、`exit revoke`、`device owner` 为真。变异验证：延迟补绑的锁定条件、登录绑定的 `case`、`available` 的三个条件、目录查询的组授权分支。
- 第一期验收（部署后由维护者用原版客户端做）：登录、地址簿、设备列表、审计正常；被控端本地写死的中继能被远程清掉；中继按双方位置选择；控制端勾选 IPv6 后两端都有 IPv6 时能直连。

## 17. 工程约定

- 如非必要，勿增实体：不加兜底代码、没人要的配置项、防御性检查；校验只针对会变的东西（用户输入、外部数据、下载的库文件）。
- 新依赖选发布满两周的版本；能用已有依赖就不加新的。
- 提交信息用英文（总仓库 AGENTS.md 2026-10-24：四个公开仓库一律英文），直接 `git commit`（签名身份已自动配置）；每个模块做完再提交，不 push，由主会话统一推送。
- 工作区保持 LF（本仓库设了 `core.eol=lf`）。
