# leapgate-server

[English](#english) | [中文](#中文)

## English

The server of [Leapgate](https://github.com/Ogannesson/leapgate), a remote desktop built on RustDesk. This repository is a hard fork of [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) at `873230e`. Upstream changes are not merged; security fixes are picked by hand.

Leapgate has not been released and this server is not ready for production use.

### What it is

- `leapgate-server` is a single process forked from hbbs. Besides rendezvous, it has a built-in HTTP API (login, address books, user groups, device list, audit logs), latency-based relay selection and a SQLite database. The third-party rustdesk-api is not needed; a one-time import from its database is provided.
- The relay is upstream hbbr, built from this repository with its logic unchanged. Run it with `-k` so it checks the key.
- Stock RustDesk clients (1.4.x to 1.5.x) can use this server. That compatibility is kept only for the first few Leapgate versions.
- Management is done from the command line (`leapgate-server user ...`, `ab ...`, `device ...`, `relay status`, `stats` and so on). There is no web admin panel.

### Building

On Linux:

```
git clone --recurse-submodules https://github.com/Ogannesson/leapgate-server.git
cd leapgate-server
cargo build --release
```

This produces `leapgate-server` and `hbbr` in `target/release/`. `libs/hbb_common` is the submodule [leapgate-cardo](https://github.com/Ogannesson/leapgate-cardo), branch `leapgate/server`.

### Configuration

The hbbs options (`-p`, `-k`, `-r`, `DB_URL` and the rest) work as before. Leapgate's own settings go in `leapgate.toml` in the working directory, or the path given by `--leapgate-config`. The HTTP API listens on port 21114 by default; put a reverse proxy in front of it for HTTPS.

Set `[api] source_url` in `leapgate.toml` to the public URL of the source code you are running, for example this repository. AGPL-3.0 section 13 requires offering the source to users who interact with a modified server over a network, and the page served at `/` on the API port shows this link.

### Documentation

`LEAPGATE.md` describes the scope, configuration, storage and behaviour of every module, in Chinese. The overall design is in the [leapgate](https://github.com/Ogannesson/leapgate) repository. Upstream's original `README.md` is kept unchanged at the repository root.

### License

AGPL-3.0, inherited from rustdesk-server. Leapgate is not affiliated with or endorsed by the RustDesk project; the RustDesk name belongs to its owners.

## 中文

[Leapgate（跃门）](https://github.com/Ogannesson/leapgate)的服务端。Leapgate 是基于 RustDesk 改进的远程桌面。本仓库是 [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) 在 `873230e` 处的硬分叉，不再合并上游，安全修复手工摘取。

Leapgate 还没有发布，这个服务端不建议用于生产环境。

### 是什么

- `leapgate-server` 是从 hbbs 分叉出来的单个进程。除了会合服务，它还内置 HTTP API（登录、地址簿、用户组、设备列表、审计日志）、按延迟选中继的路由策略和 SQLite 数据库。不需要第三方的 rustdesk-api，并提供从它的数据库一次性导入的命令。
- 中继沿用上游的 hbbr，从本仓库构建，逻辑没有改动。运行时加 `-k`，让它校验 key。
- 原版 RustDesk 客户端（1.4.x 到 1.5.x）可以连这个服务端。这份兼容只在 Leapgate 最初的几个版本里保留。
- 用命令行管理（`leapgate-server user ...`、`ab ...`、`device ...`、`relay status`、`stats` 等），没有网页后台。

### 构建

在 Linux 上执行：

```
git clone --recurse-submodules https://github.com/Ogannesson/leapgate-server.git
cd leapgate-server
cargo build --release
```

产物 `leapgate-server` 和 `hbbr` 在 `target/release/` 下。`libs/hbb_common` 是子模块 [leapgate-cardo](https://github.com/Ogannesson/leapgate-cardo) 的 `leapgate/server` 分支。

### 配置

hbbs 原有的参数（`-p`、`-k`、`-r`、`DB_URL` 等）照旧可用。Leapgate 自己的配置写在工作目录下的 `leapgate.toml`，或者用 `--leapgate-config` 指定路径。HTTP API 默认监听 21114 端口，HTTPS 交给前面的反向代理。

`leapgate.toml` 里的 `[api] source_url` 要填你所运行代码的公开源码地址，例如本仓库。AGPL-3.0 第 13 条要求向通过网络使用修改版服务端的用户提供源码，API 端口根路径 `/` 的页面会显示这个链接。

### 文档

`LEAPGATE.md` 写明了各模块的范围、配置、存储和行为，只有中文。总体方案在 [leapgate](https://github.com/Ogannesson/leapgate) 仓库。上游原来的 `README.md` 原样保留在仓库根目录。

### 许可证

AGPL-3.0，继承自 rustdesk-server。Leapgate 与 RustDesk 项目没有关联，也未获其认可；RustDesk 这个名字归其所有者。
