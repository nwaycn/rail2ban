# rail2ban 使用手册

**版本**: 0.1.0  
**适用平台**: Linux（完整功能）、Windows/macOS（编译运行，无 Unix Socket 和 systemd journal）

rail2ban 是 fail2ban 的 Rust 重实现，兼容 fail2ban 1.1.x 的配置文件格式，提供高性能的日志监控和自动 IP 封禁功能。

---

## 目录

1. [安装与构建](#1-安装与构建)
2. [快速开始](#2-快速开始)
3. [程序说明](#3-程序说明)
   - [rail2ban-server](#31-rail2ban-server)
   - [rail2ban-client](#32-rail2ban-client)
   - [rail2ban-regex](#33-rail2ban-regex)
4. [配置文件](#4-配置文件)
   - [目录结构](#41-目录结构)
   - [fail2ban.conf / rail2ban.conf](#42-fail2banconf--rail2banconf)
   - [jail.conf / jail.local](#43-jailconf--jaillocal)
   - [filter.d/ 过滤器](#44-filterd-过滤器)
   - [action.d/ 动作](#45-actiond-动作)
5. [Jail 配置参数](#5-jail-配置参数)
6. [客户端命令参考](#6-客户端命令参考)
7. [过滤器标签系统](#7-过滤器标签系统)
8. [变量插值](#8-变量插值)
9. [Ban 时间递增](#9-ban-时间递增)
10. [数据库](#10-数据库)
11. [部署指南](#11-部署指南)
12. [与 fail2ban 的差异](#12-与-fail2ban-的差异)
13. [故障排查](#13-故障排查)

---

## 1. 安装与构建

### 前置要求

- Rust 1.75+（推荐 1.92+ stable）
- C 编译器（GCC 或 Clang，用于编译 SQLite bundled 库）
- Linux 部署需要：systemd 开发库（journal 后端）

### 从源码构建

```bash
git clone https://github.com/rail2ban/rail2ban.git
cd rail2ban
cargo build --release
```

构建产物位于 `target/release/`：

| 文件 | 说明 |
|------|------|
| `rail2ban-server` | 守护进程 |
| `rail2ban-client` | 命令行客户端 |
| `rail2ban-regex` | 正则表达式测试工具 |

### 安装到系统

```bash
sudo cp target/release/rail2ban-* /usr/local/bin/
sudo mkdir -p /etc/rail2ban
```

---

## 2. 快速开始

### 最小配置示例

创建 `/etc/rail2ban/jail.conf`：

```ini
[DEFAULT]
bantime  = 10m
findtime = 10m
maxretry = 3
backend  = auto

[sshd]
enabled  = true
filter   = sshd
logpath  = /var/log/auth.log
action   = iptables-multiport[name=sshd, port=ssh, protocol=tcp]
```

创建 `/etc/rail2ban/fail2ban.conf`：

```ini
[Definition]
loglevel  = INFO
logtarget = STDOUT
socket    = /var/run/rail2ban/rail2ban.sock
dbfile    = /var/lib/rail2ban/rail2ban.sqlite3
```

### 启动服务

```bash
# 前台运行（调试）
rail2ban-server -f

# 后台运行
rail2ban-server &

# 查看状态
rail2ban-client status
```

---

## 3. 程序说明

### 3.1 rail2ban-server

守护进程，负责加载配置、监控日志、执行封禁动作。

```
rail2ban-server [OPTIONS]
```

**选项**：

| 选项 | 短选项 | 说明 |
|------|--------|------|
| `--conf <DIR>` | `-c` | 配置目录路径（逗号分隔多个目录），默认 `/etc/rail2ban,/etc/fail2ban` |
| `--socket <FILE>` | `-s` | Unix Socket 路径，覆盖配置文件中的 `socket` |
| `--loglevel <LEVEL>` | | 日志级别：`CRITICAL`/`ERROR`/`WARNING`/`NOTICE`/`INFO`/`DEBUG` |
| `--foreground` | `-f` | 前台运行（不后台化） |
| `--test` | `-t` | 测试配置文件语法并退出 |
| `--dump` | `-d` | 打印解析后的配置并退出 |
| `--version` | `-V` | 显示版本号 |

**示例**：

```bash
# 测试配置
rail2ban-server -t

# 打印配置
rail2ban-server -d

# 指定配置目录前台运行
rail2ban-server -c /etc/rail2ban -f

# 自定义 socket 和日志级别
rail2ban-server -s /tmp/rail2ban.sock --loglevel DEBUG -f
```

### 3.2 rail2ban-client

命令行客户端，通过 Unix Socket 与 server 通信。

```
rail2ban-client [OPTIONS] <COMMAND> [ARGS...]
```

**选项**：

| 选项 | 短选项 | 说明 |
|------|--------|------|
| `--conf <DIR>` | `-c` | 配置目录 |
| `--socket <FILE>` | `-s` | Socket 路径，默认 `/var/run/rail2ban/rail2ban.sock` |
| `--timeout <SECS>` | | 超时秒数，默认 30 |
| `--str2sec <STRING>` | | 将时间字符串转换为秒并退出 |
| `--dump` | `-d` | 转储配置 |
| `--test` | `-t` | 测试配置 |

**示例**：

```bash
# 查看所有 jail 状态
rail2ban-client status

# 查看特定 jail 详情
rail2ban-client status sshd

# 手动封禁 IP
rail2ban-client set sshd banip 1.2.3.4

# 解封 IP
rail2ban-client unban 1.2.3.4

# 解封所有
rail2ban-client unban --all

# 重载配置
rail2ban-client reload

# 重启某个 jail
rail2ban-client restart sshd

# 时间字符串转秒
rail2ban-client --str2sec 1d6h
# 输出: 108000
```

### 3.3 rail2ban-regex

离线正则表达式测试工具，用于验证 filter 配置是否正确匹配日志。

```
rail2ban-regex [OPTIONS] <LOG> <FILTER> [DATEPATTERN]
```

**参数**：

| 参数 | 说明 |
|------|------|
| `<LOG>` | 日志文件路径，`-` 表示从 stdin 读取 |
| `<FILTER>` | filter 名称（如 `sshd`）或内联 failregex |
| `<DATEPATTERN>` | 可选的日期模式 |

**选项**：

| 选项 | 说明 |
|------|------|
| `-c <DIR>` | 配置目录 |
| `-v` | 打印每行匹配结果 |

**示例**：

```bash
# 使用 named filter 测试
rail2ban-regex /var/log/auth.log sshd

# 使用内联正则测试
rail2ban-regex /var/log/auth.log "Failed password for .* from <HOST>"

# 从 stdin 测试
cat /var/log/auth.log | rail2ban-regex - sshd

# 指定日期模式
rail2ban-regex /var/log/auth.log sshd "%Y-%m-%d %H:%M:%S"

# 详细输出
rail2ban-regex -v /var/log/auth.log sshd
```

---

## 4. 配置文件

### 4.1 目录结构

rail2ban 兼容 fail2ban 的目录结构：

```
/etc/rail2ban/
├── fail2ban.conf          # 全局配置（或 rail2ban.conf）
├── fail2ban.d/            # 全局配置片段（*.conf）
├── jail.conf              # Jail 主配置（或 rail2ban.conf）
├── jail.d/                # Jail 配置片段
│   ├── *.conf
│   └── *.local
├── jail.local             # Jail 本地覆盖
├── filter.d/              # 过滤器定义
│   ├── sshd.conf
│   ├── apache-auth.conf
│   └── ...
└── action.d/              # 动作定义
    ├── iptables-multiport.conf
    ├── sendmail.conf
    └── ...
```

**配置加载顺序**（后者覆盖前者）：

1. `jail.conf` / `rail2ban.conf`
2. `jail.d/*.conf`（按文件名排序）
3. `jail.local` / `rail2ban.local`
4. `jail.d/*.local`（按文件名排序）

多个 `--conf` 目录按顺序加载，后者覆盖前者。

### 4.2 fail2ban.conf / rail2ban.conf

全局配置，控制 server 行为：

```ini
[Definition]
loglevel  = INFO
logtarget = STDOUT
socket    = /var/run/rail2ban/rail2ban.sock
pidfile   = /var/run/rail2ban/rail2ban.pid
dbfile    = /var/lib/rail2ban/rail2ban.sqlite3
dbmaxmatches = 10
dbpurgeage    = 1d
allowipv6 = auto

[Thread]
stacksize = 0
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `loglevel` | `INFO` | 日志级别 |
| `logtarget` | `STDOUT` | 日志输出目标 |
| `socket` | `/var/run/rail2ban/rail2ban.sock` | Unix Socket 路径 |
| `pidfile` | `/var/run/rail2ban/rail2ban.pid` | PID 文件 |
| `dbfile` | `/var/lib/rail2ban/rail2ban.sqlite3` | 数据库文件（`none` 禁用） |
| `dbmaxmatches` | `10` | 每个 ticket 在数据库中保存的最大匹配行数 |
| `dbpurgeage` | `1d` | 历史记录清理周期 |
| `allowipv6` | `auto` | IPv6 支持 |
| `stacksize` | `0` | 线程栈大小（KiB），0 = 系统默认 |

### 4.3 jail.conf / jail.local

Jail 配置使用 INI 格式，`[DEFAULT]` 节的值被所有 jail 继承：

```ini
[DEFAULT]
# 全局默认值
bantime  = 10m
findtime = 10m
maxretry = 3
backend  = auto
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16
ignoreself = true

[sshd]
enabled = true
filter  = sshd
logpath = /var/log/auth.log
action  = iptables-multiport[name=sshd, port=ssh, protocol=tcp]
maxretry = 5

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/rail2ban.log
bantime  = 1w
findtime = 1d
maxretry = 3
```

### 4.4 filter.d/ 过滤器

过滤器定义了如何从日志行中提取失败信息：

```ini
# filter.d/sshd.conf
[INCLUDES]
before = common.conf

[Definition]
_daemon = sshd

prefregex = ^<F-MLFID>\s*(?:\S+\s+)?(?:<F-MLFID>\d+\s+)?(?:<F-MLFID>\S+\s+)?<HOST> (?:error: PAM: )?Authentication failure(?: for user [^\s]+)?\s*$

failregex = ^<F-MLFID>.*?</F-MLFID> authentication failure; .* rhost=<HOST>.*$
            ^<F-MLFID>.*?</F-MLFID> Failed password for (?:invalid user )?\S+ from <HOST>.*$
            ^<F-MLFID>.*?</F-MLFID> Connection (?:closed|reset) by (?:invalid user )?<HOST>.*$

ignoreregex =

datepattern = {^LN-BEG}%%Y-%%m-%%d[T ]%%H:%%M:%%S(?:\.\d+)?(?:%z)?
              {^LN-BEG}%%b %%d %%H:%%M:%%S

maxlines = 1

[Init]
# 默认参数
mode = normal
```

**关键元素**：

| 元素 | 说明 |
|------|------|
| `[INCLUDES]` | 引入其他 filter 文件（`before`/`after`） |
| `[Definition]` | 主定义节 |
| `prefregex` | 预处理正则，提取 `content` 和 `mlfid` |
| `failregex` | 失败匹配正则（每行一个） |
| `ignoreregex` | 忽略正则（匹配的行跳过） |
| `datepattern` | 日期解析模式 |
| `maxlines` | 多行缓冲行数 |
| `[Init]` | 默认参数值 |

### 4.5 action.d/ 动作

动作定义了封禁/解禁时执行的命令：

```ini
# action.d/iptables-multiport.conf
[INCLUDES]
before = iptables-blocktype.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> --dport <port> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> --dport <port> -j f2b-<name>
             <iptables> -F f2b-<name>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

actionflush = <iptables> -F f2b-<name>

actionrepair = <iptables> -N f2b-<name>
               <iptables> -A f2b-<name> -j <returntype>

[Init]
name = default
port = ssh
protocol = tcp
chain = INPUT
blocktype = REJECT
returntype = RETURN
iptables = iptables
```

**动作生命周期**：

| 阶段 | 命令 | 触发时机 |
|------|------|----------|
| `actionstart` | 初始化 | jail 启动时（或首次 ban 时，如果 `actionstart_on_demand`） |
| `actioncheck` | 状态检查 | 每次 `actionban` 前 |
| `actionrepair` | 修复 | `actioncheck` 失败时 |
| `actionban` | 封禁 IP | 达到 `maxretry` 时 |
| `actionunban` | 解封 IP | ban 过期或手动解封 |
| `actionflush` | 批量清除 | `unban --all` 时（优先于逐个 unban） |
| `actionstop` | 清理 | jail 停止时 |

---

## 5. Jail 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 是否启用 |
| `filter` | string | (必填) | filter 名称，对应 `filter.d/<name>.conf` |
| `logpath` | string[] | (必填) | 监控的日志文件路径（空格分隔），支持 glob |
| `backend` | string | `auto` | 日志后端：`auto`/`inotify`/`polling`/`systemd` |
| `logencoding` | string | `auto` | 日志编码 |
| `logtimezone` | string | | 日志时区（如 `UTC+0800`） |
| `journalmatch` | string[] | | systemd journal 匹配表达式 |
| `maxretry` | u32 | `3` | `findtime` 内失败次数达到此值触发 ban |
| `findtime` | time | `10m` | 失败计数窗口 |
| `bantime` | time | `10m` | ban 时长 |
| `bantime_increment` | bool | `false` | 启用递增 ban |
| `bantime_factor` | u32 | `1` | 递增因子 |
| `bantime_maxtime` | time | | 递增上限 |
| `bantime_rndtime` | time | | 随机抖动时长 |
| `usedns` | string | `warn` | DNS 解析模式：`yes`/`warn`/`no`/`raw` |
| `ignoreself` | bool | `true` | 忽略本机 IP |
| `ignoreip` | string[] | | 白名单 IP/CIDR |
| `ignorecommand` | string | | 外部忽略检查命令 |
| `ignorecache` | string | | 忽略结果缓存配置 |
| `action` | string[] | | 动作列表 |
| `actionstart_on_demand` | bool | `false` | 延迟 `actionstart` 到首次 ban |
| `maxlines` | u32 | `1` | 多行匹配缓冲行数 |
| `maxmatches` | u32 | `10` | 每 ticket 保存的最大匹配行 |
| `skip_if_nologs` | bool | `false` | 无日志时跳过启动 |
| `systemd_if_nologs` | bool | `false` | 无日志时切换到 systemd 后端 |

**时间格式**：`10m`=10分钟，`1h`=1小时，`1d`=1天，`1w`=1周，`permanent`=永久

---

## 6. 客户端命令参考

### status — 查看状态

```bash
# 查看所有 jail
rail2ban-client status
# 返回: {"jails": ["sshd", "apache"], "count": 2}

# 查看特定 jail 详情
rail2ban-client status sshd
# 返回: {"jail":"sshd", "currently_banned":3, "total_banned":15, ...}
```

### start / stop — 启动停止 Jail

```bash
rail2ban-client start sshd        # 启动指定 jail
rail2ban-client start --all       # 启动所有 enabled jail
rail2ban-client stop sshd         # 停止指定 jail
rail2ban-client stop              # 停止所有 jail
```

### reload — 重载配置

```bash
rail2ban-client reload            # 重载所有配置并重启所有 jail
rail2ban-client reload sshd       # 重启指定 jail
rail2ban-client reload --all      # 同 reload
```

### restart — 重启 Jail

```bash
rail2ban-client restart sshd      # 停止再启动指定 jail
```

### unban — 解封 IP

```bash
rail2ban-client unban 1.2.3.4     # 解封指定 IP（所有 jail）
rail2ban-client unban 1.2.3.4 5.6.7.8  # 解封多个 IP
rail2ban-client unban --all       # 解封所有 IP（触发 actionflush）
```

### banned — 查询封禁状态

```bash
rail2ban-client banned            # 查看所有被封 IP（按 jail 分组）
rail2ban-client banned 1.2.3.4    # 查询 IP 在哪些 jail 中被封
```

### get — 查询配置

```bash
rail2ban-client get loglevel
rail2ban-client get dbfile
rail2ban-client get sshd bantime
rail2ban-client get sshd maxretry
rail2ban-client get sshd failregex
```

### set — 修改运行时配置

```bash
# 全局设置
rail2ban-client set loglevel DEBUG
rail2ban-client set dbmaxmatches 20

# Jail 操作
rail2ban-client set sshd banip 1.2.3.4      # 手动封禁
rail2ban-client set sshd unbanip 1.2.3.4    # 手动解封
rail2ban-client set sshd attempt 1.2.3.4 "failure line"  # 模拟失败
```

### add — 添加 Jail

```bash
rail2ban-client add sshd auto    # 添加并启动 jail
```

### 其他命令

```bash
rail2ban-client ping              # 心跳检测，返回 pong
rail2ban-client version           # 版本号
rail2ban-client echo hello        # 回显
rail2ban-client statistics        # 所有 jail 统计
```

---

## 7. 过滤器标签系统

rail2ban 支持 fail2ban 的 F-* 标签系统，在 failregex/prefregex 中使用：

### 标签列表

| 标签 | 正则组名 | 说明 |
|------|----------|------|
| `<HOST>` | `host` | 主机/IP 地址（核心标签，用于封禁目标） |
| `<F-USER>` | `user` | 用户名 |
| `<F-ALT_USER>` | `alt_user` | 备用用户名 |
| `<F-MLFID>` | `mlfid` | 多行失败 ID（关联多行日志） |
| `<F-NOFAIL>` | `nofail` | 匹配但不计为失败 |
| `<F-MLFFORGET>` | `mlfforget` | 忘记此 MLFID 的失败记录 |
| `<F-MLFGAINED>` | `mlfgained` | 成功事件（重置失败计数） |
| `<F-CONTENT>` | `content` | 内容捕获（较少使用） |

### 标签语法

**单标签**（自闭合）：

```regex
Failed password for \S+ from <HOST>
```

**配对标签**（含内容）：

```regex
<F-MLFID>session \d+</F-MLFID> Failed password from <HOST>
```

配对标签会递归展开内部的标签。

### `<HOST>` 匹配规则

`<HOST>` 展开为匹配 IP 地址或主机名的正则，包括：
- IPv4 地址
- IPv6 地址
- IPv6 映射的 IPv4 地址（`::ffff:1.2.3.4`）
- 主机名（配合 `usedns` 设置决定是否解析）

### `<F-NOFAIL>` 用法

用于匹配需要记录但不立即计为失败的行（如 PAM 的 `conversation failed`）：

```regex
<F-NOFAIL>Authentication failure</F-NOFAIL> for .* from <HOST>
```

### `<F-MLFID>` 多行关联

用于关联跨越多行的失败事件（如 dovecot 的 session）：

```regex
<F-MLFID>session=<\d+></F-MLFID>.*auth failure.*rhost=<HOST>
```

---

## 8. 变量插值

rail2ban 支持 fail2ban 的变量插值机制：

### `%(name)s` 插值

```ini
[DEFAULT]
port = ssh
bantime = 10m

[sshd]
# 引用 DEFAULT 中的变量
action = iptables-multiport[port=%(port)s]
bantime = %(bantime)s
```

### `%(section/parameter)s` 跨节引用

```ini
[sshd]
action = iptables-multiport[port=%(sshd/port)s]
```

### `<known/parameter>` 动态插值

```ini
[Init]
# 根据当前 jail 动态解析
name = <known/name>
```

### `<lt_<logtype>/...>` 条件插值

根据 `logtype` 的值选择不同的参数：

```ini
[lt_file]
datepattern = %%Y-%%m-%%d

[lt_journal]
datepattern = %%Y-%%m-%%dT%%H:%%M:%%S

[Init]
datepattern = <lt_<logtype>/datepattern>
```

### `<ipt_<type>/...>` IP 类型条件

根据 IP 类型（v4/v6）选择参数：

```ini
[ipt_ipv4]
action_rule = iptables -I f2b-<name> 1 -s <ip> -j <blocktype>

[ipt_ipv6]
action_rule = ip6tables -I f2b-<name> 1 -s <ip> -j <blocktype>

[Init]
action_rule = <ipt_<family>/action_rule>
```

---

## 9. Ban 时间递增

`bantime_increment` 启用递增 ban，对重复违规者逐渐增加封禁时长：

```ini
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/rail2ban.log
bantime  = 1w
findtime = 1d
maxretry = 3

# 递增配置
bantime_increment = true
bantime_factor    = 2        # 每次翻倍
bantime_maxtime   = 4w       # 上限 4 周
bantime_rndtime   = 5m       # 随机增加 0-5 分钟（防同步重试）
```

**计算公式**：

```
actual_bantime = min(bantime * factor^(ban_count), maxtime) + random(0, rndtime)
```

`ban_count` 从数据库历史记录查询，同一 IP 的历史封禁次数。

---

## 10. 数据库

rail2ban 使用 SQLite 持久化 ban 记录。

### 表结构

**`bans` 表** — 完整 ban 历史：

| 列 | 类型 | 说明 |
|----|------|------|
| `jail` | TEXT | Jail 名称 |
| `ip` | TEXT | IP/失败 ID |
| `timeofban` | INTEGER | ban 开始时间（epoch） |
| `bantime` | INTEGER | ban 时长秒数（NULL = 永久） |
| `data` | TEXT | JSON 编码的额外数据 |

**`bips` 表** — 当前 ban 索引（每个 jail+ip 一条）：

| 列 | 类型 | 说明 |
|----|------|------|
| `jail` | TEXT | Jail 名称 |
| `ip` | TEXT | IP/失败 ID |
| `timeofban` | INTEGER | 最近的 ban 时间 |

### 数据库行为

- **重启恢复**: server 重启时，从 `bips` 表读取当前活跃 ban 并恢复到 BanManager（不会重复执行 `actionban`，假定防火墙规则仍然有效）
- **自动清理**: `purge` 操作删除过期的历史记录，保留活跃 ban 的记录
- **递增查询**: `bantime_increment` 通过 `ban_count(jail, ip)` 查询历史 ban 次数
- **禁用数据库**: 设置 `dbfile = none` 可禁用持久化（使用内存）

---

## 11. 部署指南

### systemd 服务

创建 `/etc/systemd/system/rail2ban.service`：

```ini
[Unit]
Description=rail2ban Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rail2ban-server -f
ExecStop=/usr/local/bin/rail2ban-client stop
PIDFile=/var/run/rail2ban/rail2ban.pid
Restart=on-failure
RuntimeDirectory=rail2ban

[Install]
WantedBy=multi-user.target
```

启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rail2ban
```

### 日志轮转

创建 `/etc/logrotate.d/rail2ban`：

```
/var/log/rail2ban.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        /usr/local/bin/rail2ban-client flushlogs
    endscript
}
```

### 权限设置

```bash
# 运行目录
sudo mkdir -p /var/run/rail2ban /var/lib/rail2ban
sudo chown root:root /var/run/rail2ban /var/lib/rail2ban

# 配置目录
sudo chown -R root:root /etc/rail2ban
```

### 与 fail2ban 共存

rail2ban 可以读取 fail2ban 格式的配置文件。如果要从 fail2ban 迁移：

```bash
# 使用 fail2ban 的配置目录启动
rail2ban-server -c /etc/fail2ban -f

# 或创建符号链接
sudo ln -s /etc/fail2ban/filter.d /etc/rail2ban/filter.d
sudo ln -s /etc/fail2ban/action.d /etc/rail2ban/action.d
```

**注意**：不要同时运行 fail2ban 和 rail2ban，避免冲突。

---

## 12. 与 fail2ban 的差异

### 兼容性

- **配置文件**: 完全兼容 fail2ban 1.1.x 的 `jail.conf`/`filter.d/`/`action.d/` 格式
- **过滤器标签**: 完整支持 `<HOST>`、`<F-USER>`、`<F-MLFID>` 等 F-* 标签
- **变量插值**: 支持 `%(name)s`、`%(section/param)s`、`<known/...>`、`<lt_...>`、`<ipt_...>`
- **客户端命令**: 兼容主要命令（`status`、`start`、`stop`、`reload`、`unban`、`set`、`get`）

### 差异点

| 方面 | fail2ban | rail2ban |
|------|----------|----------|
| 实现语言 | Python | Rust |
| 协议 | 自定义文本协议 | JSON over Unix Socket |
| 性能 | 解释执行 | 编译执行，更低资源占用 |
| 后端 | pyinotify/polling/systemd | inotify/polling/systemd |
| DNS 解析 | 同步 | 异步（spawn_blocking） |
| 数据库 | SQLite (python) | SQLite (rusqlite bundled) |
| 动作执行 | subprocess | tokio::process |
| actioncheck | ban 前检查 | ban 前检查 + actionrepair 重试 |

### 已知限制

- Windows/macOS 上不支持 Unix Socket 和 systemd journal 后端
- 不支持 Python 特有的 action 脚本（如 `action.d/dummy.conf` 中的 Python 代码）
- `reload` 命令需要重新加载整个配置（不支持增量重载）

---

## 13. 故障排查

### server 启动失败

```bash
# 检查配置语法
rail2ban-server -t

# 查看详细日志
rail2ban-server -f --loglevel DEBUG

# 确认 socket 目录存在
ls -la /var/run/rail2ban/

# 确认端口未被占用
lsof /var/run/rail2ban/rail2ban.sock
```

### client 连接失败

```bash
# 确认 server 正在运行
ps aux | grep rail2ban-server

# 确认 socket 文件存在
ls -la /var/run/rail2ban/rail2ban.sock

# 指定 socket 路径
rail2ban-client -s /var/run/rail2ban/rail2ban.sock ping
```

### Filter 不匹配

```bash
# 使用 rail2ban-regex 测试
rail2ban-regex -v /var/log/auth.log sshd

# 检查日志编码
file /var/log/auth.log

# 确认日期模式
rail2ban-regex -v /var/log/auth.log "Failed password for .* from <HOST>" "%b %d %H:%M:%S"
```

### Ban 不生效

```bash
# 检查 jail 状态
rail2ban-client status sshd

# 确认 action 命令可执行
# 手动测试 actionban 命令
iptables -I f2b-sshd 1 -s 1.2.3.4 -j REJECT

# 检查 ignoreip 白名单
rail2ban-client get sshd ignoreip

# 查看 action 日志
journalctl -u rail2ban -f
```

### 数据库问题

```bash
# 检查数据库
sqlite3 /var/lib/rail2ban/rail2ban.sqlite3 "SELECT * FROM bips;"

# 查看历史记录
sqlite3 /var/lib/rail2ban/rail2ban.sqlite3 "SELECT * FROM bans ORDER BY timeofban DESC LIMIT 10;"

# 手动清理
sqlite3 /var/lib/rail2ban/rail2ban.sqlite3 "DELETE FROM bans WHERE timeofban < strftime('%s','now') - 86400;"

# 禁用数据库（调试用）
rail2ban-client set dbfile none
```

### 调试模式

```bash
# 启动 server 时开启 DEBUG 日志
rail2ban-server -f --loglevel DEBUG

# 或运行时切换
rail2ban-client set loglevel DEBUG

# 查看特定 jail 的匹配详情
rail2ban-client status sshd
```

---

## 附录：时间格式参考

| 格式 | 示例 | 秒数 |
|------|------|------|
| `Ns` | `30s` | 30 |
| `Nm` | `10m` | 600 |
| `Nh` | `1h` | 3600 |
| `Nd` | `1d` | 86400 |
| `Nw` | `1w` | 604800 |
| `permanent` | `permanent` | 18446744073709551615 (u64::MAX) |
| 组合 | `1d6h` | 108000 |

使用 `--str2sec` 验证：

```bash
rail2ban-client --str2sec "1d6h30m"
# 输出: 109800
```
