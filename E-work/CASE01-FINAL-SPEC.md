# CASE01 最终数据集定版说明

## Case01 start/end/timezone

```text
timezone: Asia/Shanghai (+08:00)
case01 evidence window start: 2026-09-09T10:49:14+08:00
case01 evidence window end:   2026-09-09T12:35:33.665578+08:00
```

时间依据：

- Nmap 开始时间：`2026-09-09 10:49:14 +08:00`；
- 最终自动跳板阶段最后一条 Web 日志：`2026-09-09T12:35:33.665440815+08:00`；
- Web→Win10 PCAP 最后数据包：`2026-09-09T12:35:33.665578+08:00`。

需要区分两个时间范围：

```text
整体 Case01 证据窗口：10:49:14–12:35:33.665578
连续自动攻击链窗口：12:35:31–12:35:33.665578
```

Nmap 和 ZAP 在自动跳板链之前执行，因此属于同日 Case01 的前置侦察/漏洞验证证据；它们与 12:35 的自动跳板动作不是无间断连续发生的。

## Canonical Host/IP mapping

| canonical host_id | 展示名称 | 实际 hostname/标识 | IP | 网络 | 角色 |
|---|---|---|---|---|---|
| `case01-attacker-10.10.10.10` | Attack | `attacker` | `10.10.10.10` | VMnet17 | 扫描、ZAP、DVWA触发 |
| `case01-fw-wan` | OPNsense WAN | `10.10.10.1` | VMnet17 | 外部测试网网关 |
| `case01-c2-10.10.10.20` | C2 | `c2` | `10.10.10.20:8080` | VMnet17 | 接收 Beacon/虚假数据 |
| `case01-fw-dmz` | OPNsense DMZ | `10.10.20.1` | VMnet18 | DMZ网关 |
| `case01-web-10.10.20.10` | Web | `web` | `10.10.20.10:80/8088` | VMnet18 | Nginx、DVWA、阶段脚本 |
| `case01-email-10.10.20.20` | Email | `email` | `10.10.20.20:25` | VMnet18 | Postfix SMTP辅助节点 |
| `case01-fw-lan` | OPNsense LAN | `10.10.30.1` | VMnet19 | 内网网关 |
| `case01-office-win-10.10.30.10` | Win10办公机 | `DESKTOP-88HQCN9` | `10.10.30.10:22` | VMnet19 | 跳板机、Windows日志来源 |
| `case01-core-10.10.30.20` | Core | `mxy-VMware-Virtual-Platform` | `10.10.30.20:9100` | VMnet19 | 测试文件服务、Linux auditd |

说明：`case01-office-win-10.10.30.10` 是唯一的 Windows 主机实体。`case01-office`、`office-win`、`DESKTOP-88HQCN9` 都映射到它，不得导入成多台主机。

Core 的 Linux hostname 仍显示为 `mxy-VMware-Virtual-Platform`。主机归属以 IP、节点目录和服务端口为准，不因 hostname 与其他克隆虚拟机相同而合并。

## 正式攻击路径

正式路径固定为：

```text
Attack 10.10.10.10
  -> Web 10.10.20.10:8088
  -> Win10 10.10.30.10:22
  -> Core 10.10.30.20:9100
  -> C2 10.10.10.20:8080
```

对应动作：

1. Attack 使用 Nmap 发现 `10.10.20.10:8088`、`10.10.20.20:25` 和 `10.10.10.20:8080`。
2. Attack 使用 ZAP 访问 DVWA，并在 Command Injection 模块中验证命令执行。
3. Attack 通过 DVWA 请求触发 Web 上的 `case01-stage.sh`。
4. Web 使用专用实验账号登录 Win10 的 SSH 服务。
5. Win10 执行 `jump.ps1`，访问 Core 的 `/finance_demo.txt`，返回 `CASE01_DEMO_FILE`。
6. Win10 访问 C2 的 `/test-beacon?data=CASE01_WIN10_FAKE_DATA`。
7. Core、Win10、Web、C2、OPNsense 和网络抓包保存对应证据。

Email 是并行辅助节点：Attack 对 `10.10.20.20:25` 做了一次 SMTP 服务访问。它不作为 Web→Win10→Core→C2 因果链中的跳板。

## 最终自动导入文件清单

下面文件作为主机/网络自动处理输入。导入时按本文件的时间窗口过滤；原始文件本身保留，不修改。

### Web 主机

```text
raw/web/web-stage.log
raw/web/case01-web-stage.log
raw/web/web-process-audit.txt
raw/web/web-file-audit.txt
raw/web/web-network-audit.txt
raw/web/nginx-access.log
raw/web/web-to-win10.pcap
```

### Win10 办公主机

```text
raw/office-win/security-final.evtx
raw/office-win/system-final.evtx
raw/office-win/win10-jump.log
```

`raw/office-win/audit-policy-final.txt` 是策略配置证据，不是事件流主输入；保留为辅助配置文件。

### Core 主机

```text
raw/core-server/core-file-audit.txt
raw/core-server/core-process-audit.txt
raw/core-server/core-network-audit.txt
raw/core-server/core-auth.log
raw/core-server/core-service.log
raw/core-server/win10-to-core.pcap
```


### C2 主机

```text
raw/c2-server/c2-beacon-final.log
raw/c2-server/win10-to-c2.pcap
```

### 防火墙

```text
raw/firewall/filter.log
```

### Attack 网络

```text
raw/attacker/attack-to-web.pcap
```

PCAP 是原始网络输入；解析时只取对应时间段和目标地址，不能把 PCAP 文件修改后再作为原始证据。

## 辅助证据文件

下面文件用于报告、截图或工具结果展示，不作为主机事件自动导入输入：

```text
raw/attacker/nmap.txt
raw/attacker/2026-09-09-ZAP-Report-.html
raw/attacker/nmap扫描.png
raw/attacker/zap漏洞扫描.png
raw/attacker/dvwa输入成功.png
raw/attacker/开始前准备.png
raw/web/dvwa和抓包准备.png
raw/core-server/服务和抓包准备.png
raw/c2-server/服务和抓包准备.png
raw/email/nmap后email服务日志.txt
```

Nmap 和 ZAP 结果必须保留，因为它们证明了攻击者的侦察和漏洞验证；它们的角色是攻击工具证据，不是 Windows/Linux Host 事件日志。

## C2 需要排除的时间范围

正式自动链只保留下面一条 C2 记录：

```text
2026-09-09T12:35:32.709840+08:00
src=10.10.30.10
path=/test-beacon?data=CASE01_WIN10_FAKE_DATA
```

以下时间范围和记录全部排除出正式自动链：

| 时间 | 原因 |
|---|---|
| `2026-09-08 17:13:11` | 历史测试 |
| `2026-09-08 17:45:15–17:47:50` | Attack 直接访问 C2 的历史测试 |
| `2026-09-08 22:35:04–22:37:36` | Core 直接访问 C2 的旧分阶段测试 |
| `2026-09-09 00:03:44–00:04:03` | Win10 手动跳板预演 |
| `2026-09-09 12:10:55–12:13:38` | Win10 手动/预演记录 |
| `2026-09-09 12:31:51.034348` | 12:35 正式自动链之前的重复执行/重试 |
| `2026-09-09 12:35:32.709840` 之后 | 正式链结束后的记录，如有则排除 |

`12:35:32.709840` 是本次 C2 正式输入的唯一 canonical 记录。

## Windows hostname 对应关系

| 来源字段 | canonical host_id | 说明 |
|---|---|---|
| Windows EVTX hostname `DESKTOP-88HQCN9` | `case01-office-win-10.10.30.10` | Windows真实主机标识 |
| Win10 SSH banner/`hostname` | `DESKTOP-88HQCN9` | 与EVTX相同 |
| Win10跳板日志 `desktop-88hqcn9\case01demo` | `case01-office-win-10.10.30.10` | 用户是 `case01demo`，主机仍是同一台Win10 |
| 报告展示名 `office-win` | `case01-office-win-10.10.30.10` | 逻辑角色名，不是新主机 |
| 报告展示名 `case01-office` | `case01-office-win-10.10.30.10` | 逻辑角色名，不是新主机 |

导入规则：以 `10.10.30.10` 和 `DESKTOP-88HQCN9` 归一化为同一个 Windows 主机；不要把 `desktop-88hqcn9\case01demo` 当作 hostname。

## 冻结状态

```text
E FINAL CASE01 SPEC FROZEN: YES
```

冻结含义：最终 Host/IP 映射、正式路径、自动导入清单、C2 排除规则和 Windows hostname 归一化规则已经确定。当前数据仍有“扫描/ZAP早于12:35自动链”的时间间隔，报告应据此表述为同日 Case01 的前置侦察加连续自动跳板链，不得虚构成无间断时间线。

本次冻结不修改 Parser、Correlation 或 Frontend。
