# D 交接：case01 主机侧事件已入库（双批共库）

2026-09-12，B 交付。你提的 4 组主机侧日志已全部解析成 Event V2 并与网络侧同库导入。

## 1. 数据在哪

| 文件 | 内容 | 条数 |
|---|---|---|
| `data/sample_events/e_case01_full_db.json` | **合并 EventOut（推荐用这个）**：网络侧 + 主机侧，含真实库 id | 47,915 |
| `data/sample_events/e_case01_eventout.json` | 网络侧单独导出（firewall 588 + network_pcap 132） | 720 |
| `data/sample_events/e_final_host_eventout.json` | 主机侧单独导出（batch_id=e_final_host） | 47,195 |
| `data/attack_trace.db` | 后端 SQLite，当前即双批共库状态 | 47,915 |

两批 batch_id：`e_case01`（网络侧）、`e_final_host`（主机侧）。重建命令：`python scripts/build_case01_full_db.py`（一条命令清库→双批导入→合并导出→校验）。

## 2. 主机侧覆盖情况（对照你的需求清单）

| host | 覆盖 |
|---|---|
| web-server | process_start 185、file_read 30,525、file_write 509、file_delete 86、file_modify 54、network_connection 60（来源 linux_audit） |
| core-server | process_start 143、login_success 5（linux_auth）、network_connection 15,106、file_read 4 |
| win10-jump | process_start 366、login_success 82、login_failed 12、logout 40、service_created 18（Security/System EVTX） |

字段口径（对照你的清单）：
- `timestamp/process/cmdline/src_ip/dst_ip/dst_port/anomaly_flags/severity/raw_log`：全部按 Event V2 FINAL 就位。
- `detail.parent_process`：**Windows 侧有**（4688/Sysmon ID 1 的 ParentImage）。**Linux 侧是 `detail.ppid`**（auditd 不给父进程名）——同主机进程链用 ppid ↔ process_start 事件的 pid 关联（auditd 的 pid 在 detail 里有吗：SYSCALL 记录带 pid，如需把 pid 提升为公共字段再商量）。
- `detail.file_path`：file_read/write/delete/modify 全有；delete/modify 额外带 old_path/new_path（rename）。
- `detail.audit_key`：E 靶场审计规则名（case01_process/case01_file/case01_lateral_*），可直接区分"靶场监控点"。
- 时间全部 UTC+8 ISO8601；Linux 侧以审计序号 detail.audit_serial 跨文件去重。

## 3. getshell 证据（web-server，你要的核心）

主机侧能证明 getshell 后的完整动作链（auditd，key=case01_process）：

```
2026-09-09T12:10:55  bash     cmdline="bash /home/mxy/case01-stage.sh"        ppid=17750
2026-09-09T12:10:55  sshpass  cmdline="sshpass -f ... ssh ... case01demo@10.10.30.10 powershell.exe"
2026-09-09T12:10:45  sshpass  cmdline="sshpass ... case01demo@10.10.30.10 hostname"（连通性测试）
2026-09-09T12:10:55  ssh      → 10.10.30.10（与 C 的 SSH 网络流量同秒对应）
```

跨源对齐（已验证）：
- 主机侧 `sshpass/ssh @12:10:45/12:10:55` ↔ 网络侧 web-server→win10-jump 的 SSH flow @12:10:45/12:10:55，**秒级对齐**；
- 网络侧 T1190（`POST /vulnerabilities/exec/`）@12:31:38/12:31:46/12:35:28 ↔ 主机侧 ping @12:31:47（audit）；
- web→c2-server 的外连 @12:10:55/12:13:38（T1071）在合并库里。

## 4. 跑关联时必须传 internal_networks（重要）

靶场全用 10.x 私网地址，`correlate_events` 默认把私网都当"内网"，攻击机 10.10.10.10 会被当成内部主机，**T1190 初始访问步骤一条都不出**。要显式声明场景边界（攻击网段排除在外）：

```python
steps = correlate_events(events, host_map,
                         internal_networks=["10.10.20.0/24", "10.10.30.0/24"])
```

实测结果：214 步，T1190×20、T1059×151、T1021×26、T1548.003×10、T1543.003×5、T1071×1、T1005×1。

另外我已在 `correlation.py` 的 `INITIAL_ACCESS_FLAGS` 里补了 `http_attack`/`entry_point_candidate`（C 的检测器实际输出的旗标名，此前与 D 的旗标表对不上，真实数据 T1190 全被漏掉）——pytest 205 例全过。

## 5. 一个要如实说明的缺口

**E 的 auditd 规则没抓到 www-data 的进程执行**（audit 规则按 auid≥1000 过滤，www-data 的 auid=unset 被跳过，这是 auditd 配置的经典坑）。所以：
- 注入瞬间（DVWA→www-data→shell）**只有网络侧证据**（T1190，http_request）；
- 主机侧的 case01-stage.sh 执行者是 `auid=mxy`（交互会话），不是 www-data——严格溯源叙事是"网络侧证明注入（T1190）+ 主机侧证明注入后的横向执行链（T1059/T1021）"，两者时间窗对得上但不是同一条进程证据链。答辩被追问时按这个口径说，别把话说满。

## 6. 遗留协调项（给 A/C）

- `data/output/e_case01_events.jsonl` 还是 v1 契约旧格式（event_id 键），别再喂给后端；用 `e_case01_eventout.json` 或合并文件。
- 前端/后端如需按 batch 过滤：detail.batch_id ∈ {e_case01, e_final_host}。
