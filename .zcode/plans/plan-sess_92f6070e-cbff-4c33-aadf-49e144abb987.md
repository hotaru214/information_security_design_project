# 成员C今日任务：网络流量解析模块（network event parser）

## 目标

一次性完成分工中 C 的 Day 1 + Day 2 任务：交付一个**可独立运行的网络流量解析与异常检测模块**，输入 PCAP（及 Zeek 日志/CSV 连接日志），输出统一格式安全事件 JSON，覆盖任务书要求的四点：流量捕获与解析、网络会话重建、异常协议行为建模、隐蔽信道检测（DNS/HTTP/ICMP）。

## 技术选型

- **scapy**（pip 安装，Windows 离线读 pcap 无需管理员权限）做 PCAP 包解析——分工建议的 Zeek 在 Windows 上安装困难，改为：包解析用 scapy，同时提供 Zeek conn.log/dns.log/http.log 读取器，若队友在 Linux 上产出 Zeek 日志可直接导入，两种输入都支持。
- 检测逻辑纯 Python 标准库，无重型依赖。

## 实施步骤

1. **搭目录**：`backend/parsers/network/`（模块代码）、`data/network_logs/`（样例数据）、`scripts/`（工具脚本），`requirements.txt` 加入 scapy。

2. **样例数据生成器 `scripts/gen_sample_pcap.py`**：用 scapy 生成模拟"企业内网完整攻击链"的 PCAP（Case 01），同时输出 `data/hosts.csv`（IP→主机名映射，与E的8节点拓扑对齐，可改）：
   - 正常背景流量（办公机浏览网页、DNS查询、邮件）
   - 攻击者 203.0.113.66 → Web服务器 10.0.0.5：端口扫描 → HTTP攻击请求 → 反弹Shell到攻击者:4444
   - 横向移动 Web → 办公机 10.0.0.21（SMB/RDP）→ 核心服务器 10.0.0.10
   - 核心服务器 → C2 185.199.108.153:8443 周期性心跳（beacon）
   - DNS隧道探测（超长高熵子域名/TXT查询）+ 大流量数据外传 + 异常ICMP大包

3. **`pcap_parser.py` 流量解析与会话重建**：流式读取 PCAP（不占大内存），按五元组聚合为连接会话（起止时间、包数、字节数、TCP标志），并从载荷中提取 DNS 查询（域名/类型）、HTTP 请求（方法/URI/UA）、ICMP 概要。

4. **`zeek_parser.py`**：解析 Zeek conn.log / dns.log / http.log（TSV 和 JSON 两种格式），转成同样的会话记录。

5. **`detectors.py` 异常检测**：端口扫描（同源大量SYN不同端口）、C2心跳（周期性规律外联）、可疑端口连接（4444等可配置清单）、DNS隧道嫌疑（高熵长域名/TXT查询量）、大流量外传（内→外大字节/长时长）、ICMP隧道嫌疑（超大载荷/周期性）——每条告警带证据字段、严重级别和攻击阶段提示（Reconnaissance/Initial Access/Lateral Movement/Command and Control/Exfiltration）。

6. **`normalize.py` 统一事件输出**：会话记录+告警 → 分工文档定义的统一事件 JSON（timestamp/source/event_type/severity/src_ip/dst_ip/protocol/description/attack_stage/evidence…），host 映射后带主机名，方便D做跨源关联。

7. **`cli.py` 命令行入口**：`python -m backend.parsers.network data/network_logs/case01.pcap --hosts data/hosts.csv --out out/network_events.json`，终端打印统计摘要（包数→会话数→告警数→攻击阶段时间线预览），输出 JSON 直接可用于 POST /api/events/import。

8. **测试**：pytest 覆盖熵计算、端口扫描/心跳/DNS隧道检测、PCAP小样例端到端解析。

9. **集成文档 `backend/parsers/network/README.md`**：用法、输出事件 schema、与A的import接口约定、与D的字段约定（D关联分析可直接依赖哪些字段）。

10. **端到端验证**：生成样例PCAP → 跑CLI → 确认能自动检出全部预埋攻击行为并输出事件JSON；pytest 通过。

## 交付物

- 可运行的 network parser 模块 + 测试
- 一套覆盖完整攻击链的样例 PCAP 与 hosts 映射（后续E真实靶场数据产出后可直接替换重跑）
- 集成说明文档（A/D 对接用）

## 明确不做（今天）

- 报告章节/PPT（Day 3）、真实靶场数据采集（E负责）、FastAPI集成（A负责，本模块只保证接口约定清晰）。