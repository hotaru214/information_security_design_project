# source 扩展交接说明

## 给 A 的交接

本次只扩展 Event V2 中已有的 `source` 字段取值，不新增公共字段。

需要 A 侧同步：

```text
source 枚举增加：
firewall
waf
```

SQLite 层面不需要新增列，因为 `events.source` 已经是文本字段；主要需要同步 Pydantic schema、接口校验、样例数据和相关测试。

D 侧已经适配：

```python
correlate_events(events, host_map=None, internal_networks=None)
```

D 仍然主要根据 `event_type`、`src_ip`、`dst_ip`、`dst_port`、`detail.uri`、`anomaly_flags` 和 `severity` 判断攻击步骤。`source=firewall/waf` 只用于增强 Initial Access 的证据解释，不改变现有 ATT&CK 主规则。

推荐 A 侧 Analysis API 调用：

```python
events = get_events(case_id="apt29_case_001")
host_map = get_host_map()
attack_steps = correlate_events(
    events,
    host_map,
    internal_networks=["10.10.20.0/24", "10.10.30.0/24"],
)
```

## 给 B/C 的交接

本次只要求按真实来源选择 `source`，不改变 `event_type` 主语义。

来源映射：

```text
Zeek 解析结果：
source = network_zeek

PCAP 直接解析结果：
source = network_pcap

防火墙/边界访问日志：
source = firewall

WAF / Web 攻击告警：
source = waf
```

事件类型仍按行为填写：

```text
HTTP 请求：
event_type = http_request

普通连接记录：
event_type = network_connection

DNS 查询：
event_type = dns_query
```

WAF 示例：

```json
{
  "source": "waf",
  "event_type": "http_request",
  "src_ip": "45.77.11.23",
  "dst_ip": "10.10.20.10",
  "dst_port": 80,
  "protocol": "http",
  "detail": {
    "uri": "/upload.php?cmd=whoami",
    "method": "GET",
    "status_code": 200,
    "attack_type": "command_injection",
    "rule_id": "WAF-RCE-001"
  },
  "anomaly_flags": ["web_attack", "initial_access"],
  "severity": 3
}
```

Firewall 示例：

```json
{
  "source": "firewall",
  "event_type": "network_connection",
  "src_ip": "45.77.11.23",
  "dst_ip": "10.10.20.10",
  "dst_port": 80,
  "protocol": "tcp",
  "detail": {
    "action": "allow",
    "rule_name": "allow_web"
  },
  "anomaly_flags": ["initial_access"],
  "severity": 2
}
```

注意：

- `source` 表示证据来自哪里。
- `event_type` 表示发生了什么行为。
- `detail` 只放该来源已有的专有字段，不需要为了 D 额外构造无意义字段。
- `id` 仍然由 A 入库生成，D 的 `evidence_event_ids` 保存数据库 `events.id`。

