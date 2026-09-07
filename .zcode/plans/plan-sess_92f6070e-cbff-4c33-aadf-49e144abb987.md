# 按 event_type 冻结枚举规范改正网络模块事件输出

## 差距分析结论（对照 B 的规范文档）

1. **8 类告警自造了 event_type**（port_scan/c2_beacon/dns_tunnel/lateral_movement/exfiltration/suspicious_port/http_attack/icmp_tunnel）——违反"不建议自行新增 event_type"原则。改正：全部映射回冻结枚举，检测名称移入 `anomaly_flags[0]`，ATT&CK 与证据留 `detail`：
   - port_scan / suspicious_port / c2_beacon / exfiltration / icmp_tunnel / lateral_movement → `network_connection`
   - http_attack → `http_request`
   - dns_tunnel → `dns_query`
2. **`icmp_traffic` 不在枚举** → 改为 `network_connection` + `protocol: "icmp"`。
3. **protocol 大小写**：规范示例为小写 `"tcp"` → 输出统一小写（tcp/udp/icmp）。
4. **detail 键名对齐 D 的推荐**：新增 `bytes_in/bytes_out`（需在 pcap/zeek 解析层加每方向字节统计）、`domain`（DNS/HTTP）、`method/uri`（HTTP）；删除冗余的 `dst_port_full`。
5. **anomaly_flags 命名对齐规范示例**：lateral_movement 告警的 flag 改为 `remote_service_connection`（规范示例原文）。
6. **契约自检增强**：`validate_events()` 增加 event_type ∈ 30 个冻结枚举的校验。

## 改动文件

- `models.py`：FlowRecord 增加 `src_bytes/dst_bytes`（每方向字节）
- `pcap_parser.py`：按方向累计字节数
- `zeek_parser.py`：orig_bytes/resp_bytes → src/dst_bytes
- `detectors.py`：exfil 证据键 `bytes` → `bytes_out`
- `normalize.py`：新增 `EVENT_TYPE_ENUM`（30 个冻结值）与 `ANOMALY_EVENT_TYPE` 映射；_flow_type 去掉 icmp_traffic；protocol 小写；detail 增删如上；validate_events 校验 event_type
- `tests/test_network_parser.py`：更新受影响断言（icmp/告警 event_type、bytes_out 键、protocol 小写），新增"全部输出 event_type ∈ 冻结枚举"测试
- `backend/parsers/network/README.md`：规则表与 Event V2 说明更新
- 根 `Readme.md`：契约摘要补一行 event_type 枚举说明

## 验证

pytest 全绿 + CLI 契约自检通过 + 抽查 JSON 确认 event_type/protocol/detail 新键正确。不涉及 git 提交（等 push 网络恢复后一并处理）。