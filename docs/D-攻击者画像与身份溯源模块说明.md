# D 攻击者画像与身份溯源模块说明

## 模块定位

本模块位于 D 的攻击关联分析之后，输入同一批 Event V2 和 `correlate_events()` 生成的
`attack_steps`，输出攻击者指纹、C2 基础设施画像和 APT/TTP 相似性匹配结果。

核心接口：

```python
def build_attribution_profile(
    events: list[dict],
    attack_steps: list[dict],
    host_map: dict[str, str] | None = None,
    apt_profiles: list[dict] | dict | None = None,
    threat_intel: dict | None = None,
    internal_networks: list[str] | None = None,
) -> dict:
    ...
```

后端已提供集成入口：

```text
GET /api/attack-chain/attribution
GET /api/attack-chain/attribution?case_id=apt29_case_001
```

## 输入

- `events`：A 后端返回的 EventOut，证据 ID 使用数据库内部 `id`。
- `attack_steps`：D 侧攻击链关联结果。
- `host_map`：IP 到主机名映射。
- `apt_profiles`：可选 APT 画像库；不传时读取 `data/threat_intel/apt_profiles.json`。
- `threat_intel`：可选 C2/IP/域名情报库；不传时读取 `data/threat_intel/c2_intel.json`。
- `internal_networks`：可选内网 CIDR，用于区分内网资产和外部基础设施。

## 输出

```json
{
  "case_id": "apt29_case_001",
  "entry_points": {
    "source_ips": ["45.77.11.23"],
    "target_hosts": ["web-server"],
    "target_ips": ["192.168.1.10"],
    "evidence_event_ids": [1, 2]
  },
  "fingerprints": {
    "tools": ["bash", "curl", "reg.exe", "wevtutil.exe"],
    "scripts": ["http://45.77.11.23/s.sh"],
    "config_files": [],
    "registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "file_hashes": [],
    "domains": [],
    "external_ips": ["45.77.11.23", "47.88.10.9"],
    "techniques": ["T1059", "T1021", "T1071"],
    "evidence_event_ids": [1, 2, 5, 10, 11]
  },
  "c2_infrastructure": [
    {
      "ip": "47.88.10.9",
      "ports": [4444],
      "protocols": ["tcp"],
      "first_seen": "2026-09-08T13:16:00+08:00",
      "last_seen": "2026-09-08T13:16:00+08:00",
      "evidence_event_ids": [9, 10],
      "intel": {
        "registered_org": "Course Lab VPS Provider",
        "related_domains": ["apt29-c2.lab"]
      }
    }
  ],
  "behavior_sequence": ["Initial Access", "Execution", "Lateral Movement"],
  "apt_matches": [
    {
      "group_id": "G0016",
      "name": "APT29 emulation profile",
      "final_score": 0.76,
      "rule_score": 0.81,
      "semantic_score": 0.64,
      "matched_techniques": ["T1059", "T1021"],
      "matched_tools": ["powershell", "reg"],
      "note": "TTP similarity match only, not confirmed attribution."
    }
  ],
  "evidence_event_ids": [1, 2, 5, 10, 11],
  "note": "Attribution is based on observable TTP similarity and local threat-intel references; it is not a confirmed identity attribution."
}
```

## 关键算法

### 1. 攻击者指纹提取

模块从 `process`、`cmdline`、`detail.file_path`、`detail.hashes`、
`detail.registry_key`、`detail.registry_value_data`、`raw_log` 中提取：

- 工具：`powershell.exe`、`reg.exe`、`curl`、`wevtutil.exe` 等。
- 脚本：`.ps1`、`.bat`、`.sh`、`.py` 等。
- 配置文件：`.conf`、`.ini`、`.json`、`.xml` 等。
- 注册表键：用于识别持久化指纹。
- 文件哈希：用于和后续样本库或威胁情报关联。
- 外部 IP/域名：用于基础设施关联。

### 2. C2 基础设施聚合

模块重点关注 `network_connection`、`http_request`、`dns_query` 和 `file_transfer`。
如果发现内网主机访问外部地址，且命中 C2/外传标签、可疑端口或短时间重复连接，
就按外部 IP/域名聚合为 C2 基础设施节点。

基础设施节点会补充本地情报库中的注册组织、ASN、关联域名、历史记录和标签。
当前实现使用本地 JSON 模拟威胁情报库，后续可替换为 WHOIS、Passive DNS 或商业情报接口。

### 3. APT/TTP 相似性匹配

最终分数使用混合算法：

```text
final_score = 0.7 * rule_score + 0.3 * semantic_score
```

其中规则分：

```text
rule_score =
  0.55 * ATT&CK 技术覆盖度
+ 0.20 * 工具覆盖度
+ 0.15 * 攻击阶段顺序相似度
+ 0.10 * 基础设施标签覆盖度
```

语义分当前使用本地 token cosine，相当于轻量 TF-IDF/词向量相似度的离线版。
如果后续有 embedding API，可以将 `profile_text` 与 APT 画像文本替换为向量相似度计算。

## 注意

本模块输出的是“基于 TTP 的相似性判断”，不是现实世界中的确认归因。
答辩或文档里建议表述为：系统支持攻击者画像生成和与已知 APT 组织的行为特征相似性匹配。
