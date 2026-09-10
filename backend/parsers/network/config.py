"""检测阈值与网络环境配置。

所有阈值集中在此，答辩演示或对接真实靶场数据（E 产出）时可按需调整，
也支持 CLI 传入 JSON 文件整体覆盖（见 cli.py --config）。
"""
import ipaddress
from dataclasses import dataclass, field

# RFC1918 内网网段默认值，可用 --internal 覆盖
INTERNAL_NETWORKS_DEFAULT = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# 常见远控/后门端口，出现即告警（可配置）
SUSPICIOUS_PORTS = {4444, 4445, 5555, 1337, 31337, 6666, 6667, 9999}

# 内网横向移动常用远程服务端口
REMOTE_SERVICE_PORTS = {22, 23, 139, 445, 3389, 5985, 5986}
SERVICE_NAMES = {22: "SSH", 23: "Telnet", 139: "NetBIOS", 445: "SMB",
                 3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS"}

HTTP_PORTS = {80, 8080, 8000, 8088}   # 明文 HTTP 请求行启发式端口（8088=E靶场 DVWA/Nginx 实际端口）

# HTTP 请求中的攻击载荷特征（正则, 说明）
HTTP_ATTACK_PATTERNS = [
    (r"union[\s+]+select", "SQL注入特征(UNION SELECT)"),
    (r"('|%27)\s*or\s*('|%27)?\s*1('|%27)?\s*=\s*('|%27)?\s*1", "SQL注入特征(OR 1=1)"),
    (r"('|%27)\s*--", "SQL注入特征(注释符--)"),
    (r"\.\./\.\./", "路径穿越特征(../../)"),
    (r"/etc/(passwd|shadow)", "敏感文件访问特征(/etc/passwd)"),
    (r"(?<![a-z])(cmd|exec|command)=", "命令执行参数特征"),   # 负向断言排除 utmcmd= 等统计参数误报
    (r"eval\s*\(", "代码执行特征(eval)"),
    (r"(&&|\|\||;)\s*/?[\w./\-]+\.(sh|py|php|bat|ps1)\b", "命令注入特征(链接执行脚本)"),
    (r"base64_decode", "Webshell特征(base64_decode)"),
    (r"<script", "XSS特征(<script)"),
]


# 各数据批次的标准网络分段预设（封箱定案，2026-09-09）。
# 用途：CLI --profile <name>，使操作员无需手工记忆 --internal/--hosts 参数。
# 网段定案：E case01 靶场三段式中 10.10.10.*(WAN: Attack/C2)=external、
#           10.10.20.*(DMZ) 与 10.10.30.*(LAN)=internal；case01 数据集 10.0.0.0/24=internal。
PROFILES = {
    "case01": {"internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
               "hosts": "data/hosts.csv"},
    "case02": {"internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
               "hosts": ""},
    "apt29_day1": {"internal_networks": ["10.0.0.0/16"],
                   "hosts": "data/hosts_apt29.csv"},
    "ctu13_s2": {"internal_networks": ["147.32.0.0/16"],
                 "hosts": "data/hosts_ctu13.csv"},
    "e_case01": {"internal_networks": ["10.10.20.0/24", "10.10.30.0/24"],
                 "hosts": "data/hosts_e_case01.csv"},
}


@dataclass
class DetectionConfig:
    internal_networks: list = field(default_factory=lambda: list(INTERNAL_NETWORKS_DEFAULT))

    # 端口扫描：同一源IP对同一目标IP 出现的不同端口数
    scan_port_threshold: int = 10

    # C2 心跳：同源同目的(IP:端口)的周期性连接
    beacon_min_count: int = 4
    beacon_min_interval: float = 5.0
    beacon_max_interval: float = 3600.0
    beacon_jitter_ratio: float = 0.35   # 间隔标准差/均值 上限，越小说越规律

    # DNS 隐蔽信道
    dns_long_label: int = 25            # 单个域名标签长度下限
    dns_entropy_threshold: float = 3.5  # 标签香农熵下限（随机编码串通常 >4）
    dns_min_label_for_entropy: int = 20 # 熵检测要求的最短标签（避免短词误报）
    dns_txt_volume: int = 6             # 同源对同域名的 TXT 查询次数阈值

    # 数据外传
    exfil_bytes: int = 1_000_000            # 内->外单会话字节数阈值
    exfil_duration_sec: float = 300.0       # 或：长会话 + 一定数据量
    exfil_bytes_with_duration: int = 200_000
    exfil_critical_bytes: int = 10_000_000

    # ICMP 隐蔽信道
    icmp_large_payload: int = 256       # 单包 ICMP 载荷字节数
    icmp_count_threshold: int = 20      # 同会话 ICMP 包数量

    # 登录爆破（网络侧证据）：同源对同目标端口 短窗口高频连接且大量未完成
    brute_force_min_count: int = 15
    brute_force_window_sec: float = 300.0
    brute_force_incomplete_ratio: float = 0.5   # 未完成连接（RST/无响应）占比下限

    # CC 列表轮询（真实僵尸网络行为）：同源对同端口在窗口内轮询大量不同外部主机。
    # 排除正常浏览/下载会大量"多目的"的端口：标准 Web 端口、基础服务端口、P2P 临时高端口
    cc_rotation_distinct_dst: int = 5
    cc_rotation_window_sec: float = 1800.0
    cc_rotation_ignored_ports: set = field(default_factory=lambda: {3, 53, 123, 80, 443, 8080, 8000, 3478, 6881, 6882, 6883})
    cc_rotation_max_port: int = 10000          # 高于此端口视为 P2P/临时端口，不参与判定

    http_attack_patterns: list = field(default_factory=lambda: list(HTTP_ATTACK_PATTERNS))
    suspicious_ports: set = field(default_factory=lambda: set(SUSPICIOUS_PORTS))
    remote_service_ports: set = field(default_factory=lambda: set(REMOTE_SERVICE_PORTS))

    def __post_init__(self):
        self._nets = [ipaddress.ip_network(n) for n in self.internal_networks]
        self._cache_internal = {}    # is_internal 结果缓存（与 is_broadcast 缓存分离，避免相互污染）
        self._cache_broadcast = {}   # is_broadcast 结果缓存

    def is_broadcast(self, ip: str) -> bool:
        """广播（x.y.z.255 / x.y.255.255 等）或多播地址，规则检测时应排除。"""
        if ip in self._cache_broadcast:
            return self._cache_broadcast[ip]
        result = False
        try:
            addr = ipaddress.ip_address(ip)
            result = addr.is_multicast or str(addr).endswith(".255")
        except ValueError:
            pass
        self._cache_broadcast[ip] = result
        return result

    def is_internal(self, ip: str) -> bool:
        """判断 IP 是否属于内网网段。"""
        if ip in self._cache_internal:
            return self._cache_internal[ip]
        result = False
        try:
            addr = ipaddress.ip_address(ip)
            result = any(addr in net for net in self._nets)
        except ValueError:
            pass
        self._cache_internal[ip] = result
        return result

    @classmethod
    def from_json(cls, path: str) -> "DetectionConfig":
        """从 JSON 文件加载配置（键名与字段名一致，未给出的键用默认值）。"""
        import json
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = cls()
        for key, value in data.items():
            if hasattr(cfg, key) and not key.startswith("_"):
                setattr(cfg, key, value)
        cfg.__post_init__()
        return cfg
