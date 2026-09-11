# -*- coding: utf-8 -*-
"""答辩 PPT 生成脚本（python-pptx）。

产出: docs/答辩PPT-恶意攻击行为溯源分析系统.pptx（16:9，深色安全风）
用法: python scripts/build_ppt.py
成员名: 封面用 A-F 占位，生成后在 PPT 里直接改文本框即可。
截图资产: docs/ppt_assets/*.png（随仓库交付，脚本按相对路径引用）
"""
import os

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

ASSETS = "docs/ppt_assets"
OUT = "docs/答辩PPT-恶意攻击行为溯源分析系统.pptx"
W, H = Inches(13.333), Inches(7.5)          # 16:9
BG = RGBColor(0x0B, 0x12, 0x20)             # 深蓝底
FG = RGBColor(0xF3, 0xF4, 0xF6)             # 主文字
MUTED = RGBColor(0x9C, 0xA3, 0xAF)          # 次要文字
RED = RGBColor(0xDC, 0x26, 0x26)            # 强调红
CYAN = RGBColor(0x22, 0xD3, 0xEE)           # 强调青
ORANGE = RGBColor(0xF5, 0x9E, 0x0B)         # 强调橙
CARD = RGBColor(0x14, 0x1C, 0x2C)           # 卡片底
LINE = RGBColor(0x2A, 0x36, 0x50)           # 分隔线

prs = Presentation()
prs.slide_width = W
prs.slide_height = H
BLANK = prs.slide_layouts[6]


def new_slide():
    s = prs.slides.add_slide(BLANK)
    r = s.shapes.add_shape(1, 0, 0, W, H)          # 1=矩形（铺底色）
    r.fill.solid(); r.fill.fore_color.rgb = BG
    r.line.fill.background()
    r.shadow.inherit = False
    return s


def text(slide, x, y, w, h, content, size=18, color=FG, bold=False,
         align=PP_ALIGN.LEFT, mono=False, anchor=MSO_ANCHOR.TOP, line_gap=1.15):
    box = slide.shapes.add_textbox(x, y, w, h)
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    first = True
    for seg in content.split("\n"):
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.alignment = align
        p.line_spacing = line_gap
        r = p.add_run(); r.text = seg
        r.font.size = Pt(size); r.font.color.rgb = color; r.font.bold = bold
        r.font.name = "Consolas" if mono else "Microsoft YaHei"
    return box


def card(slide, x, y, w, h):
    c = slide.shapes.add_shape(1, x, y, w, h)
    c.fill.solid(); c.fill.fore_color.rgb = CARD
    c.line.color.rgb = LINE; c.line.width = Pt(1)
    c.shadow.inherit = False
    return c


def picture(slide, name, x, y, w=None, h=None):
    path = os.path.join(ASSETS, name)
    if not os.path.exists(path):
        text(slide, x, y, w or Inches(4), h or Inches(2),
             f"[截图缺失: {name}]", size=11, color=RED)
        return
    if w is not None and h is not None:
        slide.shapes.add_picture(path, x, y, width=w, height=h)
    elif w is not None:
        slide.shapes.add_picture(path, x, y, width=w)
    else:
        slide.shapes.add_picture(path, x, y, height=h)


def header(slide, num, title, sub=""):
    text(slide, Inches(0.45), Inches(0.28), Inches(1.0), Inches(0.5),
         f"{num:02d}", size=30, color=CYAN, bold=True)
    text(slide, Inches(1.05), Inches(0.30), Inches(11.0), Inches(0.6),
         title, size=26, color=FG, bold=True)
    if sub:
        text(slide, Inches(1.05), Inches(0.90), Inches(11.9), Inches(0.4),
             sub, size=13, color=MUTED)
    ln = slide.shapes.add_shape(1, Inches(0.45), Inches(1.26 if sub else 0.95),
                                Inches(12.4), Pt(2))
    ln.fill.solid(); ln.fill.fore_color.rgb = CYAN; ln.line.fill.background()
    ln.shadow.inherit = False
    text(slide, Inches(11.7), Inches(7.1), Inches(1.4), Inches(0.3),
         "题3 · 溯源分析系统", size=9, color=MUTED, align=PP_ALIGN.RIGHT)


def bullets(slide, x, y, w, items, size=15, gap=0.42, color=FG, mark="▸ "):
    yy = y
    for it in items:
        text(slide, x, yy, w, Inches(gap), mark + it, size=size, color=color)
        yy += Inches(gap)
    return yy


# ---------------------------------------------------------------- 1 封面
def page_cover():
    s = new_slide()
    ln = s.shapes.add_shape(1, Inches(0.8), Inches(1.35), Inches(2.2), Pt(4))
    ln.fill.solid(); ln.fill.fore_color.rgb = RED; ln.line.fill.background()
    ln.shadow.inherit = False
    text(s, Inches(0.8), Inches(1.55), Inches(11.5), Inches(0.5),
         "网络空间安全课程设计 · 题3", size=17, color=CYAN, bold=True)
    text(s, Inches(0.8), Inches(2.1), Inches(11.5), Inches(1.6),
         "基于主机日志、主机行为、网络流量的\n恶意攻击行为溯源分析系统设计与实现",
         size=34, color=FG, bold=True, line_gap=1.35)
    text(s, Inches(0.8), Inches(3.95), Inches(11.5), Inches(0.4),
         "利用大模型多智能体协调技术 · 多源数据采集与融合 · ATT&CK 攻击链溯源",
         size=15, color=MUTED)
    text(s, Inches(0.8), Inches(4.75), Inches(11.5), Inches(0.5),
         "小组成员与分工", size=15, color=CYAN, bold=True)
    members = [
        "成员A —— 后端 / 数据库 / 契约集成",
        "成员B —— 主机日志解析（EVTX/Sysmon/auditd）",
        "成员C —— 网络流量解析（PCAP/Zeek/filterlog）",
        "成员D —— 关联分析 / 攻击链 / 归因画像",
        "成员E —— 靶场构建 / 攻击执行 / 数据交付",
        "成员F —— 前端可视化 / LLM 分析报告",
    ]
    for i, m in enumerate(members):
        col, row = i % 2, i // 2
        text(s, Inches(1.0 + col * 5.6), Inches(5.35 + row * 0.45),
             Inches(5.4), Inches(0.4), m, size=13, color=FG)
    text(s, Inches(0.8), Inches(7.0), Inches(11.5), Inches(0.35),
         "仓库：information_security_design_project · 全部数字为平台实测，可复现",
         size=11, color=MUTED)


# ---------------------------------------------------------------- 2 目录
def page_toc():
    s = new_slide()
    text(s, Inches(0.8), Inches(0.9), Inches(4), Inches(0.8), "目 录",
         size=36, color=FG, bold=True)
    ln = s.shapes.add_shape(1, Inches(0.85), Inches(1.75), Inches(1.6), Pt(3))
    ln.fill.solid(); ln.fill.fore_color.rgb = CYAN; ln.line.fill.background()
    ln.shadow.inherit = False
    items = [
        ("01", "项目背景与任务"), ("02", "系统总体设计"),
        ("03", "核心模块实现（B/C/D）"), ("04", "靶场构建与实测"),
        ("05", "公开数据集实验"), ("06", "前端与 LLM 分析"),
        ("07", "平台成果与开源对比"), ("08", "总结与展望"),
    ]
    for i, (num, t) in enumerate(items):
        col, row = i % 2, i // 2
        x, y = Inches(1.2 + col * 5.8), Inches(2.3 + row * 1.05)
        text(s, x, y, Inches(0.9), Inches(0.6), num, size=24, color=CYAN, bold=True)
        text(s, x + Inches(0.85), y + Inches(0.06), Inches(4.6), Inches(0.5), t,
             size=18, color=FG)


# ---------------------------------------------------------------- 3 背景
def page_bg():
    s = new_slide()
    header(s, 1, "项目背景与任务",
           "题目：基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现")
    text(s, Inches(0.45), Inches(1.55), Inches(12.3), Inches(0.5),
         "企业内网被入侵后，安全团队面临的四个核心痛点：", size=17, color=FG, bold=True)
    cards = [
        ("日志分散 · 格式异构",
         "Windows EVTX / Sysmon / Linux auth / auditd / Zeek / 防火墙\n各自格式不同，时钟不统一，人工逐条翻查如大海捞针"),
        ("单源视角盲区",
         "只看网络流量不知道主机上发生了什么；\n只看主机日志不知道攻击者从哪里进来、去了哪里"),
        ("攻击链路难还原",
         "入侵点 → 落地 → 提权 → 横向 → C2 → 外传，\n跨主机跨来源的移动路径无法靠人工串联"),
        ("溯源取证难",
         "缺少结构化的证据留存与关联分析，\n难以支撑溯源结论与应急处置"),
    ]
    for i, (t, d) in enumerate(cards):
        x = Inches(0.45 + (i % 2) * 6.25)
        y = Inches(2.15 + (i // 2) * 2.1)
        card(s, x, y, Inches(6.0), Inches(1.9))
        text(s, x + Inches(0.25), y + Inches(0.15), Inches(5.5), Inches(0.5),
             t, size=17, color=CYAN, bold=True)
        text(s, x + Inches(0.25), y + Inches(0.7), Inches(5.6), Inches(1.1),
             d, size=12.5, color=MUTED)
    text(s, Inches(0.45), Inches(6.55), Inches(12.3), Inches(0.7),
         "任务书要求：利用大模型多智能体协调技术，完成多源数据采集与融合，实现恶意攻击行为的全面溯源和追踪分析；"
         "并在 ≥8 节点靶场完成完整入侵链验证。", size=13, color=MUTED)


# ---------------------------------------------------------------- 4 架构
def page_arch():
    s = new_slide()
    header(s, 2, "系统总体架构",
           "一次攻击事件 = 一个 case_id = 全部证据（主机+网络+防火墙 同批入库，跨源关联）")
    boxes = [
        ("E 靶场 / 数据", "9 节点三段式\n4 抓包点+防火墙\nEVTX/auditd",
         Inches(0.45), RGBColor(0x7C, 0x3A, 0xED)),
        ("B 主机日志解析", "EVTX / Sysmon\nauditd / auth\n31 种事件类型\n会话重建+异常预标记",
         Inches(2.98), RGBColor(0x0E, 0xA5, 0xE9)),
        ("C 网络流量解析", "PCAP / Zeek\nfilterlog / CSV\n10 检测器→ATT&CK",
         Inches(5.51), RGBColor(0x22, 0xC5, 0x5E)),
        ("A 后端 + 契约", "FastAPI + SQLite\nEvent V2 FINAL\n19 字段契约\n三层校验守卫",
         Inches(8.04), ORANGE),
        ("D 关联分析", "9 阶段关联\n12 ATT&CK 技术\n攻击图+归因画像",
         Inches(10.57), RED),
    ]
    for t, d, x, c in boxes:
        card(s, x, Inches(1.75), Inches(2.31), Inches(2.2))
        text(s, x + Inches(0.12), Inches(1.9), Inches(2.1), Inches(0.5), t,
             size=15, color=c, bold=True)
        text(s, x + Inches(0.12), Inches(2.45), Inches(2.1), Inches(1.4), d,
             size=11.5, color=MUTED)
    for x in (Inches(2.80), Inches(5.33), Inches(7.86), Inches(10.39)):
        a = s.shapes.add_shape(1, x, Inches(2.7), Inches(0.14), Pt(3))
        a.fill.solid(); a.fill.fore_color.rgb = CYAN; a.line.fill.background()
        a.shadow.inherit = False
    text(s, Inches(0.45), Inches(4.2), Inches(12.4), Inches(0.5),
         "统一契约 Event V2 FINAL：19 公共字段 · source 8 枚举 · 缺失即 null · detail 开放字段 · detail.batch_id 批次隔离",
         size=14, color=CYAN, bold=True)
    text(s, Inches(0.45), Inches(4.72), Inches(12.4), Inches(0.4),
         "F 前端（5 页面 Dashboard/时间线/攻击链/报告/数据管理）与 LLM 分析（LLM 优先 + 规则降级，永远 200）消费同一契约",
         size=13, color=MUTED)
    text(s, Inches(0.45), Inches(5.4), Inches(12), Inches(0.4), "技术栈",
         size=15, color=FG, bold=True)
    text(s, Inches(0.45), Inches(5.85), Inches(12.3), Inches(1.3),
         "Python 3.13 · FastAPI · SQLite · scapy · python-evtx · ECharts · Electron（桌面版）\n"
         "LLM：DeepSeek / 千问 / GLM 可换，LLM 失败自动规则降级 · 203 个自动化测试 · 三层契约守卫",
         size=13, color=MUTED)


# ---------------------------------------------------------------- 5 契约
def page_contract():
    s = new_slide()
    header(s, 3, "Event V2 FINAL —— 全组统一数据契约",
           "一次攻击事件 = 一个 case_id = 全部证据（跨源同批，D 跨源关联的前提）")
    text(s, Inches(0.45), Inches(1.5), Inches(5.6), Inches(0.4),
         "19 个公共字段", size=17, color=CYAN, bold=True)
    text(s, Inches(0.45), Inches(1.95), Inches(5.9), Inches(2.6),
         "timestamp · host · source · source_event_id · event_type\n"
         "user · process · src_ip · dst_ip · dst_port · protocol\n"
         "logon_type · session_id · cmdline · detail · description\n"
         "anomaly_flags · severity(0-3) · raw_log\n"
         "后端入库额外生成 id（D 的 evidence_event_ids 用它）",
         size=13.5, color=FG, mono=True)
    text(s, Inches(0.45), Inches(4.4), Inches(5.8), Inches(0.4),
         "关键规则", size=16, color=CYAN, bold=True)
    bullets(s, Inches(0.45), Inches(4.85), Inches(6.1), [
        "缺失即 null，禁止 unknown / 空串 / 0 占位",
        "source 8 枚举：windows_evtx / sysmon / linux_auth / linux_audit / network_pcap / network_zeek / firewall / waf",
        "detail 开放字段 + batch_id 批次隔离，多批共库互不污染",
        "三层契约守卫：解析阻断 / EventOut 校验 / CI 守卫测试",
    ], size=12.5, mark="✓ ", gap=0.52)
    card(s, Inches(6.9), Inches(1.5), Inches(5.95), Inches(5.3))
    text(s, Inches(7.15), Inches(1.7), Inches(5.4), Inches(0.4),
         "为什么契约是本项目第一块基石", size=16, color=FG, bold=True)
    text(s, Inches(7.15), Inches(2.25), Inches(5.5), Inches(4.3),
         "· 6 人并行开发，B/C/D/F 各自消费同一份数据——\n  没有契约，联调每天在字段名上打架\n\n"
         "· id 与 source_event_id 分离：数据库主键供\n  证据回指，原始日志编号可重复可缺失\n\n"
         "· detail.batch_id 批次隔离：多批共库互不污染，\n  前端/D 按批次过滤消费\n\n"
         "· 实测：47,055 条 B 侧事件一次入库全通过\n  契约校验，0 条被页面模块打回",
         size=13.5, color=MUTED)


# ---------------------------------------------------------------- 6 B/C 模块
def page_modules():
    s = new_slide()
    header(s, 4, "核心模块实现 · 采集与解析（B / C）",
           "主机侧 31 种事件类型 · 网络侧 10 检测器 → ATT&CK")
    card(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(0.7), Inches(1.65), Inches(5.5), Inches(0.5),
         "B · 主机日志解析（b_host_parser）", size=18, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(2.25), Inches(5.5), [
        "5 类输入：Windows EVTX / Sysmon EVTX / Sysmon JSON / auth.log / auditd",
        "31 种标准事件类型（登录 3 / 进程 2 / 网络 3 / 文件 5 / 注册表 4 / 账户 6 / 服务 4 / 计划任务 3 / 日志清除）",
        "时间对齐：rsyslog ISO8601 修复 + 时区统一 UTC+8",
        "登录会话重建：4624/4634/4647 配对出会话时间线与源 IP",
        "异常预标记 9 条规则：爆破 / 用户名枚举 / 编码执行 / 远程下载 / 注册表持久化…",
        "实测：E 真实靶场 47,055 条事件一次通过契约校验",
    ], size=12, mark="✓ ", gap=0.7)
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(7.1), Inches(1.65), Inches(5.5), Inches(0.5),
         "C · 网络流量解析（parsers/network）", size=18, color=CYAN, bold=True)
    bullets(s, Inches(7.1), Inches(2.25), Inches(5.5), [
        "4 类输入：PCAP/PCAPNG · Zeek TSV/JSON/合并流 · filterlog · CSV",
        "10 检测器 → 10 ATT&CK 技术 / 7 阶段：扫描 T1046 · C2 心跳 T1071 · DNS 隧道 T1071.004 · 外传 T1048 · 横向 T1021",
        "证据增强：爆破 T1110 · 可疑端口 T1571 · ICMP 隧道 T1095 · Web 攻击 T1190 · CC 轮询",
        "CTU-13 实战新增 CC 轮询检测——感染主机轮询 7 个 C2，零误报",
        "误报修复实录：utmcmd 参数误报 1354→16 条",
        "filterlog 防火墙事件：action / rule_id 进 detail（source=firewall）",
    ], size=12, mark="✓ ", gap=0.6)


# ---------------------------------------------------------------- 7 D 模块
def page_module_d():
    s = new_slide()
    header(s, 5, "核心模块实现 · D 关联分析（backend/analysis）",
           "把 B/C 的离散事件，串成可回查证据的完整攻击链")
    card(s, Inches(0.45), Inches(1.5), Inches(5.9), Inches(2.7))
    text(s, Inches(0.7), Inches(1.65), Inches(5.4), Inches(0.5),
         "AttackStep —— 12 字段结构化攻击步骤", size=16, color=CYAN, bold=True)
    text(s, Inches(0.7), Inches(2.2), Inches(5.4), Inches(1.9),
         "step_id · case_id · stage · technique_id · technique_name\n"
         "timestamp · source_host · target_host · source_ip · target_ip\n"
         "description · evidence_event_ids\n"
         "（数据库 id 数组，前端点击可穿透到原始事件）",
         size=13, color=MUTED, mono=True)
    card(s, Inches(0.45), Inches(4.4), Inches(5.9), Inches(2.4))
    text(s, Inches(0.7), Inches(4.55), Inches(5.4), Inches(0.5),
         "攻击图 + 归因画像", size=16, color=CYAN, bold=True)
    text(s, Inches(0.7), Inches(5.1), Inches(5.4), Inches(1.6),
         "build_attack_graph：节点=主机/攻击者/C2，边=攻击动作\n"
         "find_attack_paths：BFS 提取主要攻击路径\n"
         "attribution：攻击者画像 / C2 基础设施 / TTP 相似度",
         size=13, color=MUTED)
    card(s, Inches(6.65), Inches(1.5), Inches(6.2), Inches(5.3))
    text(s, Inches(6.9), Inches(1.65), Inches(5.7), Inches(0.5),
         "关联输出实测一 · e_case01（纯网络侧 720 条）", size=15, color=CYAN, bold=True)
    rows = [
        ("Lateral Movement", "T1021", "26"),
        ("Initial Access", "T1190", "20"),
        ("Command and Control", "T1071", "1"),
    ]
    yy = 2.15
    for st, tid, n in rows:
        text(s, Inches(6.9), Inches(yy), Inches(5.7), Inches(0.35),
             f"{st}  ({tid})  ——  {n} 步", size=13.5, color=FG)
        yy += 0.38
    text(s, Inches(6.9), Inches(yy + 0.02), Inches(5.7), Inches(0.4),
         "→ 47 步攻击链，入侵点（web-server）自动标记", size=13, color=CYAN)
    text(s, Inches(6.9), Inches(yy + 0.55), Inches(5.7), Inches(0.5),
         "关联输出实测二 · apt29 批次（主机侧 23,993 条）", size=15, color=CYAN, bold=True)
    rows2 = [
        ("Privilege Escalation", "T1078", "934"),
        ("Execution", "T1059", "134"),
        ("Collection", "T1005", "36"),
        ("Persistence", "T1543.003", "22"),
    ]
    yy += 1.05
    for st, tid, n in rows2:
        text(s, Inches(6.9), Inches(yy), Inches(5.7), Inches(0.35),
             f"{st}  ({tid})  ——  {n} 步", size=13.5, color=FG)
        yy += 0.38
    text(s, Inches(6.9), Inches(yy + 0.02), Inches(5.7), Inches(0.8),
         "→ 1,129 步 / 9 阶段 12 技术引擎全量支撑；\n多源证据越全，链条越完整",
         size=13, color=CYAN)


# ---------------------------------------------------------------- 8 靶场
def page_range():
    s = new_slide()
    header(s, 6, "E 靶场构建 · 9 节点三段式真实攻击环境",
           "VMware 隔离靶场 · OPNsense 防火墙三接口分段 · 完整入侵链由攻击机一手触发")
    text(s, Inches(0.45), Inches(1.48), Inches(12.3), Inches(0.4),
         "WAN 10.10.10.0/24（攻击机·C2）  →  DMZ 10.10.20.0/24（Web·Email）  →  LAN 10.10.30.0/24（Win10 跳板·Core）",
         size=14, color=CYAN, bold=True, mono=True)
    nodes = [
        ("攻击机", "10.10.10.10", RED),
        ("C2 服务器", "10.10.10.20", RGBColor(0xBE, 0x18, 0x5D)),
        ("OPNsense 防火墙", "三接口", ORANGE),
        ("Web (DVWA)", "10.10.20.10", RGBColor(0x0E, 0xA5, 0xE9)),
        ("Email", "10.10.20.20", RGBColor(0x0E, 0xA5, 0xE9)),
        ("Win10 跳板", "10.10.30.10", RGBColor(0x22, 0xC5, 0x5E)),
        ("Core", "10.10.30.20", RGBColor(0x22, 0xC5, 0x5E)),
    ]
    for i, (t, ip, c) in enumerate(nodes):
        x = Inches(0.45 + i * 1.83)
        card(s, x, Inches(1.95), Inches(1.68), Inches(1.0))
        text(s, x, Inches(2.04), Inches(1.68), Inches(0.4), t, size=12.5,
             color=c, bold=True, align=PP_ALIGN.CENTER)
        text(s, x, Inches(2.48), Inches(1.68), Inches(0.35), ip, size=10,
             color=MUTED, align=PP_ALIGN.CENTER, mono=True)
    text(s, Inches(0.45), Inches(3.2), Inches(8.6), Inches(0.5),
         "攻击链剧本（E 全程一手操作，全程抓包 + 全节点日志留存）",
         size=16, color=FG, bold=True)
    steps = [
        ("①", "nmap 隐蔽扫描 6 端口 × 4 目标（-T2 --scan-delay）"),
        ("②", "ZAP 主动扫描 DVWA（8088）"),
        ("③", "DVWA 命令注入：127.0.0.1 && case01-stage.sh"),
        ("④", "Web 经 sshpass SSH 登录 Win10 跳板（22）"),
        ("⑤", "Win10 访问 Core:9100 取敏感文件 finance_demo.txt"),
        ("⑥", "Win10 回连 C2:8080 发送 beacon（test-beacon?data=FAKE_DATA）"),
    ]
    yy = 3.72
    for num, t in steps:
        text(s, Inches(0.45), Inches(yy), Inches(0.5), Inches(0.35), num,
             size=14, color=CYAN, bold=True)
        text(s, Inches(0.9), Inches(yy), Inches(8.1), Inches(0.35), t,
             size=13, color=FG)
        yy += 0.44
    text(s, Inches(0.45), Inches(6.5), Inches(8.4), Inches(0.8),
         "证据留存：4 个抓包点 pcap + 防火墙 filter.log + 全节点 auditd/EVTX 日志\n"
         "+ 攻击侧 nmap / ZAP 报告 + 全程截图（含 OPNsense 三接口，合计 9 节点）",
         size=12, color=MUTED)
    picture(s, "range_zap.png", Inches(9.35), Inches(3.35), w=Inches(3.55))
    text(s, Inches(9.35), Inches(5.35), Inches(3.55), Inches(0.35),
         "攻击侧实拍：ZAP 扫描 DVWA 告警", size=10.5, color=MUTED)
    picture(s, "range_nmap.png", Inches(9.35), Inches(5.8), w=Inches(1.7))
    text(s, Inches(11.15), Inches(6.3), Inches(1.8), Inches(0.6),
         "nmap 隐蔽扫描输出", size=10.5, color=MUTED)


# ---------------------------------------------------------------- 9 靶场实测
def page_range_result():
    s = new_slide()
    header(s, 7, "靶场实测 · 剧本 vs 检出对照",
           "攻击链剧本 6 段，网络侧自动检出入侵点并标记")
    card(s, Inches(0.45), Inches(1.5), Inches(6.2), Inches(5.3))
    text(s, Inches(0.7), Inches(1.65), Inches(5.7), Inches(0.5),
         "网络侧自动检出（source=network_pcap / firewall）", size=15, color=CYAN, bold=True)
    rows = [
        ("③ DVWA 命令注入", "T1190 初始访问", "4 条 Web 攻击告警 + 入侵点标记"),
        ("④ SSH 跳板 DMZ→LAN", "T1021 横向移动", "13 条横向告警（SSH 22）"),
        ("⑤ Win10→Core:9100", "5 个会话事件化", "自定义端口留主机侧佐证"),
        ("⑥ C2 Beacon :8080", "事件化 + 防火墙记录", "预演+正式跑各一次"),
        ("① nmap 扫描", "6 端口 < 阈值 10", "如实记录：低于阈值不告警"),
        ("防火墙 filterlog", "588 条（pass 391 / block 197）", "action / rule_id 进 detail"),
    ]
    yy = 2.2
    for a, b, c in rows:
        text(s, Inches(0.7), Inches(yy), Inches(5.8), Inches(0.55),
             f"▸ {a}   →   {b}\n     {c}", size=12.5, color=FG)
        yy += 0.72
    text(s, Inches(0.7), Inches(6.35), Inches(5.8), Inches(0.4),
         "720 条事件全部通过契约校验 → 攻击链 47 步", size=13, color=CYAN)
    picture(s, "shot_chain_ecase01.png", Inches(6.9), Inches(1.7), w=Inches(6.0))
    text(s, Inches(6.9), Inches(5.15), Inches(6.0), Inches(0.4),
         "攻击链页面实测：按阶段分列布局，点击边可穿透回查原始证据",
         size=11.5, color=MUTED)
    card(s, Inches(6.9), Inches(5.65), Inches(6.0), Inches(1.15))
    text(s, Inches(7.1), Inches(5.78), Inches(5.6), Inches(0.9),
         "证据穿透：攻击链每个环节都带 evidence_event_ids，\n答辩现场可当场点开任意环节的原始日志佐证",
         size=12.5, color=FG)


# ---------------------------------------------------------------- 10 CTU-13
def page_ctu13():
    s = new_slide()
    header(s, 8, "公开数据集实验 ① CTU-13 场景 2（Neris 僵尸网络）",
           "任务书测试要求(1)：收集互联网企业内网攻击数据集，开展溯源分析并与 ground truth 对照")
    card(s, Inches(0.45), Inches(1.5), Inches(6.1), Inches(5.3))
    text(s, Inches(0.7), Inches(1.65), Inches(5.6), Inches(0.4),
         "Stratosphere IPS 发布 · 真实僵尸网络流量", size=15, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(2.15), Inches(5.7), [
        "全量 356 万行 / 571MB Zeek 日志；10 万行子集 139,195 会话全部合规入库",
        "ground truth：感染主机 SARUMAN 精确命中",
        "suspicious_port 检测 8/10 精确（IRC C2 连接）",
        "cc_rotation 新规则 1 告警零误报（轮询 7 个 C2）",
        "误报修复实录：utmcmd 参数误报 1354 → 16 条",
        "交付 D：ctu13_s2 EventOut 1,215 条",
    ], size=13, mark="✓ ", gap=0.6)
    text(s, Inches(0.7), Inches(6.05), Inches(5.7), Inches(0.7),
         "结论：多源场景下网络单源检测的精确率边界被定量测出，\n为 D 的跨源关联与白名单学习提供依据。",
         size=12.5, color=MUTED)
    picture(s, "shot_dashboard_ctu13.png", Inches(6.85), Inches(1.7), w=Inches(6.05))
    text(s, Inches(6.85), Inches(5.15), Inches(6.05), Inches(0.4),
         "Dashboard 实测：ctu13_s2 批次统计与告警分布", size=11.5, color=MUTED)
    card(s, Inches(6.85), Inches(5.6), Inches(6.05), Inches(1.2))
    text(s, Inches(7.1), Inches(5.72), Inches(5.6), Inches(1.0),
         "可复现：fetch_dataset.py 一条命令重新下载全部数据；\npost_events.py 分块导入 + 契约校验 + round-trip 比对",
         size=12.5, color=FG)


# ---------------------------------------------------------------- 11 APT29
def page_apt29():
    s = new_slide()
    header(s, 9, "公开数据集实验 ② APT29 ATT&CK Evaluations Day1",
           "任务书测试要求(1)：企业内网 APT 攻击数据集 + ATT&CK ground truth 对照")
    card(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(0.7), Inches(1.65), Inches(5.5), Inches(0.4),
         "OTRF 官方评测环境 · B 主机侧解析", size=15, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(2.15), Inches(5.6), [
        "667 条 EventOut · 真实环境主机名覆盖 98.5%",
        "ground truth 19 技术（26 条 Sigma 规则提取）",
        "父技术命中 T1048.003（WebDAV 外传 over C2）",
        "GT 之外发现 APT29 真实 C2 域名 footprintdns.com",
        "48 条内网横向（T1021）与 day1 剧本一致",
    ], size=13, mark="✓ ", gap=0.6)
    text(s, Inches(0.7), Inches(5.55), Inches(5.6), Inches(1.1),
         "结论：未命中 15/19 均为主机侧行为（凭据转储、令牌窃取等）——\n"
         "定量论证了任务书「多源融合」的必要性：\n单靠网络流量不可能覆盖这些技术。",
         size=12.5, color=MUTED)
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(7.1), Inches(1.65), Inches(5.5), Inches(0.4),
         "ground truth 对照方法", size=15, color=CYAN, bold=True)
    text(s, Inches(7.1), Inches(2.15), Inches(5.6), Inches(4.5),
         "1. 官方 JSON ground truth → 提取 26 条 Sigma 规则\n"
         "2. 映射为 19 项 ATT&CK 技术清单（含父子技术）\n"
         "3. 平台按 apt29 批次导入 23,993 条主机事件\n"
         "4. D 引擎输出 1,129 步关联步骤\n"
         "5. 逐步骤与 GT 清单比对，统计命中 / 父技术命中 / 未命中\n\n"
         "命中示例：T1048.003 外传（父技术 T1048 在 GT 清单）\n"
         "额外发现：footprintdns.com C2 心跳——GT 步骤清单之外，\n"
         "由平台自动检出并可穿透到原始事件",
         size=13, color=FG)


# ---------------------------------------------------------------- 12 前端+LLM
def page_frontend():
    s = new_slide()
    header(s, 10, "F 前端与 LLM 分析报告",
           "5 页面 · Live/Demo 严格分层 · LLM 优先 + 规则降级（永远 200）")
    text(s, Inches(0.45), Inches(1.45), Inches(12.3), Inches(0.5),
         "Dashboard 统计卡片与三图联检 · 攻击时间线（5 过滤器+证据面板） · 攻击链（阶段分列图） · "
         "分析报告（LLM） · 数据管理（上传/批次/分析）",
         size=13.5, color=FG)
    picture(s, "shot_report.png", Inches(0.45), Inches(2.1), w=Inches(7.4))
    text(s, Inches(0.45), Inches(6.35), Inches(7.4), Inches(0.5),
         "分析报告页实测：LLM 攻击路径（attack-external → web-server → win10-jump → c2-server）+ 关键证据表",
         size=11.5, color=MUTED)
    card(s, Inches(8.1), Inches(2.1), Inches(4.8), Inches(4.9))
    text(s, Inches(8.35), Inches(2.25), Inches(4.3), Inches(0.4),
         "LLM 分析管线（llm_analysis.py）", size=15, color=CYAN, bold=True)
    bullets(s, Inches(8.35), Inches(2.75), Inches(4.35), [
        "事件过滤（case_id/主机/时间）→ D 关联引擎 → 精简上下文（按 severity 截断）",
        "OpenAI 兼容接口：DeepSeek / 千问 / GLM / Kimi 可换",
        "严格 JSON 解析，失败重试 1 次",
        "LLM 失败自动降级规则模板（9 阶段推荐）",
        "接口永远 200：source = llm / fallback 如实标注",
    ], size=12, gap=0.55)
    text(s, Inches(8.35), Inches(5.75), Inches(4.35), Inches(1.1),
         "断网兜底：全部 EventOut / summary 已落盘，\n前端 mock 数据可独立演示（页脚一键切换）。",
         size=12, color=MUTED)


# ---------------------------------------------------------------- 13 成果总览
def page_overview():
    s = new_slide()
    header(s, 11, "平台成果总览 · 硬数字", "全部为实测值，可复现")
    stats = [
        ("203", "自动化测试", "11 个测试文件"),
        ("10", "网络检测器→ATT&CK", "7 阶段覆盖"),
        ("31", "主机事件类型", "EVTX/Sysmon/auditd"),
        ("9+12", "D 攻击阶段/技术", "AttackStep 12 字段"),
        ("9", "靶场节点 · 3 网段", "4 抓包点+防火墙"),
        ("139,195", "CTU-13 会话入库", "ground truth 精确命中"),
        ("720→47", "e_case01 事件→攻击步骤", "靶场实测"),
        ("47,055", "B 侧事件一次过契约", "E 靶场主机侧"),
    ]
    for i, (n, t, sub) in enumerate(stats):
        x = Inches(0.45 + (i % 2) * 3.0)
        y = Inches(1.55 + (i // 2) * 1.2)
        card(s, x, y, Inches(2.85), Inches(1.05))
        text(s, x + Inches(0.12), y + Inches(0.04), Inches(2.6), Inches(0.5), n,
             size=20, color=CYAN, bold=True)
        text(s, x + Inches(0.12), y + Inches(0.5), Inches(2.6), Inches(0.3), t,
             size=11.5, color=FG, bold=True)
        text(s, x + Inches(0.12), y + Inches(0.76), Inches(2.6), Inches(0.28), sub,
             size=9.5, color=MUTED)
    picture(s, "shot_datamanage.png", Inches(6.6), Inches(1.6), w=Inches(6.3))
    text(s, Inches(6.6), Inches(5.15), Inches(6.3), Inches(0.4),
         "数据管理页实测：多文件拖拽上传 · 批次列表 · 删除 · 一键触发 B/C/D 分析",
         size=11.5, color=MUTED)
    card(s, Inches(0.45), Inches(6.42), Inches(5.95), Inches(0.85))
    text(s, Inches(0.65), Inches(6.5), Inches(5.6), Inches(0.72),
         "平台批次（当前库）：apt29 23,993 · e_case01 720 · case03-demo 96\n"
         "另导出 EventOut 交付 D：apt29_day1 667 · ctu13_s2 1,215",
         size=10.5, color=FG)


# ---------------------------------------------------------------- 14 开源对比
def page_oss_compare():
    s = new_slide()
    header(s, 12, "开源对比与创新性",
           "8 个同类开源项目 · 详见 docs/开源项目对比与自研系统创新性分析.md")
    card(s, Inches(0.45), Inches(1.5), Inches(7.3), Inches(5.3))
    text(s, Inches(0.7), Inches(1.62), Inches(6.8), Inches(0.4),
         "对比矩阵（项目：优势 / 缺口）", size=15, color=CYAN, bold=True)
    rows = [
        ("Wazuh", "主机侧 SIEM 规则丰富", "无网络流量解析与攻击图"),
        ("Security Onion", "全家桶集成度高", "部署重，不适合课程/轻量场景"),
        ("Arkime", "全流量存储检索强", "偏存储检索，无溯源链生成"),
        ("Sigma", "检测规则生态好", "仅规则格式，无关联与展示"),
        ("OpenCTI / MISP", "威胁情报平台", "偏情报共享，不解析原始日志"),
        ("TheHive", "事件响应编排", "无开箱溯源链"),
        ("Timesketch", "取证时间线协作", "无自动 ATT&CK 步骤生成"),
        ("Zeek", "网络日志事实标准", "本项目以其输出为解析输入"),
    ]
    yy = 2.1
    for name, adv, gap in rows:
        text(s, Inches(0.7), Inches(yy), Inches(6.9), Inches(0.4),
             f"{name}：{adv}；缺口 {gap}", size=11.5, color=FG)
        yy += 0.57
    card(s, Inches(8.0), Inches(1.5), Inches(4.9), Inches(5.3))
    text(s, Inches(8.25), Inches(1.62), Inches(4.4), Inches(0.4),
         "本项目的三条创新点", size=16, color=CYAN, bold=True)
    points = [
        ("① 轻量端到端闭环",
         "多源原始日志 → Event V2 契约 → ATT&CK 攻击步骤 → 攻击链图 → 证据回查 → 归因画像，单仓库可复现"),
        ("② 契约驱动协作",
         "19 字段三层守卫 + 批次隔离，6 人并行 0 次字段打架；公开数据集定量验证（CTU-13 精确命中 / APT29 父技术命中）"),
        ("③ 双重实证",
         "9 节点靶场完整入侵链实测 + CTU-13 13.9 万会话合规入库，检测器阈值有真实误报修复记录"),
    ]
    yy = 2.15
    for t, d in points:
        text(s, Inches(8.25), Inches(yy), Inches(4.45), Inches(0.4),
             t, size=13.5, color=FG, bold=True)
        text(s, Inches(8.25), Inches(yy + 0.38), Inches(4.45), Inches(1.1),
             d, size=11.5, color=MUTED)
        yy += 1.6


# ---------------------------------------------------------------- 15 总结
def page_summary():
    s = new_slide()
    header(s, 13, "总结与展望", "对照任务书逐项交付 · 局限与下一步")
    text(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(0.4),
         "已完成（对照任务书）", size=17, color=CYAN, bold=True)
    done = [
        "多源采集与融合：主机(B)+网络(C)+防火墙 → Event V2",
        "时间对齐 / 范式解析 / 实体提取 / 会话重建",
        "进程行为链 / 文件监控 / 会话异常预标记（B）",
        "流量捕获解析 / 10 检测器 / 隐蔽信道检测（C）",
        "ATT&CK 攻击链 9 阶段关联 + 攻击图 + 归因画像（D）",
        "9 节点靶场完整入侵链实测 + 公开数据集双验证",
        "前端 5 页面 + LLM 分析（降级保底）+ Electron 桌面版",
    ]
    yy = 2.0
    for d in done:
        text(s, Inches(0.7), Inches(yy), Inches(5.7), Inches(0.4),
             "✓ " + d, size=13.5, color=FG)
        yy += 0.55
    text(s, Inches(7.1), Inches(1.5), Inches(5.6), Inches(0.4),
         "局限与下一步", size=17, color=ORANGE, bold=True)
    todo = [
        "主机侧行为深挖：内存注入 / 反射加载检测",
        "隐蔽信道：HTTP 隧道建模（DNS/ICMP 已覆盖）",
        "LLM 分析调优：多智能体协作（当前单 LLM+降级）",
        "与已知 APT 组织 TTP 匹配：本地情报库扩充",
        "大库性能：分页查询 / 增量加载优化",
        "打包分发：PyInstaller 后端 + electron-builder",
    ]
    yy = 2.0
    for t in todo:
        text(s, Inches(7.35), Inches(yy), Inches(5.4), Inches(0.4),
             "▸ " + t, size=13.5, color=FG)
        yy += 0.55
    text(s, Inches(0.45), Inches(6.2), Inches(12.3), Inches(1.0),
         "一句话总结：本项目用「统一契约 + 多源解析 + ATT&CK 关联 + 证据穿透」"
         "把一次真实靶场入侵变成了可回查、可展示、可量化的完整溯源故事——"
         "并在 CTU-13 与 APT29 两个公开数据集上完成了定量验证。",
         size=15, color=CYAN)


# ---------------------------------------------------------------- 16 致谢
def page_thanks():
    s = new_slide()
    text(s, Inches(0.6), Inches(2.6), Inches(12), Inches(1.2), "谢谢观看 · Q&A",
         size=54, color=FG, bold=True, align=PP_ALIGN.CENTER)
    text(s, Inches(0.6), Inches(4.0), Inches(12), Inches(0.6),
         "恶意攻击行为溯源分析系统 · 网络空间安全课程设计 题3", size=18,
         color=MUTED, align=PP_ALIGN.CENTER)
    text(s, Inches(0.6), Inches(4.8), Inches(12), Inches(0.5),
         "运行截图素材：docs/ppt_assets/ · 演示：启动平台.bat → 数据管理页选批次 → 各页面查看",
         size=13, color=MUTED, align=PP_ALIGN.CENTER)


def main():
    page_cover()
    page_toc()
    page_bg()
    page_arch()
    page_contract()
    page_modules()
    page_module_d()
    page_range()
    page_range_result()
    page_ctu13()
    page_apt29()
    page_frontend()
    page_overview()
    page_oss_compare()
    page_summary()
    page_thanks()
    prs.save(OUT)
    print(f"saved: {OUT} ({len(prs.slides._sldIdLst)} slides)")


if __name__ == "__main__":
    main()
