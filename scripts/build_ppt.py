# -*- coding: utf-8 -*-
"""答辩 PPT 生成脚本（python-pptx，浅色版）。

产出: docs/答辩PPT-恶意攻击行为溯源分析系统.pptx（16:9，浅色简洁风）
用法: python scripts/build_ppt.py
设计原则: 浅色底 · 每页少字 · 多截图 · 数字都是平台实测
"""
import os

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

ASSETS = "docs/ppt_assets"
OUT = "docs/答辩PPT-恶意攻击行为溯源分析系统.pptx"
W, H = Inches(13.333), Inches(7.5)          # 16:9
BG = RGBColor(0xF5, 0xF7, 0xFA)             # 浅灰蓝底
FG = RGBColor(0x1E, 0x29, 0x3B)             # 主文字（深石板）
MUTED = RGBColor(0x64, 0x74, 0x8B)          # 次要文字
RED = RGBColor(0xDC, 0x26, 0x26)            # 强调红
CYAN = RGBColor(0x02, 0x84, 0xC7)           # 强调蓝（标题/数字）
ORANGE = RGBColor(0xD9, 0x77, 0x06)         # 强调橙
CARD = RGBColor(0xFF, 0xFF, 0xFF)           # 卡片白
LINE = RGBColor(0xE2, 0xE8, 0xF0)           # 分隔线

prs = Presentation()
prs.slide_width = W
prs.slide_height = H
BLANK = prs.slide_layouts[6]


def new_slide():
    s = prs.slides.add_slide(BLANK)
    r = s.shapes.add_shape(1, 0, 0, W, H)
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
                                Inches(12.4), Pt(2.5))
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
         "多源数据采集与融合 · ATT&CK 攻击链溯源 · LLM 分析",
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
         "仓库：information_security_design_project · 全部数字为平台实测",
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
    cards = [
        ("日志分散 · 格式异构", "EVTX / Sysmon / auditd / Zeek / 防火墙\n格式时钟各不同，人工翻查如大海捞针"),
        ("单源视角盲区", "只看流量不知主机行为\n只看主机不知攻击者来去"),
        ("攻击链路难还原", "入侵 → 落地 → 提权 → 横向 → C2 → 外传\n跨源路径无法人工串联"),
        ("溯源取证难", "证据散落无结构\n难以支撑溯源结论与处置"),
    ]
    for i, (t, d) in enumerate(cards):
        x = Inches(0.45 + (i % 2) * 6.25)
        y = Inches(1.75 + (i // 2) * 2.15)
        card(s, x, y, Inches(6.0), Inches(1.9))
        text(s, x + Inches(0.25), y + Inches(0.18), Inches(5.5), Inches(0.5),
             t, size=18, color=CYAN, bold=True)
        text(s, x + Inches(0.25), y + Inches(0.78), Inches(5.6), Inches(1.0),
             d, size=13.5, color=MUTED)
    text(s, Inches(0.45), Inches(6.25), Inches(12.3), Inches(0.7),
         "任务书要求：多源数据采集融合 + 大模型多智能体协调，≥8 节点靶场完成完整入侵链验证。",
         size=14, color=FG, bold=True)


# ---------------------------------------------------------------- 4 架构
def page_arch():
    s = new_slide()
    header(s, 2, "系统总体架构",
           "一次攻击事件 = 一个 case_id = 全部证据（主机+网络+防火墙 同批入库）")
    boxes = [
        ("E 靶场 / 数据", "9 节点三段式\n4 抓包点+防火墙",
         Inches(0.45), RGBColor(0x7C, 0x3A, 0xED)),
        ("B 主机日志解析", "EVTX / Sysmon / auditd\n33 种事件类型",
         Inches(2.98), CYAN),
        ("C 网络流量解析", "PCAP / Zeek / filterlog\n10 检测器→ATT&CK",
         Inches(5.51), RGBColor(0x05, 0x96, 0x69)),
        ("A 后端 + 契约", "FastAPI + SQLite\nEvent V2 · 19 字段",
         Inches(8.04), ORANGE),
        ("D 关联分析", "9 阶段 · 12 技术\n攻击图 + 归因画像",
         Inches(10.57), RED),
    ]
    for t, d, x, c in boxes:
        card(s, x, Inches(1.85), Inches(2.31), Inches(1.9))
        text(s, x + Inches(0.15), Inches(2.05), Inches(2.05), Inches(0.5), t,
             size=16, color=c, bold=True)
        text(s, x + Inches(0.15), Inches(2.65), Inches(2.05), Inches(1.0), d,
             size=12.5, color=MUTED)
    for x in (Inches(2.80), Inches(5.33), Inches(7.86), Inches(10.39)):
        a = s.shapes.add_shape(1, x, Inches(2.65), Inches(0.14), Pt(3))
        a.fill.solid(); a.fill.fore_color.rgb = CYAN; a.line.fill.background()
        a.shadow.inherit = False
    text(s, Inches(0.45), Inches(4.25), Inches(12.4), Inches(0.5),
         "统一契约 Event V2 贯穿全链 —— F 前端 5 页面与 LLM 分析消费同一契约",
         size=16, color=FG, bold=True)
    text(s, Inches(0.45), Inches(4.85), Inches(12.4), Inches(0.4),
         "Dashboard · 攻击时间线 · 攻击链 · 分析报告 · 数据管理 ｜ LLM 优先 + 规则降级，永远 200",
         size=13, color=MUTED)
    text(s, Inches(0.45), Inches(5.6), Inches(12), Inches(0.4), "技术栈",
         size=15, color=FG, bold=True)
    text(s, Inches(0.45), Inches(6.05), Inches(12.3), Inches(0.8),
         "Python 3.13 · FastAPI · SQLite · scapy · python-evtx · ECharts · Electron · LLM（DeepSeek/千问/GLM 可换）\n"
         "203 个自动化测试 · 三层契约守卫",
         size=13, color=MUTED)


# ---------------------------------------------------------------- 5 契约
def page_contract():
    s = new_slide()
    header(s, 3, "Event V2 FINAL —— 全组统一数据契约",
           "6 人并行开发的基石：B/C 产出、D/F 消费，全是同一份数据")
    card(s, Inches(0.45), Inches(1.5), Inches(6.1), Inches(3.1))
    text(s, Inches(0.7), Inches(1.65), Inches(5.6), Inches(0.4),
         "19 个公共字段（核心 9 个）", size=16, color=CYAN, bold=True)
    text(s, Inches(0.7), Inches(2.15), Inches(5.7), Inches(2.3),
         "timestamp · host · source · source_event_id\n"
         "event_type · src_ip · dst_ip · severity · detail\n\n"
         "缺失即 null，禁用 unknown / 空串 / 0 占位\n"
         "source 8 枚举：evtx/sysmon/auth/audit/\n"
         "pcap/zeek/firewall/waf",
         size=13.5, color=FG, mono=True)
    card(s, Inches(0.45), Inches(4.8), Inches(6.1), Inches(2.0))
    text(s, Inches(0.7), Inches(4.95), Inches(5.6), Inches(0.4),
         "批次与守卫", size=16, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(5.45), Inches(5.7), [
        "detail.batch_id 批次隔离，多批共库互不污染",
        "三层守卫：解析阻断 / EventOut 校验 / CI 测试",
    ], size=13, mark="✓ ", gap=0.55)
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(7.1), Inches(1.7), Inches(5.5), Inches(0.4),
         "契约带来的三个直接收益", size=16, color=FG, bold=True)
    pts = [
        ("0 次字段打架", "6 人并行开发，联调不再卡在字段名"),
        ("证据可回指", "入库 id 与原始 source_event_id 分离，\n攻击步骤可穿透到原始事件"),
        ("多批共存", "apt29 / ctu13 / 靶场批次同库互不干扰，\n前端一键切换"),
    ]
    yy = 2.3
    for t, d in pts:
        text(s, Inches(7.1), Inches(yy), Inches(5.5), Inches(0.4),
             "✓ " + t, size=15, color=CYAN, bold=True)
        text(s, Inches(7.35), Inches(yy + 0.42), Inches(5.3), Inches(0.8),
             d, size=12.5, color=MUTED)
        yy += 1.45
    text(s, Inches(7.1), Inches(6.35), Inches(5.5), Inches(0.4),
         "实测：47,195 条主机事件一次入库全过校验", size=13, color=ORANGE, bold=True)


# ---------------------------------------------------------------- 6 B 模块
def page_modules():
    s = new_slide()
    header(s, 4, "核心模块实现 · B 主机日志解析",
           "5 类异构输入，归一成 33 种标准事件类型")
    card(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(0.7), Inches(1.7), Inches(5.5), Inches(0.5),
         "能力清单", size=18, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(2.35), Inches(5.5), [
        "5 类输入：EVTX / Sysmon EVTX+JSON / auth / auditd",
        "33 种标准事件类型，时间统一 UTC+8",
        "登录会话重建：4624/4634/4647 配对",
        "异常预标记 8 规则（爆破/编码执行/内存注入…）",
        "filterlog 防火墙事件：action/rule_id 进 detail",
    ], size=13.5, mark="✓ ", gap=0.78)
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(7.1), Inches(1.7), Inches(5.5), Inches(0.5),
         "解析管线与实测", size=18, color=CYAN, bold=True)
    text(s, Inches(7.1), Inches(2.35), Inches(5.6), Inches(1.6),
         "原始日志 → 类型识别 → 字段归一\n→ 会话重建 / 异常预标记 → Event V2",
         size=14, color=FG, mono=True)
    text(s, Inches(7.1), Inches(4.0), Inches(5.5), Inches(0.4),
         "实测", size=15, color=CYAN, bold=True)
    bullets(s, Inches(7.1), Inches(4.5), Inches(5.6), [
        "E 靶场 47,195 条一次通过契约校验",
        "apt29 批次 23,993 条驱动 D 输出 1,129 步",
    ], size=13.5, mark="✓ ", gap=0.62)


# ---------------------------------------------------------------- 7 C 模块①解析与检测
def page_modules_c_build():
    s = new_slide()
    header(s, 5, "核心模块实现 · C 网络流量解析 ① 解析与检测",
           "4 种格式进，同一条 Event V2 出，全程自动嗅探")
    boxes = [
        ("多格式输入", "PCAP / PCAPNG\nZeek TSV/JSON/合并流\nfilterlog · CSV",
         Inches(0.45), CYAN),
        ("会话重组", "五元组聚流\nDNS 查询/域名提取\nHTTP 方法/URI/状态码",
         Inches(2.98), CYAN),
        ("时间与实体归一", "时间统一 UTC+8\nIP/端口/域名归一\n缺失即 null",
         Inches(5.51), RGBColor(0x05, 0x96, 0x69)),
        ("10 检测器", "阈值 + 特征 + 周期性\n三重判据告警",
         Inches(8.04), RED),
        ("Event V2 输出", "anomaly_flags / severity\n三层契约校验阻断",
         Inches(10.57), ORANGE),
    ]
    for t, d, x, c in boxes:
        card(s, x, Inches(1.75), Inches(2.31), Inches(2.0))
        text(s, x + Inches(0.15), Inches(1.92), Inches(2.05), Inches(0.5), t,
             size=15, color=c, bold=True)
        text(s, x + Inches(0.15), Inches(2.5), Inches(2.05), Inches(1.2), d,
             size=11.5, color=MUTED)
    for x in (Inches(2.80), Inches(5.33), Inches(7.86), Inches(10.39)):
        a = s.shapes.add_shape(1, x, Inches(2.6), Inches(0.14), Pt(3))
        a.fill.solid(); a.fill.fore_color.rgb = CYAN; a.line.fill.background()
        a.shadow.inherit = False
    text(s, Inches(0.45), Inches(4.1), Inches(12.3), Inches(0.45),
         "实测：三类数据源全部合规入库", size=16, color=FG, bold=True)
    results = [
        ("靶场 e_case01", "pcap + filterlog 720 条"),
        ("CTU-13", "139,195 会话全合规"),
        ("APT29 链路佐证", "48 条内网横向检出"),
    ]
    for i, (t, d) in enumerate(results):
        x = Inches(0.45 + i * 4.25)
        card(s, x, Inches(4.65), Inches(3.95), Inches(1.15))
        text(s, x + Inches(0.2), Inches(4.78), Inches(3.6), Inches(0.4), t,
             size=14, color=CYAN, bold=True)
        text(s, x + Inches(0.2), Inches(5.2), Inches(3.6), Inches(0.4), d,
             size=12.5, color=MUTED)
    text(s, Inches(0.45), Inches(6.15), Inches(12.3), Inches(0.5),
         "防错设计：格式自动嗅探 + 未知文件名兜底分类；广播/内网判定缓存分离，杜绝交叉污染误判",
         size=12.5, color=MUTED)


# ---------------------------------------------------------------- 8 C 模块②检测器与实战
def page_modules_c_hit():
    s = new_slide()
    header(s, 6, "核心模块实现 · C 网络流量解析 ② 十检测器与实战",
           "检测即证据：每条告警都供 D 关联、可穿透回查")
    card(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(0.7), Inches(1.65), Inches(5.5), Inches(0.4),
         "检测器 → ATT&CK 技术", size=16, color=CYAN, bold=True)
    dets = [
        "端口扫描 → T1046", "C2 心跳 → T1071",
        "可疑端口 → T1571", "DNS 隧道 → T1071.004",
        "数据外传 → T1048", "ICMP 隧道 → T1095",
        "横向移动 → T1021", "Web 攻击 → T1190",
        "口令爆破 → T1110", "CC 轮询 → T1071（实战新增）",
    ]
    yy = 2.2
    for d in dets:
        text(s, Inches(0.7), Inches(yy), Inches(5.6), Inches(0.35),
             "▸ " + d, size=12.5, color=FG)
        yy += 0.45
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(7.1), Inches(1.65), Inches(5.5), Inches(0.4),
         "实战战绩", size=16, color=CYAN, bold=True)
    bullets(s, Inches(7.1), Inches(2.2), Inches(5.6), [
        "e_case01：命令注入 + SSH 跳板全检出",
        "CTU-13：感染主机 SARUMAN 精确命中",
        "suspicious_port 检出 IRC C2，8/10 精确",
        "CC 轮询新规则：1 告警 0 误报",
        "误报修复实录：utmcmd 1354→16 条",
        "靶场 filterlog 588 条全量事件化",
    ], size=13, mark="✓ ", gap=0.68)
    text(s, Inches(7.1), Inches(6.15), Inches(5.6), Inches(0.5),
         "阈值如实在档：nmap 6 端口低于阈值 10 → 不告警，只记录",
         size=12, color=ORANGE, bold=True)


# ---------------------------------------------------------------- 7 D 模块①攻击链构建
def page_module_d_build():
    s = new_slide()
    header(s, 7, "核心模块实现 · D 关联分析 ① 攻击链构建",
           "从离散事件到带证据编号的攻击链，全流程自动化")
    boxes = [
        ("多源事件输入", "Event V2 统一契约\n按 case_id 分组\n按时间排序",
         Inches(0.45), CYAN),
        ("实体归一", "hosts 表 IP 与主机名互查\n内网 / 外部网段判定",
         Inches(2.98), CYAN),
        ("9 阶段检测器", "初始访问→执行→持久化\n提权→横向→收集\nC2→外传→防御逃逸",
         Inches(5.51), RED),
        ("AttackStep 序列", "12 技术映射表命中\n去重 · 时间排序\n编号 S001…",
         Inches(8.04), ORANGE),
        ("攻击图 + 路径", "build_attack_graph\nfind_attack_paths\n提取主攻击链路",
         Inches(10.57), RGBColor(0x7C, 0x3A, 0xED)),
    ]
    for t, d, x, c in boxes:
        card(s, x, Inches(1.75), Inches(2.31), Inches(2.0))
        text(s, x + Inches(0.15), Inches(1.92), Inches(2.05), Inches(0.5), t,
             size=15, color=c, bold=True)
        text(s, x + Inches(0.15), Inches(2.45), Inches(2.05), Inches(1.2), d,
             size=11.5, color=MUTED)
    for x in (Inches(2.80), Inches(5.33), Inches(7.86), Inches(10.39)):
        a = s.shapes.add_shape(1, x, Inches(2.6), Inches(0.14), Pt(3))
        a.fill.solid(); a.fill.fore_color.rgb = CYAN; a.line.fill.background()
        a.shadow.inherit = False
    text(s, Inches(0.45), Inches(4.0), Inches(12.3), Inches(0.45),
         "实测链还原（e_case01 靶场，720 条事件 → 47 步）", size=16,
         color=FG, bold=True)
    nodes = [
        ("攻击机", "10.10.10.10", RED),
        ("web-server", "入侵点", RED),
        ("win10-jump", "10.10.30.10", CYAN),
        ("core-server", "10.10.30.20", CYAN),
        ("c2-server", "10.10.10.20", RED),
    ]
    edges = ["T1190\n命令注入 ×20", "T1021\nSSH 跳板 ×26", "T1005\n取敏感文件", "T1071\nC2 beacon"]
    nx, nw, gap = 0.55, 1.9, 0.65
    for i, (t, ip, c) in enumerate(nodes):
        x = Inches(nx + i * (nw + gap))
        card(s, x, Inches(4.6), Inches(nw), Inches(1.0))
        text(s, x, Inches(4.72), Inches(nw), Inches(0.4), t, size=13.5,
             color=c, bold=True, align=PP_ALIGN.CENTER)
        text(s, x, Inches(5.14), Inches(nw), Inches(0.35), ip, size=10,
             color=MUTED, align=PP_ALIGN.CENTER, mono=True)
    for i, lbl in enumerate(edges):
        x = Inches(nx + nw + i * (nw + gap) - 0.06)
        a = s.shapes.add_shape(1, x, Inches(5.05), Inches(gap + 0.12), Pt(3))
        a.fill.solid(); a.fill.fore_color.rgb = RED; a.line.fill.background()
        a.shadow.inherit = False
        text(s, Inches(nx + nw + i * (nw + gap) - 0.28), Inches(4.42),
             Inches(gap + 0.56), Inches(0.55), lbl, size=10, color=RED,
             bold=True, align=PP_ALIGN.CENTER)
    text(s, Inches(0.45), Inches(5.85), Inches(12.3), Inches(0.45),
         "入侵点（首个被攻破的内网主机）自动标记；每一步都挂 evidence_event_ids",
         size=13.5, color=FG, bold=True)
    text(s, Inches(0.45), Inches(6.4), Inches(12.3), Inches(0.5),
         "检测器特征举例：登录爆破 · 命令注入 payload · 远程服务端口（22/445/3389/5985）· 敏感文件路径 · C2 信标周期性",
         size=12, color=MUTED)


# ---------------------------------------------------------------- 8 D 模块②行为回溯
def page_module_d_trace():
    s = new_slide()
    header(s, 8, "核心模块实现 · D 关联分析 ② 攻击者行为回溯",
           "每一步可点开原始证据，每个攻击者都有画像")
    card(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(3.4))
    text(s, Inches(0.7), Inches(1.65), Inches(5.5), Inches(0.4),
         "四种回溯手段", size=16, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(2.2), Inches(5.6), [
        "证据穿透：步骤 → evidence_event_ids → 原始事件原文",
        "时间窗回溯：展开步骤前后事件窗口，还原现场",
        "路径反演：find_attack_paths 从任一节点回推入口",
        "跨批次隔离：按 case_id 回溯，多批互不串扰",
    ], size=13, mark="▸ ", gap=0.62)
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(3.4))
    text(s, Inches(7.1), Inches(1.65), Inches(5.5), Inches(0.4),
         "归因画像（attribution.py）", size=16, color=CYAN, bold=True)
    bullets(s, Inches(7.1), Inches(2.2), Inches(5.6), [
        "入侵点提取：首个被攻破的内网主机",
        "攻击者指纹：源 IP / 手法 / 目标偏好",
        "C2 基础设施：域名 / IP / 端口 / 路径",
        "TTP 相似度：与内置 APT 画像 + 威胁情报比对",
    ], size=13, mark="▸ ", gap=0.62)
    text(s, Inches(0.45), Inches(5.15), Inches(12.3), Inches(0.45),
         "实测回溯案例", size=16, color=FG, bold=True)
    card(s, Inches(0.45), Inches(5.65), Inches(6.0), Inches(1.3))
    text(s, Inches(0.7), Inches(5.78), Inches(5.5), Inches(1.05),
         "CTU-13：CC 轮询告警 → 回溯锁定感染主机\nSARUMAN，与 ground truth 一致",
         size=13, color=FG)
    card(s, Inches(6.85), Inches(5.65), Inches(6.0), Inches(1.3))
    text(s, Inches(7.1), Inches(5.78), Inches(5.5), Inches(1.05),
         "APT29：C2 心跳事件 → 回溯出 GT 之外真实\n域名 footprintdns.com",
         size=13, color=FG)


# ---------------------------------------------------------------- 8 靶场
def page_range():
    s = new_slide()
    header(s, 9, "E 靶场构建 · 9 节点三段式",
           "VMware 隔离 · OPNsense 三接口分段 · 完整入侵链由攻击机一手触发")
    text(s, Inches(0.45), Inches(1.48), Inches(12.3), Inches(0.4),
         "WAN 10.10.10.0/24（攻击机·C2）  →  DMZ 10.10.20.0/24（Web·Email）  →  LAN 10.10.30.0/24（Win10·Core）",
         size=13.5, color=CYAN, bold=True, mono=True)
    nodes = [
        ("攻击机", "10.10.10.10", RED),
        ("C2 服务器", "10.10.10.20", RGBColor(0xBE, 0x18, 0x5D)),
        ("OPNsense", "三接口", ORANGE),
        ("Web (DVWA)", "10.10.20.10", CYAN),
        ("Email", "10.10.20.20", CYAN),
        ("Win10 跳板", "10.10.30.10", RGBColor(0x05, 0x96, 0x69)),
        ("Core", "10.10.30.20", RGBColor(0x05, 0x96, 0x69)),
    ]
    for i, (t, ip, c) in enumerate(nodes):
        x = Inches(0.45 + i * 1.83)
        card(s, x, Inches(1.95), Inches(1.68), Inches(1.0))
        text(s, x, Inches(2.04), Inches(1.68), Inches(0.4), t, size=12.5,
             color=c, bold=True, align=PP_ALIGN.CENTER)
        text(s, x, Inches(2.48), Inches(1.68), Inches(0.35), ip, size=10,
             color=MUTED, align=PP_ALIGN.CENTER, mono=True)
    text(s, Inches(0.45), Inches(3.2), Inches(8.6), Inches(0.5),
         "攻击链剧本（全程抓包 + 全节点日志留存）",
         size=16, color=FG, bold=True)
    steps = [
        ("①", "nmap 隐蔽扫描 6 端口 × 4 目标"),
        ("②", "ZAP 主动扫描 DVWA（8088）"),
        ("③", "DVWA 命令注入 getshell"),
        ("④", "SSH 跳板：Web → Win10（22）"),
        ("⑤", "Win10 → Core:9100 取敏感文件"),
        ("⑥", "Win10 回连 C2:8080 发 beacon"),
    ]
    yy = 3.72
    for num, t in steps:
        text(s, Inches(0.45), Inches(yy), Inches(0.5), Inches(0.35), num,
             size=14, color=CYAN, bold=True)
        text(s, Inches(0.9), Inches(yy), Inches(8.1), Inches(0.35), t,
             size=13.5, color=FG)
        yy += 0.44
    text(s, Inches(0.45), Inches(6.5), Inches(8.4), Inches(0.5),
         "证据留存：4 抓包点 pcap + filter.log + 全节点日志 + 攻击侧报告（含防火墙三接口共 9 节点）",
         size=12, color=MUTED)
    picture(s, "range_zap.png", Inches(9.35), Inches(3.35), w=Inches(3.55))
    text(s, Inches(9.35), Inches(5.32), Inches(3.55), Inches(0.3),
         "ZAP 扫描 DVWA 实拍", size=10.5, color=MUTED)
    picture(s, "range_nmap.png", Inches(9.35), Inches(5.72), w=Inches(1.7))
    picture(s, "range_dvwa.png", Inches(11.45), Inches(5.6), w=Inches(1.3))
    text(s, Inches(9.35), Inches(7.1), Inches(1.8), Inches(0.3),
         "nmap / DVWA 实拍", size=10.5, color=MUTED)


# ---------------------------------------------------------------- 9 靶场实测
def page_range_result():
    s = new_slide()
    header(s, 10, "靶场实测 · 剧本 vs 检出对照",
           "6 段剧本全部事件化，入侵点自动标记")
    card(s, Inches(0.45), Inches(1.5), Inches(6.2), Inches(5.3))
    text(s, Inches(0.7), Inches(1.65), Inches(5.7), Inches(0.5),
         "网络侧自动检出", size=15, color=CYAN, bold=True)
    rows = [
        ("③ 命令注入", "T1190 · 4 告警 + 入侵点"),
        ("④ SSH 跳板", "T1021 · 13 告警"),
        ("⑤ Core:9100", "5 个会话事件化"),
        ("⑥ C2 beacon", "事件化 + 防火墙记录"),
        ("① nmap 6 端口", "低于阈值 → 如实不告警"),
        ("filterlog 588 条", "action/rule_id 进 detail"),
    ]
    yy = 2.3
    for a, b in rows:
        text(s, Inches(0.7), Inches(yy), Inches(5.8), Inches(0.4),
             f"▸ {a}   →   {b}", size=13.5, color=FG)
        yy += 0.58
    text(s, Inches(0.7), Inches(6.15), Inches(5.8), Inches(0.45),
         "720 条全过契约 → 攻击链 47 步", size=15, color=CYAN, bold=True)
    picture(s, "shot_chain_ecase01.png", Inches(6.9), Inches(1.7), w=Inches(6.0))
    text(s, Inches(6.9), Inches(5.15), Inches(6.0), Inches(0.35),
         "攻击链页面：阶段分列布局，点击环节穿透原始证据", size=11.5, color=MUTED)
    picture(s, "shot_dashboard_ecase01.png", Inches(6.9), Inches(5.55), w=Inches(3.2))
    text(s, Inches(10.25), Inches(6.2), Inches(2.6), Inches(0.6),
         "Dashboard 实测：\n统计卡片与告警分布", size=11.5, color=MUTED)


# ---------------------------------------------------------------- 10 CTU-13
def page_ctu13():
    s = new_slide()
    header(s, 11, "公开数据集实验 ① CTU-13 僵尸网络",
           "任务书测试要求(1)：与 ground truth 对照")
    card(s, Inches(0.45), Inches(1.5), Inches(6.1), Inches(4.0))
    text(s, Inches(0.7), Inches(1.65), Inches(5.6), Inches(0.4),
         "Stratosphere IPS · Neris 场景 2", size=15, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(2.2), Inches(5.7), [
        "139,195 会话全量合规入库",
        "ground truth：感染主机 SARUMAN 精确命中",
        "CC 轮询新规则：1 告警 0 误报",
        "误报修复：1354 → 16 条",
        "交付 D：EventOut 1,215 条",
    ], size=13.5, mark="✓ ", gap=0.62)
    card(s, Inches(0.45), Inches(5.75), Inches(6.1), Inches(1.05))
    text(s, Inches(0.7), Inches(5.88), Inches(5.6), Inches(0.8),
         "结论：网络单源检测的精确率边界被定量测出",
         size=13.5, color=ORANGE, bold=True)
    picture(s, "shot_dashboard_ctu13.png", Inches(6.85), Inches(1.7), w=Inches(6.05))
    text(s, Inches(6.85), Inches(5.15), Inches(6.05), Inches(0.35),
         "Dashboard 实测：ctu13_s2 批次统计与告警分布", size=11.5, color=MUTED)
    card(s, Inches(6.85), Inches(5.6), Inches(6.05), Inches(1.2))
    text(s, Inches(7.1), Inches(5.73), Inches(5.6), Inches(1.0),
         "可复现：fetch_dataset.py 一键下载\npost_events.py 分块导入 + 契约校验",
         size=12.5, color=FG)


# ---------------------------------------------------------------- 11 APT29
def page_apt29():
    s = new_slide()
    header(s, 12, "公开数据集实验 ② APT29 Evaluations Day1",
           "企业内网 APT 数据集 + ATT&CK ground truth 对照")
    card(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(0.7), Inches(1.7), Inches(5.5), Inches(0.4),
         "检出结果（B 主机侧 667 条 EventOut）", size=15, color=CYAN, bold=True)
    bullets(s, Inches(0.7), Inches(2.3), Inches(5.6), [
        "真实环境主机名覆盖 98.5%",
        "父技术命中 T1048.003（WebDAV 外传）",
        "GT 之外发现真实 C2：footprintdns.com",
        "48 条内网横向（T1021）与剧本一致",
        "未命中 15/19 均为主机侧行为",
    ], size=13.5, mark="✓ ", gap=0.7)
    text(s, Inches(0.7), Inches(6.0), Inches(5.6), Inches(0.6),
         "→ 单靠网络流量覆盖不了这些技术，\n多源融合是刚需", size=13.5,
         color=ORANGE, bold=True)
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(5.3))
    text(s, Inches(7.1), Inches(1.7), Inches(5.5), Inches(0.4),
         "ground truth 对照方法", size=15, color=CYAN, bold=True)
    steps = [
        "① 官方 GT → 提取 26 条 Sigma 规则",
        "② 映射 19 项 ATT&CK 技术清单",
        "③ apt29 批次 23,993 条入库",
        "④ D 引擎输出 1,129 步",
        "⑤ 逐步骤比对：命中 / 父命中 / 未命中",
    ]
    yy = 2.4
    for t in steps:
        text(s, Inches(7.1), Inches(yy), Inches(5.6), Inches(0.45),
             t, size=14, color=FG)
        yy += 0.68
    text(s, Inches(7.1), Inches(6.0), Inches(5.6), Inches(0.6),
         "每个结论都可穿透到原始事件佐证", size=13.5, color=ORANGE, bold=True)


# ---------------------------------------------------------------- 12 前端+LLM
def page_frontend():
    s = new_slide()
    header(s, 13, "F 前端与 LLM 分析报告",
           "5 页面 · LLM 优先 + 规则降级（永远 200）")
    picture(s, "shot_report.png", Inches(0.45), Inches(1.6), w=Inches(7.6))
    text(s, Inches(0.45), Inches(5.95), Inches(7.6), Inches(0.5),
         "分析报告页实测：LLM 攻击路径 + 关键证据表（可穿透原始事件）",
         size=11.5, color=MUTED)
    card(s, Inches(8.3), Inches(1.6), Inches(4.6), Inches(5.2))
    text(s, Inches(8.55), Inches(1.75), Inches(4.1), Inches(0.4),
         "5 个页面", size=15, color=CYAN, bold=True)
    text(s, Inches(8.55), Inches(2.2), Inches(4.15), Inches(1.0),
         "Dashboard · 攻击时间线 · 攻击链\n分析报告 · 数据管理",
         size=13, color=FG)
    text(s, Inches(8.55), Inches(3.35), Inches(4.1), Inches(0.4),
         "LLM 管线", size=15, color=CYAN, bold=True)
    bullets(s, Inches(8.55), Inches(3.8), Inches(4.2), [
        "过滤 → D 引擎 → LLM（可换厂商）",
        "失败自动规则降级，永远 200",
        "断网可 mock 数据独立演示",
    ], size=12.5, mark="✓ ", gap=0.55)
    text(s, Inches(8.55), Inches(5.7), Inches(4.2), Inches(0.9),
         "Live / Demo 严格分层，\n页脚一键切换演示数据",
         size=12.5, color=MUTED)


# ---------------------------------------------------------------- 13 成果总览
def page_overview():
    s = new_slide()
    header(s, 14, "平台成果总览 · 硬数字", "全部为实测值，可复现")
    stats = [
        ("203", "自动化测试"),
        ("10", "网络检测器→ATT&CK"),
        ("31", "主机事件类型"),
        ("9+12", "D 攻击阶段/技术"),
        ("9", "靶场节点 · 3 网段"),
        ("139,195", "CTU-13 会话入库"),
        ("720→47", "e_case01→攻击步骤"),
        ("47,195", "B 侧事件过契约"),
    ]
    for i, (n, t) in enumerate(stats):
        x = Inches(0.45 + (i % 2) * 3.0)
        y = Inches(1.55 + (i // 2) * 1.2)
        card(s, x, y, Inches(2.85), Inches(1.05))
        text(s, x + Inches(0.15), y + Inches(0.1), Inches(2.55), Inches(0.55), n,
             size=23, color=CYAN, bold=True)
        text(s, x + Inches(0.15), y + Inches(0.62), Inches(2.55), Inches(0.35), t,
             size=12, color=MUTED, bold=True)
    picture(s, "shot_datamanage.png", Inches(6.6), Inches(1.6), w=Inches(6.3))
    text(s, Inches(6.6), Inches(5.15), Inches(6.3), Inches(0.35),
         "数据管理页：多文件拖拽上传 · 批次管理 · 一键触发分析", size=11.5, color=MUTED)
    card(s, Inches(0.45), Inches(6.42), Inches(5.95), Inches(0.85))
    text(s, Inches(0.65), Inches(6.54), Inches(5.6), Inches(0.65),
         "平台批次：apt29 23,993 · e_case01 720 · demo 96\n"
         "交付 D：apt29_day1 667 · ctu13_s2 1,215",
         size=11, color=FG)


# ---------------------------------------------------------------- 14 开源对比
def page_oss_compare():
    s = new_slide()
    header(s, 15, "开源对比与创新性",
           "8 个同类项目对比 · 详见 docs/开源项目对比与自研系统创新性分析.md")
    card(s, Inches(0.45), Inches(1.5), Inches(7.3), Inches(5.3))
    text(s, Inches(0.7), Inches(1.65), Inches(6.8), Inches(0.4),
         "同类项目 vs 本项目", size=15, color=CYAN, bold=True)
    rows = [
        ("Wazuh", "主机 SIEM，无流量解析与攻击图"),
        ("Security Onion", "全家桶，部署重不适合课程"),
        ("Arkime", "偏存储检索，无溯源链生成"),
        ("Sigma", "仅规则格式，无关联展示"),
        ("OpenCTI / MISP", "情报共享，不解析原始日志"),
        ("Timesketch", "时间线协作，无自动 ATT&CK"),
        ("Zeek", "事实标准，本项目作解析输入"),
    ]
    yy = 2.25
    for name, gap in rows:
        text(s, Inches(0.7), Inches(yy), Inches(6.9), Inches(0.4),
             f"{name}：{gap}", size=13, color=FG)
        yy += 0.62
    card(s, Inches(8.0), Inches(1.5), Inches(4.9), Inches(5.3))
    text(s, Inches(8.25), Inches(1.65), Inches(4.4), Inches(0.4),
         "三条创新点", size=16, color=CYAN, bold=True)
    points = [
        ("① 端到端闭环", "原始日志 → 契约 → 攻击链\n→ 证据回查 → 归因"),
        ("② 契约协作", "三层守卫 + 批次隔离\n6 人并行 0 次字段打架"),
        ("③ 双重实证", "靶场完整入侵链\n+ 公开数据集定量验证"),
    ]
    yy = 2.25
    for t, d in points:
        text(s, Inches(8.25), Inches(yy), Inches(4.4), Inches(0.4),
             t, size=14.5, color=FG, bold=True)
        text(s, Inches(8.45), Inches(yy + 0.42), Inches(4.2), Inches(0.8),
             d, size=12.5, color=MUTED)
        yy += 1.55


# ---------------------------------------------------------------- 15 总结
def page_summary():
    s = new_slide()
    header(s, 16, "总结与展望", "对照任务书逐项交付")
    card(s, Inches(0.45), Inches(1.5), Inches(6.0), Inches(4.4))
    text(s, Inches(0.7), Inches(1.65), Inches(5.5), Inches(0.4),
         "已完成", size=16, color=CYAN, bold=True)
    done = [
        "多源采集融合 → Event V2 统一契约",
        "B 31 类型 · C 10 检测器 · D 9 阶段关联",
        "9 节点靶场完整入侵链实测",
        "CTU-13 + APT29 定量验证",
        "前端 5 页面 + LLM 报告 + Electron",
    ]
    bullets(s, Inches(0.7), Inches(2.25), Inches(5.6), done,
            size=13.5, mark="✓ ", gap=0.68)
    card(s, Inches(6.85), Inches(1.5), Inches(6.0), Inches(4.4))
    text(s, Inches(7.1), Inches(1.65), Inches(5.5), Inches(0.4),
         "局限与下一步", size=16, color=ORANGE, bold=True)
    todo = [
        "内存镜像取证：YARA 扫描",
        "隐蔽信道：HTTP 隧道建模",
        "LLM 升级多智能体协作",
        "打包分发：PyInstaller + electron-builder",
    ]
    bullets(s, Inches(7.1), Inches(2.25), Inches(5.6), todo,
            size=13.5, mark="▸ ", gap=0.68)
    text(s, Inches(0.45), Inches(6.3), Inches(12.3), Inches(0.9),
         "一句话总结：统一契约 + 多源解析 + ATT&CK 关联 + 证据穿透，"
         "把一次真实入侵变成可回查、可量化的完整溯源故事。",
         size=15, color=CYAN, bold=True)


# ---------------------------------------------------------------- 16 致谢
def page_thanks():
    s = new_slide()
    text(s, Inches(0.6), Inches(2.6), Inches(12), Inches(1.2), "谢谢观看 · Q&A",
         size=54, color=FG, bold=True, align=PP_ALIGN.CENTER)
    text(s, Inches(0.6), Inches(4.0), Inches(12), Inches(0.6),
         "恶意攻击行为溯源分析系统 · 网络空间安全课程设计 题3", size=18,
         color=MUTED, align=PP_ALIGN.CENTER)
    text(s, Inches(0.6), Inches(4.8), Inches(12), Inches(0.5),
         "演示路径：启动平台.bat → 数据管理页选批次 → 各页面查看",
         size=13, color=MUTED, align=PP_ALIGN.CENTER)


def main():
    page_cover()
    page_toc()
    page_bg()
    page_arch()
    page_contract()
    page_modules()
    page_modules_c_build()
    page_modules_c_hit()
    page_module_d_build()
    page_module_d_trace()
    page_range()
    page_range_result()
    page_ctu13()
    page_apt29()
    page_frontend()
    page_overview()
    page_oss_compare()
    page_summary()
    page_thanks()
    try:
        prs.save(OUT)
        print(f"saved: {OUT} ({len(prs.slides._sldIdLst)} slides)")
    except PermissionError:
        alt = OUT.replace(".pptx", "-新.pptx")
        prs.save(alt)
        print(f"LOCKED: {OUT} 正被 PowerPoint 占用，已另存: {alt}")
        print("关闭 PowerPoint 后把 -新 文件重命名回去即可")


if __name__ == "__main__":
    main()
