/* ============================================================
 * app.js — 全局应用对象：tab 切换 + 渲染入口（成员F）
 * ============================================================
 * 结构说明（先看这个再看其他文件）：
 *   - App 是全局对象，所有页面模块（stats/timeline/chain/report）
 *     都通过 App.xxx 使用公共工具函数和全局数据。
 *   - App.DATA 是全站唯一的数据仓库：
 *       events: 事件数组（19公共字段 + id）
 *       chain:  { nodes, links } 攻击链
 *       mode:   "live"(后端已连接) | "demo"(回退mock)
 *   - index.html 里先引入 api/stats/timeline/chain/report，
 *     最后引入本文件；DOMContentLoaded 后调 App.init() 启动。
 * ============================================================ */

const App = {
  /* ---------- 全局数据 ---------- */
  /* hostMap: IP→主机名映射（契约：不进事件字段，后端单独维护；
   *          mock 模式下来自 mock/host_map.json，见 api.js loadHostMap） */
  DATA: { events: [], chain: { nodes: [], links: [] }, hostMap: {}, mode: "demo" },

  /* ---------- 契约相关的常量与工具函数 ---------- */

  /* severity 四档语义（契约原文）：
   *   0 正常/未标记、1 低、2 中、3 高。
   * cls 是时间线上的 CSS 类，用来给圆点染色。 */
  SEVERITY: {
    0: { label: "正常", cls: "" },
    1: { label: "低", cls: "sev1" },
    2: { label: "中", cls: "sev2" },
    3: { label: "高", cls: "sev3" },
  },

  /* 攻击阶段配色表——照抄全局契约的"攻击阶段映射"。
   * 攻击链图、时间线、报告页都用它，保证全站阶段颜色一致。
   * （ATT&CK Kill Chain 经典八阶段 + D 实际新增的 Defense Evasion，
   *   2026-09-08 A 确认实际输出共 9 个阶段——D 用 Defense Evasion
   *   标记 log_cleared（1102 清日志）等反取证行为）
   * 取色一律走下面的 stageColor()（容错查找），不要直接查表。 */
  STAGE_COLORS: {
    "Initial Access": "#dc2626",        // 初始访问
    "Execution": "#ea580c",             // 执行
    "Persistence": "#d97706",           // 持久化
    "Privilege Escalation": "#7c3aed",  // 权限提升
    "Defense Evasion": "#0f766e",       // 防御规避（D 新增第9阶段，teal 区分全表）
    "Lateral Movement": "#2563eb",      // 横向移动
    "Collection": "#0891b2",            // 收集
    "Command and Control": "#be185d",   // 命令与控制
    "Exfiltration": "#b91c1c",          // 数据外传
  },

  /* source 六值枚举（契约冻结）→ 界面显示用的中文名。
   * 前端只做"翻译"，绝不自造第 7 个值。 */
  SOURCE_LABEL: {
    windows_evtx: "Windows EVTX",
    sysmon: "Sysmon",
    linux_auth: "Linux auth",
    linux_audit: "Linux audit",
    network_pcap: "PCAP 流量",
    network_zeek: "Zeek 日志",
  },

  /* anomaly_flags 规则名 → 中文标签（契约冻结 9 个规则名）。
   * 时间线 / 详情弹窗共用：徽章显示中文，title 悬停保留英文原名
   * （规则命中溯源回查原始规则名时用）。未知规则名回退显示原名。 */
  FLAG_LABEL: {
    offhour_login: "非工作时间登录",
    brute_force: "暴力破解",
    username_enumeration: "用户名枚举",
    encoded_exec: "编码执行",
    remote_download: "远程下载",
    registry_persistence: "注册表持久化",
    suspicious_process: "可疑进程",
    webshell_execution: "Webshell执行",
    remote_service_connection: "远程服务连接",
  },

  /* detail 已知键 → 中文标签。
   * 依据：契约《统一数据契约.txt》第 6 节 + 项目各模块实际产出键的并集。
   * 属于"详情组件"的一部分：时间线内嵌面板 / 攻击链侧栏事件详情共用。
   * detail 是开放对象，未知键不在表里 → 原样展示（绝不丢字段）。 */
  DETAIL_LABEL: {
    parent_process: "父进程",
    parent_cmdline: "父进程命令行",
    file_path: "文件路径",
    hashes: "文件哈希",
    registry_key: "注册表键",
    registry_value_name: "注册表值名",
    registry_value_data: "注册表值数据",
    registry_operation: "注册表操作",
    src_port: "源端口",
    domain: "域名",
    uri: "URI",
    method: "请求方法",
    status_code: "状态码",
    bytes_in: "入流量",
    bytes_out: "出流量",
    attack_stage: "攻击阶段",
    mitre_technique: "MITRE 技术",
    logon_id: "登录会话 ID",
    substatus: "登录子状态码",
    substatus_desc: "登录子状态说明",
    /* 以下为 B/C/D 各模块实际产出中出现过的键（持续补充） */
    log_name: "日志通道",
    target_user: "目标用户",
    group_name: "用户组",
    privilege: "权限",
    service_name: "服务名",
    task_name: "计划任务名",
    sudo_command: "sudo 命令",
    sudo_user: "sudo 用户",
    packets: "数据包数",
    bytes: "字节数",
    duration_sec: "持续时长（秒）",
    end_time: "结束时间",
    flow_key: "流标识",
    peer_host: "对端主机",
    direction: "连接方向",
    dns_queries: "DNS 查询列表",
  },

  /* Windows logon_type 档位 → 中文含义（展示辅助；未知档位只显示数字） */
  LOGON_TYPE_LABEL: {
    2: "交互式登录", 3: "网络登录", 4: "批处理", 5: "服务", 7: "解锁",
    8: "网络明文", 9: "新凭据", 10: "远程交互", 11: "缓存域凭据",
  },

  /**
   * 攻击阶段 → 颜色（容错版查找）。
   * 依次尝试：精确匹配 → 忽略大小写 → 包含匹配（比如数据源给出
   * "Initial Access (T1190)" 或大小写变体也能命中）→ 兜底灰色。
   * D 的 stage 取值口径尚未 100% 锁死为契约全名，所以查找要宽容。
   */
  stageColor(stage) {
    if (!stage) return "#64748b";
    const keys = Object.keys(this.STAGE_COLORS);
    if (keys.includes(stage)) return this.STAGE_COLORS[stage];
    const lower = String(stage).toLowerCase();
    const ci = keys.find(k => k.toLowerCase() === lower);
    if (ci) return this.STAGE_COLORS[ci];
    const part = keys.find(k => lower.includes(k.toLowerCase()));
    return part ? this.STAGE_COLORS[part] : "#64748b";
  },

  /**
   * 展示层主机名回退规则（契约原文）：
   *   target_host ?? target_ip —— 有主机名显示主机名，没有就显示 IP，
   *   禁止把 IP 字符串塞进 host 字段。
   *
   * "??"（空值合并运算符）：只有 null/undefined 才取右边的值，
   * 空字符串不会触发回退——这正好符合契约"缺失一律 null"的语义。
   */
  hostOrIp(entity) {
    if (typeof entity === "string") return entity;
    if (!entity) return "-";
    return entity.host ?? entity.ip ?? "-";
  },

  /**
   * 时间格式化：ISO8601 UTC+8 → "MM-DD HH:MM:SS"。
   * 契约规定事件时间统一 UTC+8（如 2026-09-08T13:10:00+08:00），
   * 所以这里不做时区换算，直接截字符串（快且不会引入时区bug）。
   */
  fmtTime(iso) {
    if (!iso) return "-";
    return iso.slice(5, 19).replace("T", " ");
  },

  /**
   * HTML 转义——安全基本功。
   * 事件数据里有 raw_log（原始日志原文），里面可能有 < > "，
   * 直接 innerHTML 插入会被浏览器当标签解析，轻则布局乱、
   * 重则 XSS。所有动态字符串进 innerHTML 前必须过这里。
   */
  esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  },

  /**
   * 详情表格一行（时间线内嵌面板与详情弹窗共用）。
   * 契约的 null 规则：缺失一律 null，禁止 "unknown"/0/"" 占位；
   * 对应的前端约定（2026-09-08 统一口径）：null 字段整行不渲染，
   * 不显示 "null" 字样——契约原话"前端渲染时 null 字段直接不显示"。
   * 返回空字符串而不是占位行，调用方直接拼接即可。
   */
  kvRow(label, value, formatter) {
    if (value === null || value === undefined) return "";
    const v = formatter ? formatter(value) : this.esc(value);
    return `<tr><th>${label}</th><td>${v}</td></tr>`;
  },

  /** 异常规则名徽标（anomaly_flags 是数组，一个事件可带多个规则命中）。
   *  显示中文（App.FLAG_LABEL 映射），title 保留英文原名供回查；
   *  映射表没有的规则名（未来新增）回退显示原名，绝不显示空白。 */
  flagBadges(flags) {
    if (!flags || flags.length === 0) return "";
    return flags.map(f =>
      `<span class="chip flag" title="${this.esc(f)}">${this.esc(this.FLAG_LABEL[f] || f)}</span>`
    ).join(" ");
  },

  /** 按 id 查事件——契约：前端跳转/定位一律用 id，不用 source_event_id */
  eventById(id) {
    return this.DATA.events.find(e => e.id === Number(id));
  },

  /**
   * 主机展示键（需求⑥：host_map 主机名优先，无映射显示 IP）。
   * 契约"target_host ?? target_ip"的落地实现，Dashboard 主机统计
   * 和时间线主机列/过滤器共用这一个口径：
   *   1) 事件自身的 host 字段（解析器已写入主机名）非空 → 直接用；
   *   2) 否则拿 src_ip / dst_ip 查 hostMap → 有映射用主机名；
   *   3) 没映射 → 显示裸 IP；
   *   4) 全缺 → null（调用方跳过这条，页面绝不显示 "unknown"）。
   * 全程 safeField 取值，字段缺失不抛异常。
   */
  displayHostKey(e, hostMap) {
    const map = hostMap || this.DATA.hostMap || {};
    const host = safeField(e, "host");
    if (host) return host;
    for (const key of ["src_ip", "dst_ip"]) {
      const ip = safeField(e, key);
      if (ip && map[ip]) return map[ip];      // 有映射 → 主机名
    }
    for (const key of ["src_ip", "dst_ip"]) {
      const ip = safeField(e, key);
      if (ip) return ip;                       // 无映射 → IP（契约允许的回退）
    }
    return null;
  },

  /**
   * 跳转到"攻击时间线"并应用过滤条件（Dashboard 卡片/图形点击的中枢）。
   *
   * 设计：stats.js 不直接操作时间线的 DOM（页面模块解耦），
   * 统一走这里：先模拟点击 tab（复用 bindTabs 的切换逻辑，
   * 包括 page-shown 事件让 ECharts resize），再把 filter 交给
   * timeline.js 注册的 _applyTimelineFilter 回调落到控件上。
   *
   * @param {Object} filter 可选条件：{anomalyOnly, eventType, source,
   *                        severity, hour, host}，未给的条件不动
   */
  showTimeline(filter = {}) {
    const btn = document.querySelector('#tabs .tab[data-tab="timeline"]');
    if (btn) btn.click();
    if (typeof this._applyTimelineFilter === "function") {
      this._applyTimelineFilter(filter);
    }
  },

  /* ============================================================
   * 启动流程
   * ============================================================ */
  async init() {
    const report = document.getElementById("report");
    report.innerHTML = '<p class="muted">数据加载中…</p>';
    try {
      /* Promise.all 并发加载事件、攻击链、主机映射：
       * 三个请求互不依赖，串行等会把启动时间翻倍。 */
      const [ev, ch, hm] = await Promise.all([loadEvents(), getAttackChain(), loadHostMap()]);
      /* 封箱规则：events/chain 永远是数组（错误/空态给 []），
       * 页面模块渲染空数据不会崩；真实状态记在 evState/chState，
       * 由下方徽章如实展示——Live 模式绝不拿 mock 充数。 */
      this.DATA.events = Array.isArray(ev.events) ? ev.events : [];
      this.DATA.chain = ch.chain && Array.isArray(ch.chain.links) ? ch.chain : { nodes: [], links: [] };
      this.DATA.hostMap = hm || {};
      this.DATA.evState = ev.state || (ev.mode === "demo" ? "ok" : "error");
      this.DATA.chState = ch.state || (ch.mode === "demo" ? "ok" : "error");
      this.DATA.evError = ev.error || "";
      this.DATA.chError = ch.error || "";
      this.DATA.mode = ev.mode === "demo" && ch.mode === "demo" ? "demo" : "live";
    } catch (err) {
      /* 能走到这里说明连本地 mock 都挂了（比如没起 http.server） */
      report.innerHTML = `<p style="color:var(--anomaly)">数据加载失败：${this.esc(err.message)}</p>`;
      return;
    }

    /* 状态徽章（封箱）：Demo → 常驻演示徽章；Live → 按真实状态显示
     * 错误/空态提示，正常时隐藏。绝不在 Live 下显示演示徽章。 */
    const badge = document.getElementById("mode-badge");
    if (this.DATA.mode === "demo") {
      badge.textContent = "演示模式（手动开启，数据为内置样例）";
      badge.classList.remove("hidden");
    } else if (this.DATA.evState === "error" && this.DATA.chState === "error") {
      badge.textContent = `Live 模式 · 后端未连接（不回退演示数据）：${this.DATA.evError}`;
      badge.classList.remove("hidden");
    } else if (this.DATA.evState === "error" || this.DATA.chState === "error") {
      badge.textContent = `Live 模式 · 部分接口异常：${this.DATA.evError || this.DATA.chError}`;
      badge.classList.remove("hidden");
    } else if (this.DATA.evState === "empty" && this.DATA.chState === "empty") {
      badge.textContent = "Live 模式 · 数据库为空，未检测到任何事件";
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }

    this.bindTabs();
    this.bindModal();
    this.bindDemoToggle();
    // 四个页面模块各渲染各的，互相不依赖
    renderStats(this.DATA);
    renderTimeline(this.DATA);
    renderChain(this.DATA);
    initReport(this.DATA);
  },

  /* ---------- Demo Mode 开关（封箱：mock 只在显式 Demo 模式使用） ----------
   * 页脚按钮切换 + 整页刷新重取数据。URL ?demo=1 优先级更高，
   * 评委演示可以用带参数的链接直达确定性 Demo。 */
  bindDemoToggle() {
    const btn = document.getElementById("demo-toggle");
    if (!btn) return;
    const sync = () => { btn.textContent = isDemoMode() ? "退出演示模式（回到 Live）" : "进入演示模式（mock 数据）"; };
    sync();
    btn.addEventListener("click", () => {
      setDemoMode(!isDemoMode());
      location.reload();
    });
  },

  /* ---------- Tab 切换 ---------- */
  bindTabs() {
    const tabs = document.querySelectorAll("#tabs .tab");
    tabs.forEach(btn => {
      btn.addEventListener("click", () => {
        // 1) 高亮当前按钮
        tabs.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        // 2) 只显示对应 section（class="page active" 才 display:block）
        document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
        const page = document.getElementById(`page-${btn.dataset.tab}`);
        page.classList.add("active");
        // 3) 广播"页面显示了"事件——ECharts 在 display:none 的容器里
        //    初始化时宽高是 0，画出来是空白；切 tab 后必须 resize 重算。
        window.dispatchEvent(new Event("page-shown"));
      });
    });
  },

  /* ---------- 事件详情弹窗：点遮罩/✕ 关闭 ---------- */
  bindModal() {
    const modal = document.getElementById("modal");
    document.getElementById("modal-close").addEventListener("click", () => modal.classList.add("hidden"));
    modal.addEventListener("click", e => { if (e.target === modal) modal.classList.add("hidden"); });
  },

  /**
   * 事件详情弹窗——把 19+1 个字段逐行展示。
   * 这是"契约逐一对得上"的验收现场：每条事件的所有字段
   * （包括 detail 里的独有键）都能在这里查到，raw_log 完整展示。
   */
  openEventDetail(id) {
    const e = this.eventById(id);
    if (!e) return;
    const sev = this.SEVERITY[e.severity] || this.SEVERITY[0];

    document.getElementById("modal-title").innerHTML =
      `事件 #${e.id} <span class="chip">${this.esc(e.event_type)}</span> ` +
      `<span class="chip src">${this.esc(this.SOURCE_LABEL[e.source] || e.source)}</span> ` +
      `<span class="chip sev-${e.severity}">${sev.label}</span> ${this.flagBadges(e.anomaly_flags)}`;

    /* detail 是开放对象：每类事件的独有字段都在里面
     * （parent_process / file_path / registry_* / src_port / domain / uri...）。
     * 值本身也可能是对象（比如 C 模块的 dns_queries 数组），
     * 所以统一 JSON.stringify 后展示。 */
    const d = e.detail || {};
    const detailRows = Object.keys(d).length
      ? Object.entries(d).map(([k, v]) =>
          `<tr><th>detail.${this.esc(k)}</th><td>${this.esc(typeof v === "object" ? JSON.stringify(v) : v)}</td></tr>`
        ).join("")
      : `<tr><th>detail</th><td>{}</td></tr>`; // 契约：无额外内容时 detail 传 {}

    document.getElementById("modal-body").innerHTML = `
      <table class="kv">
        ${this.kvRow("id", e.id)}
        ${this.kvRow("timestamp", e.timestamp)}
        ${this.kvRow("host", e.host)}
        ${this.kvRow("source", e.source, v => this.esc(this.SOURCE_LABEL[v] || v))}
        ${this.kvRow("source_event_id", e.source_event_id)}
        ${this.kvRow("event_type", e.event_type)}
        ${this.kvRow("user", e.user)}
        ${this.kvRow("process", e.process)}
        ${this.kvRow("src_ip", e.src_ip)}
        ${this.kvRow("dst_ip", e.dst_ip)}
        ${this.kvRow("dst_port", e.dst_port)}
        ${this.kvRow("protocol", e.protocol)}
        ${this.kvRow("logon_type", e.logon_type)}
        ${this.kvRow("session_id", e.session_id)}
        ${this.kvRow("cmdline", e.cmdline)}
        ${detailRows}
        ${this.kvRow("description", e.description)}
        ${this.kvRow("severity", e.severity, v => `${v}（${(this.SEVERITY[v] || {}).label || "?"}）`)}
        ${this.kvRow("anomaly_flags", e.anomaly_flags, v => this.esc(JSON.stringify(v)))}
      </table>
      <div class="rawlog-title">raw_log（原始日志证据）</div>
      <div class="rawlog">${this.esc(e.raw_log)}</div>
    `;
    document.getElementById("modal").classList.remove("hidden");
  },

  /**
   * 事件详情组件（共享）——三区详情面板 HTML。
   * 时间线 tab（卡片内展开）与攻击链 tab（侧栏事件展开）复用同一份，
   * 保证两处证据展示口径完全一致：
   *   a. 关键字段——null 整行不渲染（契约：不显示 "null" 字样）；
   *   b. detail——开放对象全遍历，已知键配中文标签（DETAIL_LABEL）；
   *   c. raw_log——等宽深色代码块原样展示 + "溯源证据"说明条。
   * 返回的 HTML 里有 .btn-copy 按钮，复制功能由 document 级委托统一处理
   * （见文件底部的 copyButtonDelegation），页面模块无需各自绑定。
   */
  buildEventDetailHTML(e) {
    /* ---- a. 关键字段：null 直接跳过，整行不渲染 ---- */
    const row = (label, text, mono) =>
      `<tr><th>${this.esc(label)}</th><td${mono ? ' class="mono"' : ""}>${this.esc(text)}</td></tr>`;
    const rows = [];
    const id = safeField(e, "id");
    if (id !== null) rows.push(row("id（数据库唯一编号）", String(id)));
    const seid = safeField(e, "source_event_id");
    if (seid !== null) rows.push(row("原始日志编号（source_event_id）", String(seid)));
    const user = safeField(e, "user");
    if (user) rows.push(row("用户（user）", user));
    const process = safeField(e, "process");
    if (process) rows.push(row("进程（process）", process));
    const sip = safeField(e, "src_ip");
    if (sip) rows.push(row("源 IP（src_ip）", sip));
    const dip = safeField(e, "dst_ip");
    if (dip) rows.push(row("目的 IP（dst_ip）", dip));
    const dport = safeField(e, "dst_port");
    if (dport !== null) rows.push(row("目的端口（dst_port）", String(dport)));
    const proto = safeField(e, "protocol");
    if (proto) rows.push(row("协议（protocol）", proto));
    const cmdline = safeField(e, "cmdline");
    if (cmdline) rows.push(row("命令行（cmdline）", cmdline, true));   // 命令行等宽，便于读
    const lt = safeField(e, "logon_type");
    if (lt !== null) {
      const zh = this.LOGON_TYPE_LABEL[Number(lt)];
      rows.push(row("登录类型（logon_type）", `${lt}${zh ? `（${zh}）` : ""}`));
    }
    const source = safeField(e, "source");
    if (source) rows.push(row("数据来源（source）", this.SOURCE_LABEL[source] || source));

    /* ---- b. detail：开放对象全遍历，已知键配中文标签 ---- */
    const d = safeField(e, "detail");
    const dEntries = (d && typeof d === "object" && !Array.isArray(d))
      ? Object.entries(d) : [];
    const detailHtml = dEntries.length === 0
      ? `<p class="muted">detail 为空对象 {}（契约：该类事件无独有字段）</p>`
      : `<table class="kv">${dEntries.map(([k, v]) => {
          const label = this.DETAIL_LABEL[k] ? `${this.DETAIL_LABEL[k]}（detail.${k}）` : `detail.${k}`;
          // 值可能是对象/数组（如 C 模块的 dns_queries），统一 JSON.stringify 成字符串
          const text = (v !== null && typeof v === "object") ? JSON.stringify(v) : String(v);
          return `<tr><th>${this.esc(label)}</th><td class="mono">${this.esc(text)}</td></tr>`;
        }).join("")}</table>`;

    /* ---- c. raw_log：深色等宽代码块 + 溯源证据说明 ---- */
    const raw = safeField(e, "raw_log") ?? "";

    return `
      <div class="tl-detail">
        <div class="tl-detail-head">
          <b>事件详情 #${this.esc(String(safeField(e, "id") ?? "?"))}</b>
          <button class="btn-copy" data-id="${this.esc(String(id ?? ""))}">复制 JSON</button>
        </div>
        <h5>① 关键字段</h5>
        <table class="kv">${rows.join("")}</table>
        <h5>② detail（事件独有字段）</h5>
        ${detailHtml}
        <h5>③ raw_log · 原始日志（溯源证据）</h5>
        <div class="evidence-note">以下为解析器入库时原样保留的原始日志，是攻击行为的直接证据，可用于回溯取证。</div>
        <div class="rawlog">${this.esc(raw)}</div>
      </div>`;
  },

  /**
   * 复制完整事件 JSON（详情组件配套按钮 .btn-copy 用）。
   * 两级策略：Clipboard API（https/localhost 安全上下文才可用）
   * → 失败回退 隐藏 textarea + execCommand("copy")（http.server 部署到
   * 局域网 IP 时 Clipboard API 会被浏览器禁掉，老 API 反而能用）。
   */
  async copyEventJSON(id, btn) {
    const e = this.eventById(id);
    const old = btn.textContent;
    if (!e) { btn.textContent = "复制失败"; }
    else {
      const text = JSON.stringify(e, null, 2);   // 2 空格缩进，粘到编辑器可直接读
      let ok = false;
      if (navigator.clipboard && window.isSecureContext) {
        try { await navigator.clipboard.writeText(text); ok = true; } catch (err) { /* 走回退 */ }
      }
      if (!ok) {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { ok = document.execCommand("copy"); } catch (err) { /* 放弃 */ }
        ta.remove();
      }
      btn.textContent = ok ? "已复制 ✓" : "复制失败";
    }
    setTimeout(() => { btn.textContent = old; }, 1500);
  },
};

/* .btn-copy（详情组件的"复制 JSON"按钮）document 级委托：
 * 详情面板可能渲染在时间线卡片内、攻击链侧栏等任意容器，
 * 统一在这里兜住复制动作，各页面模块不必重复绑定。
 * 注意各容器自己的 click 处理器要先对 .tl-detail / .btn-copy 内的
 * 点击早退，避免"复制一下面板被收起"的误触。 */
document.addEventListener("click", ev => {
  const btn = ev.target.closest(".btn-copy");
  if (!btn) return;
  App.copyEventJSON(Number(btn.dataset.id), btn);
});

/* DOMContentLoaded：HTML 解析完再启动。
 * 脚本放在 </body> 前其实已经保证 DOM 就绪，这里再兜一层，
 * 防止以后有人把 <script> 挪回 <head>。 */
window.addEventListener("DOMContentLoaded", () => App.init());
