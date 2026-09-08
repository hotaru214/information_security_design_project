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
   * （八阶段是 ATT&CK Kill Chain 的经典划分） */
  STAGE_COLORS: {
    "Initial Access": "#dc2626",        // 初始访问
    "Execution": "#ea580c",             // 执行
    "Persistence": "#d97706",           // 持久化
    "Privilege Escalation": "#7c3aed",  // 权限提升
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
   * 详情表格一行。
   * 契约的 null 规则：缺失一律 null，禁止 "unknown"/0/"" 占位；
   * 对应的前端约定：null 字段直接不显示——表格里显示为浅灰
   * "null（不显示）"，让学习时能看清"这条事件哪些字段是空的"。
   */
  kvRow(label, value, formatter) {
    if (value === null || value === undefined) {
      return `<tr><th>${label}</th><td class="null">null（不显示）</td></tr>`;
    }
    const v = formatter ? formatter(value) : this.esc(value);
    return `<tr><th>${label}</th><td>${v}</td></tr>`;
  },

  /** 异常规则名徽标（anomaly_flags 是数组，一个事件可带多个规则命中） */
  flagBadges(flags) {
    if (!flags || flags.length === 0) return "";
    return flags.map(f => `<span class="chip flag">${this.esc(f)}</span>`).join(" ");
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
      const [ev, ch, hm] = await Promise.all([loadEvents(), loadChain(), loadHostMap()]);
      this.DATA.events = ev.events;
      this.DATA.chain = ch.chain;
      this.DATA.hostMap = hm;
      /* 两组数据都来自后端才算 live；
       * 只要有一个回退了 mock，就整站标"演示模式"，避免误导。 */
      this.DATA.mode = ev.mode === "live" && ch.mode === "live" ? "live" : "demo";
    } catch (err) {
      /* 能走到这里说明连本地 mock 都挂了（比如没起 http.server） */
      report.innerHTML = `<p style="color:var(--anomaly)">数据加载失败：${this.esc(err.message)}</p>`;
      return;
    }

    // 演示模式徽章：mock 模式才显示（index.html 里默认带 hidden 类）
    const badge = document.getElementById("mode-badge");
    if (this.DATA.mode !== "live") badge.classList.remove("hidden");

    this.bindTabs();
    this.bindModal();
    // 四个页面模块各渲染各的，互相不依赖
    renderStats(this.DATA);
    renderTimeline(this.DATA);
    renderChain(this.DATA);
    initReport(this.DATA);
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
};

/* DOMContentLoaded：HTML 解析完再启动。
 * 脚本放在 </body> 前其实已经保证 DOM 就绪，这里再兜一层，
 * 防止以后有人把 <script> 挪回 <head>。 */
window.addEventListener("DOMContentLoaded", () => App.init());
