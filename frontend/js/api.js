/* ============================================================
 * api.js — 数据层（成员F）
 * ============================================================
 * 职责：前端所有"拿数据"的代码都集中在这里，页面模块不直接发请求。
 * 这样设计的好处：
 *   1) 后端接口路径/地址变了，只改这一个文件；
 *   2) "连后端"和"连 mock"的切换逻辑只写一遍，所有页面共用。
 *
 * 数据来源策略（验收要求）：
 *   优先请求后端 http://127.0.0.1:8000 的 API；
 *   请求失败（没启动 / 超时 / 返回格式不对）自动回退本地 mock，
 *   并把加载模式（live/demo）返回给 app.js，由它在页面角落
 *   显示"演示模式（后端未连接）"徽章。
 *
 * 契约要点（Event V2 FINAL，动手前必读）：
 *   - 一条事件 = 19 个公共字段；入库后后端额外生成 id。
 *   - mock 数据是"还没入库"的形态，所以没有 id —— 契约规定
 *     mock 阶段前端用数组下标模拟 id（见 withSimulatedIds）。
 *   - 前端跳转/定位/URL 参数一律用 id；source_event_id 只是
 *     原始日志自带的编号（4624、Sysmon 1 等），可重复、网络事件恒 null。
 * ============================================================ */

/* 后端地址：同源优先。
 * 页面由后端 StaticFiles 托管时（8000=主库 / 8001=批次演示库），
 * 直接用同源地址——多批次演示换端口无需改代码；
 * 前端独立部署（http.server 8030 等）时回落到固定后端地址。
 * 注意：不要写 "localhost"——部署到别的机器时它会指向观众自己的电脑。 */
const SAME_ORIGIN_BACKEND = ["8000", "8001"].includes(location.port);
const API_BASE = SAME_ORIGIN_BACKEND ? location.origin : "http://127.0.0.1:8000";

/* 超时 2 秒：后端没启动时，浏览器 fetch 默认会等很久（几十秒的
 * TCP 超时），页面会白屏转圈。必须主动掐断，快速失败。 */
const FETCH_TIMEOUT_MS = 2000;

/* LLM 分析专用超时：后端要等 LLM 生成完再返回（llm_analysis 默认
 * 30s 超时 + 网络余量）。沿用 2s 会在后端正常工作时把请求掐死——
 * 这是"前端 2 秒 vs 后端长 LLM"冲突的解法：按接口语义分超时。 */
const ANALYSIS_TIMEOUT_MS = 60000;

/* 攻击链专用超时：后端 /api/attack-chain 要跑 D 的关联引擎（9 阶段
 * 检测器 + 建图 + BFS），E 实测 2026-09-10 约 2.28s（优化前 3.22s），
 * 已超通用 2s 上限——前端会先 abort，Live 攻击链必然报"连接超时"。
 * 取 10s：约 4 倍余量，既容忍机器负载波动，又不至于白屏等太久。
 * 通用 FETCH_TIMEOUT_MS 保持 2s 不动：/api/events、/api/hosts/map
 * 是轻量查询，快速失败语义对它们仍然正确。 */
const ATTACK_CHAIN_TIMEOUT_MS = 10000;

/* 事件接口专用超时（2026-09-10 Final E 浏览器验收暴露的 P0）：
 * /api/events 在 Final E 数据集下要返回 30,963 条事件，实测 2.017s，
 * 而它此前走的是通用 2s —— 请求被前端自己 abort，页面 Event=0。
 * 注意这是"数据量"问题不是"后端慢"问题：2s 当初够用只是因为 mock
 * 只有 50 条。取 10s：与 ATTACK_CHAIN_TIMEOUT_MS 同一余量级别
 * （约 5 倍），数据量再涨、三请求并发抢 CPU 也不会被前端掐断。
 * 单条事件查询 getEventById() 也复用本常量——单条虽轻，但它发生在
 * 用户点击之后（弹窗同步等待），宁可多等也不能误报"取不到"。
 * 通用 FETCH_TIMEOUT_MS 保持 2s 不动：/api/hosts/map 是轻量查询，
 * "后端没启动就快速失败"的语义对它仍然正确。 */
const EVENTS_TIMEOUT_MS = 10000;

/* ============================================================
 * Live / Demo 模式开关（封箱规则，2026-09-09）
 * ============================================================
 * 默认 Live 模式：接口失败→错误状态、空库→空状态、空链→"未检测
 * 到攻击链"、LLM 失败→后端真实降级结果或失败提示。**禁止静默
 * 替换成固定 mock**——把假数据当真数据展示是演示事故。
 * Demo Mode 必须显式开启，mock 只在这一模式下使用：
 *   1. URL 带 ?demo=1（评委演示的确定性入口；demo=0 强制关闭）；
 *   2. 页脚"演示模式"开关（localStorage 持久化，断网答辩一键切）。
 */
const DEMO_STORAGE_KEY = "isd-demo-mode";

function isDemoMode() {
  try {
    const q = new URLSearchParams(location.search);
    if (q.has("demo")) return q.get("demo") !== "0";
    return localStorage.getItem(DEMO_STORAGE_KEY) === "1";
  } catch (e) {
    return false;   // localStorage 被禁（隐私模式等）→ 默认 live
  }
}

function setDemoMode(on) {
  try {
    localStorage.setItem(DEMO_STORAGE_KEY, on ? "1" : "0");
  } catch (e) { /* 写不进去就算了，isDemoMode 会兜回 false */ }
}

/**
 * 带超时控制的 fetch。
 *
 * 原理（新手要点）：
 *   fetch 本身不支持超时参数，标准做法是配合 AbortController：
 *   1. new 一个 AbortController，它有个 signal（信号量）；
 *   2. 把 signal 传给 fetch，相当于给这次请求装了"取消开关"；
 *   3. setTimeout 到点后调用 controller.abort()，请求立刻失败；
 *   4. finally 里 clearTimeout —— 请求正常完成时把定时器撤掉，
 *      避免它之后再触发（那是无害但不好的习惯）。
 *
 * @param {string} url 请求地址
 * @param {number} ms  超时毫秒数
 * @param {Object} [options] 透传给 fetch 的额外选项（method/headers/body），
 *                           POST /api/analysis 这类带请求体的接口要用
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, ms = FETCH_TIMEOUT_MS, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    /* GET 请求统一加缓存穿透参数：曾出现浏览器缓存了"空库时期"的
     * /api/events 响应，导致页面反复显示 0 事件（服务端实际有数据）。
     * 带请求体的 POST 不受影响，不动。 */
    const isGet = !options.method || options.method === "GET";
    const finalUrl = isGet ? `${url}${url.includes("?") ? "&" : "?"}_cb=${Date.now()}` : url;
    return await fetch(finalUrl, { signal: controller.signal, ...options });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 给 mock 事件补上"模拟 id"。
 *
 * 为什么不直接在 mock/events.json 里写死 id？
 *   因为契约规定 id 是"后端数据库入库时才生成的自增主键"。
 *   mock 文件保持无 id 的真实输入形态，前端加载时按数组下标
 *   补 id（第 1 条 → id=1），这样一旦接上真后端，逻辑无缝切换。
 *
 * 用 {...e, id: i+1} 浅拷贝而不是直接改 e：
 *   不污染原对象——同一份数据如果别处还要用"无 id 的原始形态"，
 *   不会被这里改坏。
 */
function withSimulatedIds(events) {
  return events.map((e, i) => ({ ...e, id: i + 1 }));
}

/* ============================================================
 * normalizeEvent / normalizeEvents —— 单事件归一化（联调适配层）
 * ============================================================
 * 2026-09-09 联调引入。职责：把后端 EventOut 的实际形态修整成
 * 全组契约（Event V2 FINAL）的形态，页面模块永远只认契约字段。
 * 四条处理规则（联调任务书 3a-3d，d 已按封箱规则收紧）+ 一条时间规则：
 *   a) 接口字段 event_id → source_event_id（改名，语义=原始日志编号）；
 *   b) detail / anomaly_flags 缺失 → 补 {} / []（契约必填，缺了页
 *      面组件会炸）；
 *   c) event_type 不在冻结枚举 → console.warn 并原样保留（不私造
 *      也不丢弃——擅自改值会破坏过滤器和统计口径）；
 *   d) id 缺失 → live 事件整条剔除并警告（保真实数据血缘）；mock
 *      由 withSimulatedIds 静默补下标 id（显式 Demo 的设计内行为）；
 *   时间规则：timestamp 解析失败（非 ISO8601 / 空 / 类型不对）→
 *      该事件整体跳过并 console.warn——时间线排序和"按小时统计"
 *      都依赖它，坏一条会污染整页。
 */

/* 契约冻结的 event_type 全集（31 值 = 7 类 30 值 + log_cleared）。
 * 出处：docs/数据格式契约-v1.md 第四节（V2.1 起 log_cleared 转正）。
 * 与 timeline.js 的 EVENT_TYPE_GROUPS 保持同源——那边按 7 类分组
 * 做过滤器下拉，这边只做"是否合法"判定；改枚举必须两处同步。 */
const EVENT_TYPE_ALLOWED = new Set([
  "login_success", "login_failed", "logout",
  "process_start", "process_end",
  "network_connection", "dns_query", "http_request",
  "file_create", "file_read", "file_write", "file_modify", "file_delete",
  "registry_set", "registry_create", "registry_delete", "registry_query",
  "user_created", "user_deleted", "user_modified",
  "group_member_added", "group_member_removed", "privilege_change",
  "service_created", "service_started", "service_stopped", "service_deleted",
  "scheduled_task_created", "scheduled_task_run", "scheduled_task_deleted",
  "log_cleared",
]);

/**
 * 校验契约时间戳：UTC+8 ISO8601（`2026-09-07T09:02:08[.微秒]+08:00`）。
 * @returns {Date|null} 可解析返回 Date；不可解析返回 null
 */
function parseContractTime(ts) {
  if (typeof ts !== "string" || ts.length === 0) return null;
  const d = new Date(ts);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * 归一化单条事件。
 * @param {Object} e 后端/原始事件对象（会被就地修整）
 * @param {number} idx 在列表中的下标（模拟 id 用）
 * @param {boolean} liveMode true=live 数据（缺 id 要警告）；false=mock（静默模拟）
 * @returns {Object|null} 修整后的事件；时间戳坏 → null（调用方跳过）
 */
function normalizeEvent(e, idx, liveMode) {
  if (!e || typeof e !== "object") return null;

  /* 时间规则（任务书 4）：先验时间，坏事件直接跳过——
   * 避免给一个马上要被丢弃的事件做无谓的补字段。 */
  const ts = parseContractTime(safeField(e, "timestamp"));
  if (!ts) {
    console.warn("[api.js] 事件已跳过：timestamp 无法按 ISO8601 解析（index=%d）", idx, e);
    return null;
  }
  /* 不带时区的时间戳会被 new Date 当作浏览器本地时区——国内机器
   * 恰好就是 +08:00 所以结果碰巧对，但这是巧合不是契约。只警告
   * 不丢弃：A 的数据目前都带 +08:00，出现这种数据先人工对齐。 */
  if (!/[+-]\d{2}:?\d{2}$/.test(e.timestamp)) {
    console.warn("[api.js] 事件 timestamp 缺少时区后缀（契约要求 +08:00）：", e.timestamp);
  }

  /* a) event_id → source_event_id（与 normalizeSourceEventId 同规则） */
  const oldVal = safeField(e, "event_id");
  const newVal = safeField(e, "source_event_id");
  e.source_event_id = newVal !== null ? newVal : oldVal;
  delete e.event_id;

  /* b) 契约必填字段缺失兜底 */
  if (e.detail === undefined || e.detail === null) e.detail = {};
  if (e.anomaly_flags === undefined || e.anomaly_flags === null) e.anomaly_flags = [];

  /* c) event_type 冻结枚举校验：只警告不改值 */
  if (!EVENT_TYPE_ALLOWED.has(e.event_type)) {
    console.warn("[api.js] event_type 不在冻结枚举（原样保留）：", e.event_type);
  }

  /* d) id 血缘规则（封箱）：live 事件缺 id → 整条剔除并警告。
   *    不允许用 idx+1 冒充真实 ID——攻击链 evidence_event_ids 和
   *    时间线跳转全靠真 id 关联，假 id 会造成证据错链。
   *    （Demo 模式下 withSimulatedIds 已补下标 id，不会走到这里。） */
  if (e.id === undefined || e.id === null) {
    if (liveMode) {
      console.warn("[api.js] live 事件缺失数据库 id，已剔除以保证证据血缘——请反馈 A（index=%d）", idx, e);
      return null;
    }
    e.id = idx + 1;
  }
  return e;
}

/**
 * 归一化整份事件列表（loadEvents 的 live/mock 两条路都走这里）。
 * 时间戳坏的事件会被剔除，返回的数组可能比入参短。
 */
function normalizeEvents(list, liveMode) {
  const out = [];
  (list || []).forEach((e, idx) => {
    const fixed = normalizeEvent(e, idx, liveMode);
    if (fixed) out.push(fixed);
  });
  return out;
}

/**
 * 加载事件列表（Dashboard / 时间线页共用）。
 *
 * 封箱规则（2026-09-09）：严格 Live / Demo 两态，不再有"失败静默回退"。
 *   Demo（显式开启）→ mock 数据，mode:"demo"；
 *   Live（默认）    → 后端失败 → {state:"error"}（页面显示错误状态）；
 *                     空库     → {state:"empty"}（页面显示空状态）；
 *                     正常     → {state:"ok"}。
 * live 下缺 id 的事件会被 normalizeEvents 剔除（不用 idx+1 冒充，
 * 保住 evidence_event_ids → Event 的真实数据血缘）。
 *
 * @returns {Promise<{events: Array|null, mode: "live"|"demo",
 *                     state: "ok"|"error"|"empty", error?: string}>}
 */
async function loadEvents() {
  if (isDemoMode()) {
    const resp = await fetch("mock/events.json");
    const events = await resp.json();
    /* mock：先按下标补 id（Demo 模式的设计内行为，静默），再归一化 */
    return { events: normalizeEvents(withSimulatedIds(events), false), mode: "demo", state: "ok" };
  }

  try {
    /* 批次过滤（2026-09-10 平台化）：页眉下拉选中的 case_id 传给后端，
     * 同一批次隔离语义的"共存版"——多批共库，按 case_id 取视图。 */
    const cid = resolveCaseId();
    const caseQs = cid ? `?case_id=${encodeURIComponent(cid)}` : "";
    /* 显式传 EVENTS_TIMEOUT_MS（10s）：Final E 30,963 条实测 2.017s，
     * 通用 2s 会把正常响应掐断（见文件头常量区注释）。 */
    const resp = await fetchWithTimeout(`${API_BASE}/api/events${caseQs}`, EVENTS_TIMEOUT_MS);
    if (!resp.ok) {
      return { events: null, mode: "live", state: "error", error: `后端返回 HTTP ${resp.status}` };
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      return { events: null, mode: "live", state: "error", error: "后端返回了非 JSON 内容" };
    }
    if (!Array.isArray(data)) {
      return { events: null, mode: "live", state: "error", error: "后端返回结构不是事件数组" };
    }
    if (data.length === 0) {
      return { events: [], mode: "live", state: "empty" };   // 空库 → 空状态
    }
    return { events: normalizeEvents(data, true), mode: "live", state: "ok" };
  } catch (e) {
    return { events: null, mode: "live", state: "error",
             error: e.name === "AbortError" ? `连接超时（${EVENTS_TIMEOUT_MS / 1000}s）` : "后端未连接" };
  }
}

/**
 * getEventById(id) — 按数据库 id 取单条事件（证据详情弹窗的兜底取数）。
 *
 * 背景（2026-09-10 Final E P0）：攻击链/报告里的"证据事件"chip 点击原本
 * 只走 App.eventById() —— 从启动时 loadEvents() 灌进内存的数组里 find()。
 * 这个隐式依赖意味着：只要 events 列表那次请求失败（超时/后端没起），
 * find() 就是 undefined，而弹窗代码 `if (!e) return;` 静默返回 ——
 * 用户看到的现象是"点证据没反应"，实际是详情没有独立取数能力。
 * 契约规定 events.id 是数据库主键，A 已提供单条查询（GET /api/events/{id}
 * → read_event），所以详情可以直接按 id 取真身，不依赖那 30,963 条
 * 是否已经全量灌进浏览器。
 *
 * 封箱规则不变：
 *   Demo（显式开启）→ 读 mock/events.json，按下标补 id 后按 id 找；
 *   Live 404        → state:"not_found"（如实告知，不编数据）；
 *   Live 其他失败    → state:"error"（**不回退 mock**，也不拿本地数组凑数）。
 *
 * @param {number|string} id 数据库 events.id（不是 source_event_id）
 * @returns {Promise<{event: Object|null, mode: "live"|"demo",
 *                    state: "ok"|"not_found"|"error", error?: string}>}
 */
async function getEventById(id) {
  const nid = Number(id);
  /* id 非法（undefined/NaN）→ 直接报错，不发 /api/events/NaN 这种请求 */
  if (!Number.isFinite(nid)) {
    return { event: null, mode: "live", state: "error", error: "证据事件 id 非法" };
  }

  if (isDemoMode()) {
    try {
      const resp = await fetch("mock/events.json");
      const all = normalizeEvents(withSimulatedIds(await resp.json()), false);
      const hit = all.find(e => e.id === nid);
      return hit ? { event: hit, mode: "demo", state: "ok" }
                 : { event: null, mode: "demo", state: "not_found" };
    } catch (e) {
      return { event: null, mode: "demo", state: "error", error: "演示数据不可用" };
    }
  }

  try {
    const resp = await fetchWithTimeout(
      `${API_BASE}/api/events/${encodeURIComponent(nid)}`, EVENTS_TIMEOUT_MS);
    if (resp.status === 404) {
      /* A 的实现：库里没有这条 → 404 Event not found。这是事实，照实说。 */
      return { event: null, mode: "live", state: "not_found" };
    }
    if (!resp.ok) {
      return { event: null, mode: "live", state: "error", error: `后端返回 HTTP ${resp.status}` };
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      return { event: null, mode: "live", state: "error", error: "后端返回了非 JSON 内容" };
    }
    /* 单条也走 normalizeEvent：event_id→source_event_id 改名、detail/flags
     * 兜底、时间戳校验，保证"弹窗里看到的字段"与列表口径完全一致。
     * live 模式下若这条缺 id / 时间戳不可解析，normalizeEvent 返回 null
     * ——说明后端这条数据不合法，按 error 处理，绝不拿残缺数据渲染。 */
    const ev = normalizeEvent(data, 0, true);
    if (!ev || ev.id == null) {
      return { event: null, mode: "live", state: "error", error: "后端返回的事件数据不合法" };
    }
    return { event: ev, mode: "live", state: "ok" };
  } catch (e) {
    return { event: null, mode: "live", state: "error",
             error: e.name === "AbortError" ? `连接超时（${EVENTS_TIMEOUT_MS / 1000}s）` : "后端未连接" };
  }
}

/**
 * getAttackChain() — 加载攻击链（攻击链页 / 分析报告页共用）。
 *
 * 封箱规则：与 loadEvents 同一套严格 Live/Demo 两态。
 *   Live 失败 → state:"error"（页面显示错误状态，不换 mock）；
 *   Live 空链 → state:"empty"（页面显示"未检测到攻击链"）；
 *   有链才返回 state:"ok" 的真实链数据。
 *
 * @returns {Promise<{chain: {nodes: Array, links: Array}|null,
 *                     mode: "live"|"demo", state: "ok"|"error"|"empty",
 *                     error?: string}>}
 */
async function getAttackChain() {
  if (isDemoMode()) {
    const resp = await fetch("mock/chain.json");
    return { chain: normalizeChain(await resp.json()), mode: "demo", state: "ok" };
  }

  try {
    /* 批次过滤：与 loadEvents 同一 case_id 口径（页眉下拉/URL ?case=）。 */
    const cid = resolveCaseId();
    const caseQs = cid ? `?case_id=${encodeURIComponent(cid)}` : "";
    /* 显式传 ATTACK_CHAIN_TIMEOUT_MS（10s）：后端关联引擎实测 ~2.28s，
     * 默认 2s 会提前 abort（2026-09-10 E 实测暴露的联调问题）。
     * 见文件头常量区的注释——按接口语义分超时。 */
    const resp = await fetchWithTimeout(`${API_BASE}/api/attack-chain${caseQs}`, ATTACK_CHAIN_TIMEOUT_MS);
    if (!resp.ok) {
      return { chain: null, mode: "live", state: "error", error: `后端返回 HTTP ${resp.status}` };
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      return { chain: null, mode: "live", state: "error", error: "后端返回了非 JSON 内容" };
    }
    const links = data && Array.isArray(data.links) ? data.links : [];
    if (links.length === 0) {
      /* 空链（库里没事件 / 关联引擎没跑出链）→ 空状态，如实展示 */
      return { chain: { nodes: [], links: [] }, mode: "live", state: "empty" };
    }
    return { chain: normalizeChain(data), mode: "live", state: "ok" };
  } catch (e) {
    return { chain: null, mode: "live", state: "error",
             error: e.name === "AbortError" ? "连接超时（10s）" : "后端未连接" };
  }
}

/**
 * 攻击链结构归一化（数据边界兼容层，与 normalizeSourceEventId 同思路）。
 *
 * 背景（2026-09-08 与 A 对齐的集成方案）：
 *   D 的关联模块输出的 AttackStep 字段名是 stage / technique_id，
 *   前端（chain.js / report.js）消费的是 attack_stage / mitre_technique。
 *   A 会做 /api/attack-chain adapter 转换，但为了**不依赖 adapter 做
 *   得全不满**，这里做前端侧兜底：
 *     - 字段名：attack_stage ?? stage、mitre_technique ?? technique_id，
 *       mock（契约名）和 live（可能是 D 原始名）两种都认；
 *     - evidence_event_ids（数据库 events.id 数组，D 产出）原样保留，
 *       chain.js 拿它渲染可点击的证据 chip；
 *     - nodes：adapter 若只输出 links 没拼 nodes，前端从 links 两端的
 *       主机自动推导节点表（含坐标），页面照样出图。
 *
 * 不改传入对象（mock/chain.json 是共享数据），返回归一化后的新结构。
 */
function normalizeChain(chain) {
  const out = { nodes: [], links: [], ...chain };
  if (!Array.isArray(out.links)) out.links = [];

  out.links = out.links.map(l => {
    const link = { ...l };
    if (link.attack_stage === undefined) link.attack_stage = safeField(l, "stage");
    if (link.mitre_technique === undefined) link.mitre_technique = safeField(l, "technique_id");
    return link;
  });

  if (!Array.isArray(out.nodes) || out.nodes.length === 0) {
    const seen = {};              // host键 -> 节点对象（同主机多步只建一个节点）
    out.links.forEach(l => {
      ["source", "target"].forEach(side => {
        const host = safeField(l, `${side}_host`);
        const ip = safeField(l, `${side}_ip`);
        const key = host ?? ip;
        if (!key || seen[key]) return;
        const lower = String(key).toLowerCase();
        seen[key] = {
          id: key,
          host: host ?? null,
          ip: ip ?? null,
          role: null,
          // 命名启发式分类：给节点上色用（attacker红 / c2深红 / 受害主机蓝）
          category: lower.includes("attacker") ? "attacker"
                  : lower.includes("c2") ? "c2"
                  : "host",
        };
      });
    });
    const derived = Object.values(seen);
    derived.forEach((n, i) => {
      // layout:none 需要每个节点有坐标：按出现顺序横向排开
      n.x = 60 + i * 230;
      n.y = 130;
    });
    out.nodes = derived;
  }
  return out;
}

/* ============================================================
 * 空值安全取值（全局工具，Dashboard 聚合 / Timeline 过滤共用）
 * ============================================================
 * 为什么需要它（验收标准原话："任何字段缺失不能抛异常"）：
 *   JS 里访问 null.xxx / undefined.xxx 会直接 TypeError 崩掉整页；
 *   聚合统计要遍历几十条事件的十几个字段，任何一条数据缺字段
 *   都不应该炸掉 Dashboard。所以所有动态取值都走这里：
 *     - obj 本身是 null/undefined → 返回 null；
 *     - 字段不存在或值为 undefined → 返回 null（统一成 null，契约语义）；
 *   try/catch 是最后防线（比如 obj 是个数字这种脏数据也不崩）。
 */
function safeField(obj, key) {
  try {
    const v = obj ? obj[key] : undefined;
    return v === undefined ? null : v;
  } catch (e) {
    return null;
  }
}

/**
 * 加载 IP→主机名映射表（host_map）。
 *
 * 契约背景：IP→Host 映射不进事件字段，由 A 后端单独维护，
 * 展示规则 target_host ?? target_ip——有主机名显示主机名，没有显示 IP。
 *
 * 数据来源优先级：
 *   1. 后端 GET /api/hosts/map（A 已实现，直接返回 {ip:hostname}，
 *      由 data/hosts.csv 入库生成，含 attacker/c2/exfil 的映射）；
 *   2. 回退 GET /api/hosts（[{ip,hostname,...}] 形态也兼容——万一
 *      map 接口变动还有一层缓冲）；
 *   3. 回退 mock/host_map.json（out/build_mock.py 从 data/hosts.csv 生成）；
 *   4. 连 mock 都没有 → 返回 {}，展示层自然回退显示 IP，页面不报错。
 *
 * @returns {Promise<Object>} 归一化的 { "10.0.0.5": "web-server", ... }
 */
async function loadHostMap() {
  /* Demo 模式直接用 mock 映射；Live 模式只信后端——拿不到就返回
   * {}，展示层回退显示 IP（{} 是"没有映射"这一事实，不是假数据）。 */
  if (isDemoMode()) {
    try {
      return await (await fetch("mock/host_map.json")).json();
    } catch (e) {
      return {};
    }
  }
  let raw = null;
  for (const path of ["/api/hosts/map", "/api/hosts"]) {
    try {
      const resp = await fetchWithTimeout(`${API_BASE}${path}`);
      if (resp.ok) {
        raw = await resp.json();
        if (raw && (Array.isArray(raw) ? raw.length > 0 : Object.keys(raw).length > 0)) break;
        raw = null;   // 空数据视同失败，继续下一个来源
      }
    } catch (e) { /* 该来源不可用，试下一个 */ }
  }
  if (!raw || typeof raw !== "object") {
    /* Live 模式拿不到映射 → 返回空 map（展示层回退显示 IP），
     * 不回退 mock——映射缺失是事实，不是换数据的理由。 */
    return {};
  }
  // 归一化成平面对象 {ip: hostname}，过滤掉缺 ip 或缺主机名的脏行
  const map = {};
  if (Array.isArray(raw)) {
    raw.forEach(row => {
      const ip = safeField(row, "ip");
      const host = safeField(row, "hostname") ?? safeField(row, "host");
      if (ip && host) map[ip] = host;
    });
  } else {
    Object.entries(raw).forEach(([ip, host]) => {
      if (ip && host) map[ip] = host;
    });
  }
  return map;
}

/* ============================================================
 * getAnalysisReport() — 分析报告数据层（成员F）
 * ============================================================
 * 架构约束（需求原文）："LLM 调用属于后端，前端只消费结构化结果，
 * 禁止在前端直接调 LLM API。"
 *   - 前端只做一件事：POST /api/analysis（带分析范围），
 *     拿回结构化 JSON 后交给 report.js 渲染；
 *   - 后端收到请求后自己组织 prompt（攻击链+证据事件）去调 LLM，
 *     把 LLM 输出解析成下面的固定结构再返回——LLM 的 key、
 *     网络细节全部留在后端，前端零接触（key 不落前端）；
 *   - mock（当前阶段）：返回固定 JSON，结构与真实接口完全一致，
 *     后端就绪后本函数一行不用改，report.js 更不用改。
 *
 * 返回结构（后端 LLM 分析结果契约）：
 *   attack_path      string[]  攻击路径节点（主机名按攻击顺序）
 *   summary          string    攻击路径文字摘要
 *   key_evidences    [{event_id, reason}]  关键证据（event_id=数据库 id）
 *   mitre_mapping    [{stage, technique, evidence_event_ids:number[]}]
 *   risk_level       string    风险等级（低危/中危/高危/严重）
 *   recommendations  string[]  处置建议
 *
 * id 口径（重要，答辩会被问）：
 *   key_evidences[].event_id 和 mitre_mapping[].evidence_event_ids
 *   存的都是数据库 events.id（整数）。mock 阶段前端用"数组下标+1"
 *   模拟 id（见 withSimulatedIds），所以 mock JSON 里的 id 都能在
 *   mock 事件列表里找到对应事件（id=12 即第 12 条，T1190 Web 攻击）。
 * ============================================================ */

/**
 * mock 固定报告 JSON（演示模式，断网可答辩）。
 * 内容按 mock/chain.json 的真实攻击链编写（与攻击链 tab 互相印证），
 * 所有 id 均指向 mock 事件列表里的真实事件，点击证据可跳转详情。
 */
const MOCK_ANALYSIS_REPORT = {
  attack_path: ["attacker-external", "web-server", "office-pc-01", "core-server", "c2-server"],
  summary:
    "攻击者 203.0.113.66 于 09:01 前后对 web-server 发起端口扫描与 Web 攻击载荷投递（T1190），" +
    "利用 Web 应用漏洞取得执行权限；09:02 起 web-server 出现 cmd.exe/rundll32 编码执行与远程下载行为（T1059），" +
    "载荷落地后建立持久化；09:03 攻击者经 SMB/RDP 从 web-server 横向移动至 office-pc-01，" +
    "再经 SSH 抵达 core-server（T1021）；09:04 起 core-server 出现 60s 固定间隔 C2 心跳与 DNS 隐蔽信道（T1071）；" +
    "09:06 core-server 向外部 45.33.32.156 上传约 1.2MB 数据（T1041），判定发生数据外传。" +
    "整条链路为典型的「初始访问 → 执行落地 → 横向移动 → C2 控制 → 数据外传」入侵链。",
  key_evidences: [
    { event_id: 12, reason: "Web 攻击载荷命中（http_attack / T1190）——初始入侵点" },
    { event_id: 15, reason: "cmd.exe 编码执行并派生 rundll32 远程下载（remote_download/encoded_exec）——载荷落地" },
    { event_id: 23, reason: "web-server 经 SMB(445) 横向连接 office-pc-01（remote_service_connection / T1021）——横向移动起点" },
    { event_id: 27, reason: "core-server 以 60s 固定间隔外联 C2（c2_beacon / T1071）——命令与控制信道" },
    { event_id: 47, reason: "core-server 向外部 45.33.32.156:80 上传数据（exfiltration / T1041）——数据外传" },
  ],
  mitre_mapping: [
    { stage: "Initial Access", technique: "T1190", evidence_event_ids: [12, 13] },
    { stage: "Execution", technique: "T1059", evidence_event_ids: [15, 16] },
    { stage: "Lateral Movement", technique: "T1021", evidence_event_ids: [23, 25, 26] },
    { stage: "Command and Control", technique: "T1071", evidence_event_ids: [27, 33] },
    { stage: "Exfiltration", technique: "T1041", evidence_event_ids: [47] },
  ],
  risk_level: "高危",
  recommendations: [
    "立即隔离 web-server / office-pc-01 / core-server，阻断其对外一切连接",
    "封禁攻击源 203.0.113.66 及外联目标 45.33.32.156、c2bad-dns.com",
    "修复 web-server 输入校验缺陷（T1190 入口），排查 Web 日志中的其他入侵痕迹",
    "全域重置凭据并审计 4624/4625 登录记录，确认横向移动是否触及更多主机",
    "评估 core-server 上传数据内容与范围，确认泄露等级并按预案上报",
  ],
};

/* ============================================================
 * getAttribution() — 身份溯源（Attribution）数据层（成员F）
 * ============================================================
 * 数据来源：A/D 已实现的 GET /api/attack-chain/attribution（case_id 可选）。
 * 前端只做两件事：取结构化结果 + 交给 report.js 渲染；**不参与归因计算**，
 * 也不补充任何外部情报（WHOIS / passive DNS / 注册信息）——后端返回什么
 * 就展示什么，C2 部分由页面明确标注为"本地关联分析"。
 *
 * case_id 从哪来（**不写死 case01**）：
 *   1) URL 查询参数 ?case=xxx（验收/多批次演示可显式指定）；
 *   2) localStorage 的 isd-case-id（若页面上曾选择过 case）；
 *   3) 都没有 → 不带 case_id 请求，由后端分析当前库里的全部事件
 *      （库中只有一个 case 时，后端直接返回该 case 的单一画像）。
 *
 * 封箱规则（与其他接口一致）：
 *   Live 失败 → state:"error"（**不回退 mock**）；
 *   Live 空   → state:"empty"（多 case 形态下 profiles 为空 = 库里没有 case）；
 *   Live 正常 → state:"ok"——注意 payload 里的 attribution_status 可能是
 *               "insufficient_evidence"，那是**正常结果**，页面如实显示
 *               "证据不足"，既不报错也不伪造相似度排名；
 *   Demo 模式 → state:"demo_unavailable"：内置样例不含 attribution 结果
 *               （它是后端实时分析产物），如实告知，不编造归因数据。
 * ============================================================ */

/** 当前 case（不写死具体值；取不到返回 null → 后端按全库分析） */
function resolveCaseId() {
  try {
    const fromUrl = new URLSearchParams(location.search).get("case");
    if (fromUrl) return fromUrl;
    const stored = localStorage.getItem("isd-case-id");
    if (stored) return stored;
  } catch (e) { /* URL/localStorage 不可用 → 按全库分析 */ }
  return null;
}

/**
 * 加载身份溯源结果。
 * @param {string|null} caseId 不传则用 resolveCaseId() 的结果
 * @returns {Promise<{attribution: Object|null, mode: "live"|"demo",
 *                    state: "ok"|"empty"|"error"|"demo_unavailable",
 *                    error?: string}>}
 */
async function getAttribution(caseId = resolveCaseId()) {
  if (isDemoMode()) {
    /* 演示模式不内置 attribution 样例：不编造归因数据（封箱规则） */
    return { attribution: null, mode: "demo", state: "demo_unavailable" };
  }

  try {
    const url = `${API_BASE}/api/attack-chain/attribution` +
      (caseId ? `?case_id=${encodeURIComponent(caseId)}` : "");
    /* 与 /api/attack-chain 是同一个关联引擎（correlate_events + 指纹/相似度
     * 匹配），因此复用同一超时常量；实测 case01（720 事件）约 0.22s，
     * Final E 量级与攻击链同档。 */
    const resp = await fetchWithTimeout(url, ATTACK_CHAIN_TIMEOUT_MS);
    if (!resp.ok) {
      return { attribution: null, mode: "live", state: "error", error: `后端返回 HTTP ${resp.status}` };
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      return { attribution: null, mode: "live", state: "error", error: "后端返回了非 JSON 内容" };
    }
    if (!data || typeof data !== "object") {
      return { attribution: null, mode: "live", state: "error", error: "后端返回结构异常" };
    }
    /* 多 case 形态：{case_id:null, profiles:[...]}；profiles 为空 → 无数据。
     * 单 case 形态（含 attribution_status="insufficient_evidence"）一律 ok，
     * 由页面按 status 决定展示"画像"还是"证据不足"。 */
    if (Array.isArray(data.profiles)) {
      return data.profiles.length === 0
        ? { attribution: null, mode: "live", state: "empty" }
        : { attribution: data, mode: "live", state: "ok" };
    }
    return { attribution: data, mode: "live", state: "ok" };
  } catch (e) {
    return { attribution: null, mode: "live", state: "error",
             error: e.name === "AbortError" ? `连接超时（${ATTACK_CHAIN_TIMEOUT_MS / 1000}s）` : "后端未连接" };
  }
}

/**
 * 分析范围 → 后端请求体的适配。
 * A 的 AnalysisRequest 契约是 {host?, start?, end?}（都可空，空=全库）；
 * report.js 页面用的是 {scope:"all"} / {scope:"host", host} 这种带
 * scope 字段的 UI 形态。适配层放这里，页面代码不用知道后端长啥样。
 * （后端 pydantic 会忽略多余字段，所以就算不适配也能跑——但发精确
 * 契约体是白捡的稳健性：万一 A 将来开了 forbid_extra，前端零改动。）
 */
function toAnalysisPayload(scope) {
  /* 批次过滤（2026-09-10 平台化）：页眉下拉选中的 case_id 一并传给后端，
   * 报告按所选批次分析而非全库——切换批次后报告内容随之变化。 */
  const payload = {};
  const cid = resolveCaseId();
  if (cid) payload.case_id = cid;
  if (!scope || scope.scope === "all") return payload;
  if (scope.scope === "host") { payload.host = scope.host; return payload; }
  return Object.assign(payload, scope);
}

/**
 * 请求 LLM 分析报告（封箱规则：严格三态，无静默 mock）。
 *   Demo（显式）  → 固定 mock 报告（mode:"demo"，页脚标注数据来源）；
 *   Live 失败     → state:"error"（网络/HTTP/非 JSON/超时，前端 60s
 *                    上限，覆盖后端 LLM 30s 超时）；
 *   Live 空链     → state:"empty"（当前范围没检出攻击链，无法分析）；
 *   Live 正常     → state:"ok"。后端 source="fallback"（LLM 不可用
 *                    时的真实规则模板）也算正常结果——它是后端基于
 *                    当前真实攻击链/事件算出来的，不是前端假数据。
 *
 * @param {Object} scope 分析范围：{scope:"all"}（默认全部数据）或
 *                       {scope:"host", host:"web-server"}（仅某主机）
 * @returns {Promise<{report: Object|null, mode: "live"|"demo",
 *                     state: "ok"|"error"|"empty", error?: string}>}
 */
async function getAnalysisReport(scope = { scope: "all" }) {
  if (isDemoMode()) {
    /* mock 是共享常量，浅拷贝一层防止页面代码改动污染常量本身 */
    return { report: { ...MOCK_ANALYSIS_REPORT }, mode: "demo", state: "ok" };
  }

  let data;
  try {
    const resp = await fetchWithTimeout(
      `${API_BASE}/api/analysis`, ANALYSIS_TIMEOUT_MS, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(toAnalysisPayload(scope)),
      });
    if (!resp.ok) {
      return { report: null, mode: "live", state: "error", error: `后端返回 HTTP ${resp.status}` };
    }
    data = await resp.json();   // 非 JSON（网关错误页等）→ 进下方 catch
  } catch (e) {
    const msg = e.name === "AbortError"
      ? `分析超时（前端 ${ANALYSIS_TIMEOUT_MS / 1000}s 上限，LLM 仍在后端执行）`
      : "分析服务未连接";
    return { report: null, mode: "live", state: "error", error: msg };
  }

  /* malformed 响应防御：结构不对一律按 error 处理，绝不带病渲染 */
  if (!data || typeof data !== "object" || !Array.isArray(data.attack_path)) {
    return { report: null, mode: "live", state: "error", error: "后端返回了畸形分析结果" };
  }
  if (data.attack_path.length === 0) {
    return { report: { ...data }, mode: "live", state: "empty" };
  }
  return { report: { ...data }, mode: "live", state: "ok" };
}


/* ============================================================
 * getBatches() — 批次清单（2026-09-10 平台化：批次下拉/数据管理页用）
 * 返回 {batches: [{case_id, count, alert_count, sources, first_ts, last_ts}], total}
 * ============================================================ */
async function getBatches() {
  const resp = await fetchWithTimeout(`${API_BASE}/api/batches`, FETCH_TIMEOUT_MS);
  if (!resp.ok) throw new Error(`后端返回 HTTP ${resp.status}`);
  return resp.json();
}
