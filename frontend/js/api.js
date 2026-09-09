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

/* 后端地址集中成一个常量。
 * 注意：不要写成 "localhost"——如果页面将来部署到别的机器，
 * localhost 会指向用户自己的电脑而不是后端。 */
const API_BASE = "http://127.0.0.1:8000";

/* 超时 2 秒：后端没启动时，浏览器 fetch 默认会等很久（几十秒的
 * TCP 超时），页面会白屏转圈。必须主动掐断，快速回退 mock。 */
const FETCH_TIMEOUT_MS = 2000;

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
    return await fetch(url, { signal: controller.signal, ...options });
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
 * 四条处理规则（联调任务书 3a-3d）+ 一条时间规则（任务书 4）：
 *   a) 接口字段 event_id → source_event_id（改名，语义=原始日志编号）；
 *   b) detail / anomaly_flags 缺失 → 补 {} / []（契约必填，缺了页
 *      面组件会炸）；
 *   c) event_type 不在冻结枚举 → console.warn 并原样保留（不私造
 *      也不丢弃——擅自改值会破坏过滤器和统计口径）；
 *   d) id 缺失 → 用数组下标模拟并 console.warn（live 数据缺 id 属
 *      于 A 侧事故，必须留痕；mock 缺 id 是设计内行为，不警告）；
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

  /* d) id 缺失 → 下标模拟；live 模式下必须留痕（这是 A 侧事故信号） */
  if (e.id === undefined || e.id === null) {
    e.id = idx + 1;
    if (liveMode) {
      console.warn("[api.js] live 事件缺失数据库 id，已用数组下标模拟（index=%d）——请反馈 A", idx);
    }
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
 * 回退判定不只是"请求失败"：
 *   - 没启动后端 → fetch 直接 reject（连接被拒）→ 进 catch；
 *   - 后端启动了但库里没数据 → resp.ok 但 data.length === 0
 *     → 空数组渲染不出任何东西，也视为不可用，回退 mock。
 *
 * @returns {Promise<{events: Array, mode: "live"|"demo"}>}
 *          mode 交给 app.js 控制演示模式徽章
 */
async function loadEvents() {
  try {
    const resp = await fetchWithTimeout(`${API_BASE}/api/events`);
    if (resp.ok) {
      const data = await resp.json();
      // Array.isArray 防御：万一后端返回了 {error: ...} 之类的对象
      if (Array.isArray(data) && data.length > 0) {
        // live 数据走完整归一化（缺 id 警告 / 坏时间戳跳过）
        return { events: normalizeEvents(data, true), mode: "live" };
      }
    }
  } catch (e) {
    /* 后端未连接——这里故意不弹错误提示，
     * 因为回退 mock 之后页面照常能看，只是顶部出徽章。 */
  }
  /* 注意路径是相对路径 "mock/events.json"：
   * 我们用 python -m http.server 直接跑 frontend/ 目录，
   * 相对路径跟部署位置无关，绝对路径反而容易写错。 */
  const resp = await fetch("mock/events.json");
  const events = await resp.json();
  /* mock：先按下标补 id（设计内行为，静默），再走同一套归一化 */
  return { events: normalizeEvents(withSimulatedIds(events), false), mode: "demo" };
}

/**
 * getAttackChain() — 加载攻击链（攻击链页 / 分析报告页共用）。
 *
 * 数据层封装约定（2026-09-09）：攻击链的获取统一走这一个函数，
 * 页面模块只管调用、不关心数据从哪来。后续切换到真实后端时
 * 只改这里一行即可（现状已经是 GET /api/attack-chain + mock 回退）：
 *   const resp = await fetchWithTimeout(`${API_BASE}/api/attack-chain`);
 *
 * 和 loadEvents 的区别：
 *   攻击链接口 /api/attack-chain 是 D 模块的产出（A 的 adapter 已在
 *   main 分支实现），除了判 HTTP 状态还要校验结构——**只要有 links
 *   就算可用**：nodes 缺失时 normalizeChain() 能从 links 自动推导，
 *   页面照样出图（接口存在但返回空链时才回退 mock）。
 *
 * @returns {Promise<{chain: {nodes: Array, links: Array}, mode: "live"|"demo"}>}
 */
async function getAttackChain() {
  try {
    const resp = await fetchWithTimeout(`${API_BASE}/api/attack-chain`);
    if (resp.ok) {
      const data = await resp.json();
      if (data && Array.isArray(data.links) && data.links.length > 0) {
        return { chain: normalizeChain(data), mode: "live" };
      }
    }
  } catch (e) {
    /* 回退 mock */
  }
  const resp = await fetch("mock/chain.json");
  return { chain: normalizeChain(await resp.json()), mode: "demo" };
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
  let raw = null;
  /* 主选 /api/hosts/map（精确的 {ip:hostname} 字典）；
   * 失败再试 /api/hosts（完整主机表）；都失败才走 mock。 */
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
    try {
      raw = await (await fetch("mock/host_map.json")).json();
    } catch (e) {
      return {};
    }
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

/**
 * 分析范围 → 后端请求体的适配。
 * A 的 AnalysisRequest 契约是 {host?, start?, end?}（都可空，空=全库）；
 * report.js 页面用的是 {scope:"all"} / {scope:"host", host} 这种带
 * scope 字段的 UI 形态。适配层放这里，页面代码不用知道后端长啥样。
 * （后端 pydantic 会忽略多余字段，所以就算不适配也能跑——但发精确
 * 契约体是白捡的稳健性：万一 A 将来开了 forbid_extra，前端零改动。）
 */
function toAnalysisPayload(scope) {
  if (!scope || scope.scope === "all") return {};
  if (scope.scope === "host") return { host: scope.host };
  return scope;   // 已经是 {host,start,end} 形态的直接透传
}

/**
 * 请求 LLM 分析报告。
 * 结构校验只卡最核心的 attack_path（数组非空）——其余字段缺失时
 * report.js 渲染层会用 safeField 兜底成"该区不渲染"，不会崩页。
 *
 * @param {Object} scope 分析范围：{scope:"all"}（默认全部数据）或
 *                       {scope:"host", host:"web-server"}（仅某主机）
 * @returns {Promise<{report: Object, mode: "live"|"demo"}>}
 */
async function getAnalysisReport(scope = { scope: "all" }) {
  try {
    const resp = await fetchWithTimeout(`${API_BASE}/api/analysis`, FETCH_TIMEOUT_MS, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(toAnalysisPayload(scope)),
    });
    if (resp.ok) {
      const data = await resp.json();
      if (data && Array.isArray(data.attack_path) && data.attack_path.length > 0) {
        return { report: data, mode: "live" };
      }
    }
  } catch (e) {
    /* 后端未连接 / 超时 —— 回退 mock，由 report.js 在页面上标注演示模式 */
  }
  /* mock 是共享常量，浅拷贝一层防止页面代码改动污染常量本身 */
  return { report: { ...MOCK_ANALYSIS_REPORT }, mode: "demo" };
}
