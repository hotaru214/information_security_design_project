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
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, ms = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { signal: controller.signal });
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

/**
 * 字段名归一化：event_id → source_event_id（数据边界兼容层）。
 *
 * 背景（2026-09-08 对齐 A 后端时发现）：
 *   A 的 EventOut pydantic 模型里字段名叫 event_id（输入端用
 *   AliasChoices 兼容 source_event_id，但输出序列化是 event_id），
 *   而全组契约规定的名字是 source_event_id。
 *   归一化放在 api.js（数据边界）而不是让每个页面模块各自兼容——
 *   下游代码永远只认契约名；A 哪天把输出改成 source_event_id，
 *   本函数自动变成空操作，前端其他地方零改动。
 *
 * 处理规则（保持事件恰好 19+1 个键，不留脏字段）：
 *   - 只有 event_id           → 改名为 source_event_id；
 *   - 两个都有                → 契约名 source_event_id 优先，删 event_id；
 *   - 两个都没有              → 补 null（契约：网络事件无原始编号时为 null）。
 */
function normalizeSourceEventId(events) {
  events.forEach(e => {
    if (e && typeof e === "object") {
      const oldVal = safeField(e, "event_id");
      const newVal = safeField(e, "source_event_id");
      e.source_event_id = newVal !== null ? newVal : oldVal;
      delete e.event_id;
    }
  });
  return events;
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
        // 先过字段名归一化（A 的输出用 event_id，契约叫 source_event_id）
        return { events: normalizeSourceEventId(data), mode: "live" };
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
  return { events: withSimulatedIds(events), mode: "demo" };
}

/**
 * 加载攻击链（攻击链页 / 分析报告页共用）。
 *
 * 和 loadEvents 的区别：
 *   攻击链接口 /api/attack-chain 是 D 模块的产出，后端"可能还没实现"，
 *   所以除了判HTTP状态，还要校验结构——**只要有 links 就算可用**：
 *   nodes 缺失时 normalizeChain() 能从 links 自动推导，页面照样出图
 *   （接口存在但返回空链时才回退 mock）。
 *
 * @returns {Promise<{chain: {nodes: Array, links: Array}, mode: "live"|"demo"}>}
 */
async function loadChain() {
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
 *   1. 后端 GET /api/hosts（{ip:hostname} 或 [{ip,hostname}] 两种形态都兼容）；
 *   2. 回退 mock/host_map.json（out/build_mock.py 从 data/hosts.csv 生成）；
 *   3. 连 mock 都没有 → 返回 {}，展示层自然回退显示 IP，页面不报错。
 *
 * @returns {Promise<Object>} 归一化的 { "10.0.0.5": "web-server", ... }
 */
async function loadHostMap() {
  let raw = null;
  try {
    const resp = await fetchWithTimeout(`${API_BASE}/api/hosts`);
    if (resp.ok) raw = await resp.json();
  } catch (e) {
    /* 后端未连接，走 mock */
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
