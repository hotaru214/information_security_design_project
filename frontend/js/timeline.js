/* ============================================================
 * timeline.js — 攻击时间线页（成员F）
 * ============================================================
 * 页面定位（本次需求原文）："证据展示"——raw_log、cmdline、detail
 * 就是答辩时给老师看的证据。所以本页的核心交互是：
 *   时间轴概览（一屏看清攻击节奏） → 点击展开证据面板（三区详情）。
 *
 * 页面内容：
 *   ① 纵向时间轴（纯 CSS：左侧轴线 ::before + 节点圆点 ::before），
 *      事件按 timestamp 升序（ISO8601 字符串顺序 == 时间顺序，契约保证）。
 *   ② 每条节点：时间 / host / event_type / description（+severity 档位）。
 *   ③ severity≥2 的事件：红色节点圆点 + 红色边框卡片；
 *      anomaly_flags 渲染成红色中文标签（映射表 App.FLAG_LABELS，
 *      未知规则名回退显示英文原名，title 里始终保留原始规则名）。
 *   ④ 过滤器：host / event_type（冻结枚举分组下拉）/ 只看异常 /
 *      时间范围（起止 datetime-local）/ severity（Dashboard 图3跳转用），
 *      条件之间 AND 组合。
 *   ⑤ 点击事件展开内嵌详情面板（三区）：
 *      a. 关键字段表——null 字段直接不渲染整行（契约：禁 "null" 字样）；
 *      b. detail 对象——遍历全部键值对，已知键配中文标签（App.DETAIL_LABEL，
 *         与攻击链侧栏共用同一详情组件，见 app.js），
 *         未知键原样展示（detail 是开放对象，不能漏掉任何独有字段）；
 *      c. raw_log——等宽字体深色代码块原样展示，配"溯源证据"说明样式。
 *   ⑥ 面板带"复制 JSON"按钮（完整事件对象，答辩可粘贴到别处核对）；
 *      支持 URL 参数 ?id=<数据库id> 直接定位并展开某条事件
 *      （供其他 tab / 外部链接跳转，如 index.html?id=17）。
 *
 * 实现模式（无框架的最简状态管理）：
 *   - 过滤条件存在 DOM 里（checkbox.checked / select.value / input.value），
 *     任何变化触发 draw() 整体重渲染。数据 50 条量级，性能完全够。
 *   - 展开状态只有一个变量 expandedId（同一时刻至多展开一条，
 *     避免页面被撑得过长，也更符合"逐条讲证据"的答辩节奏）。
 *   - 事件委托：container 上绑一次 click，子节点 innerHTML 怎么换
 *     监听器都不丢（比每次重绘后逐项 addEventListener 稳）。
 *
 * 与其他模块的联动（改动前必读）：
 *   - Dashboard 各卡片/图形通过 App.showTimeline(filter) 跳转，
 *     最终落到本文件的 applyFilter(filter)（注册在 App._applyTimelineFilter）。
 *     语义：每次跳转 = "恰好 filter 里那组条件"，先全部清空再应用，
 *     防止上一次的条件残留导致计数对不上。
 *     特例：filter.hour（Dashboard 小时柱）本页已没有小时下拉，
 *     折算成"该小时 00:00~59:59"的时间范围落到两个时间输入框上。
 *   - 攻击链页的证据 chip 仍走 App.openEventDetail 弹窗（chain.js），
 *     本页的内嵌面板与弹窗共用 app.js 的工具函数，口径一致。
 * ============================================================ */

/* ---------- 冻结枚举：event_type 7 类分组（契约冻结，不得自造） ---------- */
const EVENT_TYPE_GROUPS = [
  ["登录与会话", ["login_success", "login_failed", "logout"]],
  ["进程行为", ["process_start", "process_end"]],
  ["网络行为", ["network_connection", "dns_query", "http_request"]],
  ["文件行为", ["file_create", "file_read", "file_write", "file_modify", "file_delete"]],
  ["注册表行为", ["registry_set", "registry_create", "registry_delete", "registry_query"]],
  ["账户与权限", ["user_created", "user_deleted", "user_modified",
                  "group_member_added", "group_member_removed", "privilege_change"]],
  ["服务与计划任务", ["service_created", "service_started", "service_stopped",
                      "service_deleted", "scheduled_task_created",
                      "scheduled_task_run", "scheduled_task_deleted"]],
];

/* ---------- detail 中文标签 / logon_type 档位说明 ----------
 * 已上移至 app.js（App.DETAIL_LABEL / App.LOGON_TYPE_LABEL）——
 * 详情组件被时间线内嵌面板和攻击链侧栏共用，契约常量统一放 app.js。 */

function renderTimeline(data) {
  const { events, hostMap } = data;

  /* ---------- 控件引用 ---------- */
  const typeSel = document.getElementById("filter-type");
  const sevSel = document.getElementById("filter-severity");
  const hostSel = document.getElementById("filter-host");
  const checkbox = document.getElementById("filter-anomaly");
  const startInput = document.getElementById("filter-start");
  const endInput = document.getElementById("filter-end");
  const clearBtn = document.getElementById("filter-clear");
  const countEl = document.getElementById("timeline-count");
  const container = document.getElementById("timeline");

  /* id → 事件对象 查找表（复制 JSON / URL 定位都用 O(1) 查它） */
  const eventsById = new Map(events.map(e => [Number(safeField(e, "id")), e]));

  /* 当前展开详情的事件 id（null = 全部收起） */
  let expandedId = null;

  /* ---------- 下拉框选项（全部从数据动态生成） ---------- */
  fillTypeSelect(typeSel, events);          // 冻结枚举分组下拉（见下方函数）
  fillSelect(sevSel, ["0", "1", "2", "3"]); // severity 固定四档
  // 主机：展示键口径（host ?? host_map[ip] ?? ip），与 Dashboard 主机 chip 一致
  fillSelect(hostSel, [...new Set(
    events.map(e => App.displayHostKey(e, hostMap)).filter(Boolean)
  )].sort());

  /* ================================================================
   * 主绘制函数：读控件 → 过滤 → 排序 → 渲染时间轴
   * ================================================================ */
  function draw() {
    // 时间升序：ISO8601 字符串比较 == 时间先后（契约保证统一格式）
    let list = [...events].sort((a, b) =>
      String(safeField(a, "timestamp") || "").localeCompare(
        String(safeField(b, "timestamp") || "")));

    // 过滤①：仅看异常（severity≥2 或 flags 非空，与 Dashboard 卡片同口径）
    if (checkbox.checked) list = list.filter(isAnomalousTimeline);
    // 过滤②：event_type
    if (typeSel.value) list = list.filter(e => safeField(e, "event_type") === typeSel.value);
    // 过滤③：severity（select.value 是字符串，必须转数字再比）
    if (sevSel.value !== "") list = list.filter(e => safeField(e, "severity") === Number(sevSel.value));
    // 过滤④：主机（展示键口径，host 缺失但 IP 能映射的也能被筛到）
    if (hostSel.value) list = list.filter(e => App.displayHostKey(e, hostMap) === hostSel.value);
    // 过滤⑤：时间范围（闭区间，分钟精度）。
    // datetime-local 的值形如 "2026-09-07T09:02"，取事件 timestamp 的
    // 前 16 位同格式做字符串比较（同格式 ISO 字符串可直接比大小）。
    const startVal = startInput.value;   // 空串 = 不限起点
    const endVal = endInput.value;       // 空串 = 不限终点
    if (startVal || endVal) {
      list = list.filter(e => {
        const ts = safeField(e, "timestamp");
        if (typeof ts !== "string" || ts.length < 16) return false; // 无时间不落在任何区间
        const minute = ts.slice(0, 16);
        if (startVal && minute < startVal) return false;
        if (endVal && minute > endVal) return false;
        return true;
      });
    }

    countEl.textContent = `共 ${list.length} 条`;
    container.innerHTML = list.map(e => {
      const sev = App.SEVERITY[e.severity] || App.SEVERITY[0];
      const high = typeof e.severity === "number" && e.severity >= 2; // 需求③：红色卡片
      const hostLabel = App.displayHostKey(e, hostMap) ?? "-";
      return `
        <div class="tl-item ${sev.cls} ${high ? "high" : ""}" data-id="${e.id}">
          <div class="tl-head">
            <span class="tl-time">${App.esc(App.fmtTime(e.timestamp))}</span>
            <span class="tl-host">${App.esc(hostLabel)}</span>
            <span class="chip">${App.esc(e.event_type ?? "?")}</span>
            <span class="chip">sev-${e.severity ?? "-"} ${sev.label}</span>
            ${App.flagBadges(e.anomaly_flags)}
          </div>
          <div class="tl-desc">${App.esc(e.description ?? "")}</div>
        </div>`;
    }).join("");

    // 重绘后恢复展开态（重绘前展开的那条如果还在列表里，面板跟着回来）
    if (expandedId !== null) {
      const item = container.querySelector(`.tl-item[data-id="${expandedId}"]`);
      if (item) injectPanel(item, expandedId);
      else expandedId = null;   // 被过滤掉了，收起
    }
  }

  /* ================================================================
   * 详情面板（需求⑤：三区 + 复制按钮）
   * 面板 HTML 由共享详情组件 App.buildEventDetailHTML 生成（app.js），
   * 攻击链侧栏的事件详情复用同一份；复制由 document 级 .btn-copy
   * 委托统一处理，本文件不再自带面板组装与复制实现。
   * ================================================================ */

  /**
   * 在时间轴卡片内注入详情面板。
   * 用 insertAdjacentHTML 而不是整体重绘：不破坏卡片本身的 DOM，
   * 滚动条位置不跳，点击切换的手感更好。
   */
  function injectPanel(item, id) {
    const e = eventsById.get(id);
    if (!e) return;
    item.classList.add("open");
    item.insertAdjacentHTML("beforeend", App.buildEventDetailHTML(e));
    // 面板可能很高，展开后把面板顶部滚进视口，保证"点哪看哪"
    const panel = item.querySelector(".tl-detail");
    if (panel) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  /** 收起：去掉面板 + open 标记 */
  function collapsePanel(item) {
    item.classList.remove("open");
    const panel = item.querySelector(".tl-detail");
    if (panel) panel.remove();
  }

  /* ================================================================
   * 事件委托：点击卡片 → 展开/收起
   * （"复制 JSON"由 app.js 的 document 级 .btn-copy 委托统一处理；
   *   .btn-copy 在 .tl-detail 内部，下面的早退判断天然放行该事件。）
   * ================================================================ */
  container.addEventListener("click", ev => {
    // 面板内部的点击（拖选 raw_log 文字、点表格行、点复制按钮等）
    // 不参与"收起"——用户看证据时经常要手动选中文本复制，
    // 误触收起非常恼火。只有点击卡片自身区域（头部/描述）才切换。
    if (ev.target.closest(".tl-detail")) return;
    const item = ev.target.closest(".tl-item");
    if (!item) return;
    const id = Number(item.dataset.id);
    if (expandedId === id) {
      expandedId = null;                 // 二次点击 = 收起
      collapsePanel(item);
    } else {
      expandedId = id;                   // 换一条展开：先收旧再开新
      container.querySelectorAll(".tl-detail").forEach(p => p.remove());
      container.querySelectorAll(".tl-item.open").forEach(i => i.classList.remove("open"));
      injectPanel(item, id);
    }
  });

  /* ================================================================
   * 过滤条件落点：Dashboard / 其他模块跳转的入口
   * ================================================================ */
  function applyFilter(filter = {}) {
    // "先清空再应用"：每次跳转 = 恰好 filter 那组条件，无残留
    checkbox.checked = filter.anomalyOnly === true;
    setSelect(typeSel, filter.eventType);
    setSelect(sevSel, filter.severity === undefined ? undefined : String(filter.severity));
    setSelect(hostSel, filter.host);

    // 时间范围：本页已去掉小时下拉，Dashboard 的小时跳转（filter.hour）
    // 折算成该小时的闭区间。日期部分从数据里任取一条该小时的事件反推
    // ——mock/live 的事件都在同一攻击窗口内，这个反推是稳定的。
    if (typeof filter.hour === "string" && filter.hour) {
      const sample = events.find(e => {
        const ts = safeField(e, "timestamp");
        return typeof ts === "string" && ts.slice(11, 13) === filter.hour;
      });
      if (sample) {
        const date = sample.timestamp.slice(0, 10);
        startInput.value = `${date}T${filter.hour}:00`;
        endInput.value = `${date}T${filter.hour}:59`;
      } else {
        // 该小时在数据中不存在（防御：正常跳转不会走到这）→ 清空区间，
        // 避免残留上一次跳转的时间条件造成"过滤结果对不上"的困惑
        startInput.value = "";
        endInput.value = "";
      }
    } else if (filter.start !== undefined || filter.end !== undefined) {
      // 直接给区间（未来其他模块跳转用）
      startInput.value = typeof filter.start === "string" ? filter.start : "";
      endInput.value = typeof filter.end === "string" ? filter.end : "";
    } else {
      startInput.value = "";
      endInput.value = "";
    }
    draw();
  }
  // 注册到 App：app.js 的 showTimeline 调它
  App._applyTimelineFilter = applyFilter;
  // 跨页定位入口：分析报告页关键证据表点行 → 时间线展开对应事件详情
  App._locateTimelineEvent = locateEvent;

  /**
   * 跨页定位事件（需求⑥的通用化）：index.html?id=<数据库id> 与
   * 其他 tab 的跳转（如分析报告页关键证据表点行）共用这一个实现：
   * 切到时间线 tab → 重置过滤并展开该事件 → 滚到视野中央 + 高亮描边
   * （3 秒后自动淡出，不干扰后续浏览）。
   * @param {number} id 数据库 events.id
   * @returns {boolean} 是否定位成功（id 不在当前数据范围返回 false）
   */
  function locateEvent(id) {
    if (!eventsById.has(id)) return false;     // 无此 id，静默返回
    App.showTimeline({});                       // 切 tab 并恢复默认视图
    expandedId = id;
    draw();
    const el = container.querySelector(`.tl-item[data-id="${id}"]`);
    if (el) {
      el.classList.add("located");
      setTimeout(() => el.scrollIntoView({ behavior: "smooth", block: "center" }), 150);
      setTimeout(() => el.classList.remove("located"), 3000);
    }
    return true;
  }

  function locateFromURL() {
    const params = new URLSearchParams(location.search);
    const id = Number(params.get("id"));
    if (id) locateEvent(id);
  }

  /* ---------- 控件变化 → 重画 ---------- */
  checkbox.addEventListener("change", draw);
  [typeSel, sevSel, hostSel].forEach(sel => sel.addEventListener("change", draw));
  [startInput, endInput].forEach(inp => inp.addEventListener("change", draw));
  // 清空按钮：一键回到"全部事件"（比逐个控件手动还原省事，演示时常用）
  clearBtn.addEventListener("click", () => applyFilter({}));

  draw();            // 首次渲染
  locateFromURL();   // URL 带了 id 就直接跳到那条证据上
}

/**
 * 时间线专用的异常判定。
 * 说明：stats.js 里已有 isAnomalous()，但"异常"口径属于业务规则而不是
 * 某页私有——两处保持同一规则（severity≥2 或 flags 非空），都做空值防御。
 */
function isAnomalousTimeline(e) {
  const sev = safeField(e, "severity");
  const flags = safeField(e, "anomaly_flags");
  return (typeof sev === "number" && sev >= 2) ||
         (Array.isArray(flags) && flags.length > 0);
}

/**
 * event_type 下拉：按冻结枚举 7 类分组（optgroup）。
 * 只列出数据里实际出现过的值（30 值全列会大而空，演示时不好点）；
 * 数据里出现、但不在冻结枚举里的值（如 D 确认过的 log_cleared）
 * 归入"其他（不在冻结枚举）"分组——既不漏数据，也让契约偏差显式可见，
 * 答辩被问到枚举外值时这就是现成的解释入口。
 */
function fillTypeSelect(sel, events) {
  const present = new Set(
    events.map(e => safeField(e, "event_type")).filter(Boolean));
  const current = sel.value;
  sel.querySelectorAll("option:not(:first-child)").forEach(o => o.remove());

  const remaining = new Set(present);   // 分组后剩下的 = 枚举外值
  EVENT_TYPE_GROUPS.forEach(([group, values]) => {
    const inData = values.filter(v => present.has(v));
    if (inData.length === 0) return;    // 该类在数据中没出现，整组不渲染
    const og = document.createElement("optgroup");
    og.label = group;
    inData.forEach(v => {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = v;
      og.appendChild(opt);
      remaining.delete(v);
    });
    sel.appendChild(og);
  });
  if (remaining.size > 0) {
    const og = document.createElement("optgroup");
    og.label = "其他（不在冻结枚举）";
    [...remaining].sort().forEach(v => {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = v;
      og.appendChild(opt);
    });
    sel.appendChild(og);
  }
  sel.value = current;
}

/**
 * 填充 <select> 选项。
 * 细节：只删第 2 个起的 option（第 1 个是"全部 xx"占位）；
 * 先记 current 再恢复——重复渲染不会清掉用户已选的条件。
 */
function fillSelect(sel, values) {
  const current = sel.value;
  sel.querySelectorAll("option:not(:first-child)").forEach(o => o.remove());
  values.forEach(v => {
    const opt = document.createElement("option");
    opt.value = v;
    opt.textContent = v;
    sel.appendChild(opt);
  });
  sel.value = current;
}

/**
 * 程序化设置 select 值（applyFilter 专用，与 fillSelect 配对）。
 * value 为 undefined/null → 重置为"全部"（''）——配合"先清空再应用"语义；
 * 给了值但选项里没有 → 也回退"全部"。
 */
function setSelect(sel, value) {
  if (value === undefined || value === null) { sel.value = ""; return; }
  sel.value = String(value);
  if (sel.value !== String(value)) sel.value = "";   // 无此选项，回退全部
}
