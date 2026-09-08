/* ============================================================
 * timeline.js — 攻击时间线页（成员F）
 * ============================================================
 * 页面内容：
 *   - 全部事件按时间先后排成竖直时间线；
 *   - 每条事件：时间 / 主机 / 类型徽章 / 来源徽章 / severity /
 *     异常规则名（红） / 中文描述；点击弹出详情（含 raw_log 证据）。
 *
 * 过滤器（本次扩展，承接 Dashboard 的点击跳转）：
 *   仅看异常 checkbox + event_type / source / severity / 小时 / 主机
 *   五个下拉框，条件之间是 AND 组合。
 *   Dashboard 的卡片/图形通过 App.showTimeline(filter) 跳转过来时，
 *   调 applyFilter(filter) 把条件落到这些控件上再重画——
 *   用户能"看见"当前过滤条件（而不是隐形状态），也能随手改掉。
 *
 * 实现模式（无框架的最简状态管理）：
 *   过滤条件全部存在 DOM 里（checkbox.checked / select.value），
 *   任何变化触发 draw() 整体重渲染。数据 50 条，性能完全够。
 * ============================================================ */

function renderTimeline(data) {
  const { events, hostMap } = data;

  /* ---------- 下拉框选项（全部从数据动态生成） ---------- */
  const typeSel = document.getElementById("filter-type");
  const srcSel = document.getElementById("filter-source");
  const sevSel = document.getElementById("filter-severity");
  const hourSel = document.getElementById("filter-hour");
  const hostSel = document.getElementById("filter-host");
  const checkbox = document.getElementById("filter-anomaly");
  const countEl = document.getElementById("timeline-count");
  const container = document.getElementById("timeline");

  fillSelect(typeSel, sortedValues(events, "event_type"));
  fillSelect(srcSel, sortedValues(events, "source"));
  // severity 是数字档位：0~3 固定四档，不需要从数据生成
  fillSelect(sevSel, ["0", "1", "2", "3"].map(String));
  // 小时桶：timestamp 第 12~13 位（ISO8601 T 后面就是 HH）
  const hours = [...new Set(events.map(e => {
    const ts = safeField(e, "timestamp");
    return (typeof ts === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}/.test(ts))
      ? ts.slice(11, 13) : null;
  }).filter(Boolean))].sort();
  fillSelect(hourSel, hours);
  // 主机：用展示键（host ?? host_map[ip] ?? ip，与 Dashboard 主机 chip 同口径）
  const hostKeys = [...new Set(events.map(e => App.displayHostKey(e, hostMap)).filter(Boolean))].sort();
  fillSelect(hostSel, hostKeys);

  /* ---------- 主绘制函数 ---------- */
  function draw() {
    // 时间升序：ISO8601 字符串顺序 == 时间顺序（契约保证格式统一）
    let list = [...events].sort((a, b) =>
      String(safeField(a, "timestamp") || "").localeCompare(
        String(safeField(b, "timestamp") || "")));

    // 过滤①：仅看异常（severity≥2 或 flags 非空，与 Dashboard 卡片同口径）
    if (checkbox.checked) list = list.filter(e => isAnomalousTimeline(e));
    // 过滤②③：event_type / source（空字符串 = 全部）
    if (typeSel.value) list = list.filter(e => safeField(e, "event_type") === typeSel.value);
    if (srcSel.value) list = list.filter(e => safeField(e, "source") === srcSel.value);
    // 过滤④：severity（注意比较用 Number——select.value 永远是字符串）
    if (sevSel.value !== "") list = list.filter(e => safeField(e, "severity") === Number(sevSel.value));
    // 过滤⑤：小时（timestamp 缺失的事件在任何小时筛选下都不显示）
    if (hourSel.value) list = list.filter(e => {
      const ts = safeField(e, "timestamp");
      return typeof ts === "string" && ts.slice(11, 13) === hourSel.value;
    });
    // 过滤⑥：主机（用展示键，host 缺失但 IP 能映射的也能被筛到）
    if (hostSel.value) list = list.filter(e => App.displayHostKey(e, hostMap) === hostSel.value);

    countEl.textContent = `共 ${list.length} 条`;
    container.innerHTML = list.map(e => {
      const sev = App.SEVERITY[e.severity] || App.SEVERITY[0];
      const anomalous = isAnomalousTimeline(e);
      const hostLabel = App.displayHostKey(e, hostMap) ?? "-";
      return `
        <div class="tl-item ${sev.cls} ${anomalous ? "anomalous" : ""}" data-id="${e.id}">
          <div class="tl-head">
            <span class="tl-time">${App.esc(App.fmtTime(e.timestamp))}</span>
            <span class="tl-host">${App.esc(hostLabel)}</span>
            <span class="chip">${App.esc(e.event_type ?? "?")}</span>
            <span class="chip src">${App.esc(App.SOURCE_LABEL[e.source] || e.source || "?")}</span>
            <span class="chip">sev-${e.severity ?? "-"} ${sev.label}</span>
            ${App.flagBadges(e.anomaly_flags)}
          </div>
          <div class="tl-desc">${App.esc(e.description ?? "")}</div>
        </div>`;
    }).join("");

    // innerHTML 替换子节点后旧监听器全部失效，必须重新绑
    container.querySelectorAll(".tl-item").forEach(item => {
      item.addEventListener("click", () => App.openEventDetail(item.dataset.id));
    });
  }

  /* ---------- 过滤条件落点：Dashboard 跳转的入口 ----------
   * App.showTimeline(filter) 最终会调用这里（通过 App._applyTimelineFilter）。
   * 语义：每次跳转 = "恰好 filter 里那组条件"——先全部清空再应用，
   * 避免上一次跳转的条件残留（比如先点了饼图再点小时柱，
   * 不清空的话两个条件叠加，计数会让人困惑）。
   * 用户在时间线手动调过的条件会被覆盖，这是预期行为。 */
  function applyFilter(filter = {}) {
    checkbox.checked = filter.anomalyOnly === true;
    setSelect(typeSel, filter.eventType);
    setSelect(srcSel, filter.source);
    setSelect(sevSel, filter.severity === undefined ? undefined : String(filter.severity));
    setSelect(hourSel, filter.hour);
    setSelect(hostSel, filter.host);
    draw();
  }
  // 注册到 App：app.js 的 showTimeline 调它（app.js 先于本函数执行加载，
  // 但注册发生在 init 渲染时，时序安全）
  App._applyTimelineFilter = applyFilter;

  /* 控件变化 → 重画 */
  checkbox.addEventListener("change", draw);
  [typeSel, srcSel, sevSel, hourSel, hostSel].forEach(sel =>
    sel.addEventListener("change", draw));
  draw(); // 首次渲染
}

/**
 * 时间线专用的异常判定。
 * 说明：stats.js 里已有 isAnomalous()，但脚本加载顺序上 stats.js 在前、
 * 且"异常"口径属于业务规则而不是某页私有——为保证两页永远同口径，
 * 这里独立实现同一规则（severity≥2 或 flags 非空），并都做了空值防御。
 */
function isAnomalousTimeline(e) {
  const sev = safeField(e, "severity");
  const flags = safeField(e, "anomaly_flags");
  return (typeof sev === "number" && sev >= 2) ||
         (Array.isArray(flags) && flags.length > 0);
}

/** 取某字段的非空去重排序值（下拉框选项用） */
function sortedValues(events, key) {
  return [...new Set(events.map(e => safeField(e, key)).filter(Boolean))].sort();
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
 * value 为 undefined → 重置为"全部"（''）——配合"先清空再应用"的语义；
 * 给了值但选项里没有（比如要过滤的小时数据里不存在）→ 也回退"全部"。
 */
function setSelect(sel, value) {
  if (value === undefined || value === null) { sel.value = ""; return; }
  sel.value = String(value);
  if (sel.value !== String(value)) sel.value = "";   // 无此选项，回退全部
}
