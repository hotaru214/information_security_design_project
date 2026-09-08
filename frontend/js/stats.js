/* ============================================================
 * stats.js — Dashboard 页（成员F）
 * ============================================================
 * 页面内容（本次任务的全部验收点）：
 *   ① 4 个统计卡片（数据全部从 mock/events.json 前端聚合）：
 *      - 分析事件总数：events.length（记录数，不管字段缺不缺）
 *      - 异常事件数：severity >= 2 或 anomaly_flags 非空（两者满足其一）
 *      - 涉及主机数：展示键（host ?? host_map[ip] ?? ip）去重
 *      - 攻击阶段数：优先按 detail.attack_stage 去重；
 *        数据里没有 detail.attack_stage 时，按"涉及的攻击行为类别数"
 *        估算（anomaly_flags 去重、剔除 MITRE T-ID——T1190 是技术编号
 *        不是行为类别名）
 *   ② 图1 event_type 分布（饼图）
 *   ③ 图2 按小时聚合堆叠柱状图：正常事件深色、异常事件红色
 *   ④ 图3 severity 0~3 分布（柱状图，四档各自契约色）
 *   ⑤ 卡片 / 图形可点击 → 跳到"攻击时间线"tab 并按对应条件过滤
 *      （跳转中枢是 App.showTimeline(filter)，见 app.js）
 *   ⑥ 主机相关统计展示 host_map 主机名，无映射显示 IP
 *      （target_host ?? target_ip 规则，见 app.js 的 displayHostKey）
 *
 * 健壮性要求（验收原话："任何字段缺失不能抛异常"）：
 *   所有字段读取一律走 safeField()（定义在 api.js，全局可用），
 *   聚合时跳过 null 字段，脏数据最多"少算一条"，绝不崩页面。
 * ============================================================ */

/* severity 中文标签与配色（契约：0 正常/1 低/2 中/3 高） */
const SEVERITY_LABELS = { 0: "正常/未标记", 1: "低", 2: "中", 3: "高" };
const SEVERITY_COLORS = { 0: "#94a3b8", 1: "#f59e0b", 2: "#ea580c", 3: "#dc2626" };

/* 图2 堆叠柱配色：正常事件深色（藏青），异常事件红色（契约要求异常用红） */
const BAR_NORMAL_COLOR = "#1e3a8a";
const BAR_ANOMALY_COLOR = "#dc2626";

/**
 * 异常事件判定（全文件统一用这一个函数，卡片和图2口径一致）：
 *   severity >= 2（中/高危） 或 anomaly_flags 非空数组。
 * 两个条件都要做防御：severity 可能是 null（契约里 severity 必填，
 * 但健壮性要求下 null 也不能炸），flags 可能不是数组。
 */
function isAnomalous(e) {
  const sev = safeField(e, "severity");
  const flags = safeField(e, "anomaly_flags");
  return (typeof sev === "number" && sev >= 2) ||
         (Array.isArray(flags) && flags.length > 0);
}

function renderStats(data) {
  /* ---- 0. 数据防御：整个 data 缺了也不崩 ---- */
  const events = Array.isArray(safeField(data, "events")) ? data.events : [];
  const hostMap = (safeField(data, "hostMap") && typeof data.hostMap === "object")
    ? data.hostMap : {};

  /* ================================================================
   * ① 统计卡片
   * ================================================================ */

  /* 卡1：分析事件总数 —— 记录条数，不做字段校验 */
  const total = events.length;

  /* 卡2：异常事件数 —— 口径见 isAnomalous() 注释 */
  const anomalous = events.filter(isAnomalous).length;

  /* 卡3：涉及主机数 + 主机 chip 列表（需求⑥）
   * 聚合键 = displayHostKey(e)：
   *   事件自身 host 字段 → 查 host_map（src_ip/dst_ip）→ 裸 IP → null 跳过
   * 这正是契约 target_host ?? target_ip 的落地。 */
  const hostStats = {};   // key -> {label, count, anomalous}
  events.forEach(e => {
    const key = App.displayHostKey(e, hostMap);
    if (!key) return;                     // 空键（host/IP 全缺失）直接跳过
    if (!hostStats[key]) hostStats[key] = { label: key, count: 0, anomalous: 0 };
    hostStats[key].count++;
    if (isAnomalous(e)) hostStats[key].anomalous++;
  });
  const hostCount = Object.keys(hostStats).length;

  /* 卡4：攻击阶段数 —— 两级策略（需求①原文）：
   *   第一级：detail.attack_stage 去重（契约里 attack_stage 是 detail 的
   *          合法键，D 关联模块产出的事件会带）；
   *   第二级（数据里没有时）：按"涉及的攻击行为类别数"估算——
   *          取全部 anomaly_flags 去重，剔除 MITRE T-ID（/^T\d/ 开头，
   *          T1190 是技术编号不是行为类别）。 */
  const stageSet = new Set();
  events.forEach(e => {
    const d = safeField(e, "detail");
    const st = (d && typeof d === "object") ? safeField(d, "attack_stage") : null;
    if (st) stageSet.add(st);             // null/非字符串自然被跳过
  });
  let stageCount;
  if (stageSet.size > 0) {
    stageCount = stageSet.size;
  } else {
    const behaviorCats = new Set();
    events.forEach(e => {
      const flags = safeField(e, "anomaly_flags");
      if (!Array.isArray(flags)) return;  // 缺字段/null 跳过
      flags.forEach(f => {
        if (typeof f === "string" && !/^T\d/i.test(f)) behaviorCats.add(f);
      });
    });
    stageCount = behaviorCats.size;
  }

  /* 渲染 4 张卡片。
   * data-filter 标记点击后的过滤动作（需求⑤）：
   *   total  → 清空全部条件后跳时间线
   *   anomaly → 勾上"仅看异常"
   *   hosts / stages → 无单一对应条件，清条件跳转（看明细） */
  document.getElementById("stat-cards").innerHTML = `
    <div class="stat-card clickable" data-filter="total" title="点击查看全部事件">
      <div class="num">${total}</div><div class="label">分析事件</div></div>
    <div class="stat-card clickable" data-filter="anomaly" title="severity≥2 或带异常规则，点击查看">
      <div class="num alert">${anomalous}</div><div class="label">异常事件</div></div>
    <div class="stat-card clickable" data-filter="hosts" title="点击查看事件明细">
      <div class="num">${hostCount}</div><div class="label">涉及主机</div></div>
    <div class="stat-card clickable" data-filter="stages" title="点击查看事件明细">
      <div class="num">${stageCount}</div><div class="label">攻击阶段</div></div>
  `;
  document.querySelectorAll("#stat-cards .stat-card").forEach(card => {
    card.addEventListener("click", () => {
      const f = card.dataset.filter;
      if (f === "anomaly") App.showTimeline({ anomalyOnly: true });
      else App.showTimeline({});          // 其余卡片：清条件看全部
    });
  });

  /* 主机 chip 行（需求⑥）：展示 host_map 主机名，带事件数和异常数，
   * 点击 → 时间线按该主机过滤。异常主机名标红。 */
  const chipsBox = document.getElementById("host-chips");
  const hostEntries = Object.entries(hostStats)
    .sort((a, b) => b[1].count - a[1].count);       // 按事件数降序
  chipsBox.innerHTML =
    `<span class="muted">涉及主机：</span>` +
    hostEntries.map(([key, s]) => `
      <span class="chip host-chip ${s.anomalous > 0 ? "host-alert" : ""}"
            data-host="${App.esc(key)}"
            title="点击查看该主机的事件（${s.anomalous} 条异常）">
        ${App.esc(s.label)} · ${s.count}
      </span>`).join("");
  chipsBox.querySelectorAll(".host-chip").forEach(chip => {
    chip.addEventListener("click", () =>
      App.showTimeline({ host: chip.dataset.host }));
  });

  /* ================================================================
   * ② 图1：event_type 分布（饼图，需求2）
   * ================================================================ */
  const typeCount = {};
  events.forEach(e => {
    const t = safeField(e, "event_type");
    if (t) typeCount[t] = (typeCount[t] || 0) + 1;   // null 跳过
  });
  const typeChart = chartOrResize("chart-type", dom => echarts.init(dom));
  typeChart.setOption({
    tooltip: {},
    legend: { type: "scroll", bottom: 0 },           // 枚举多时图例可滚动
    series: [{
      type: "pie", radius: ["30%", "62%"], center: ["50%", "44%"],
      data: Object.entries(typeCount).map(([k, v]) => ({ name: k, value: v })),
      label: { formatter: "{b}\n{c} ({d}%)" },        // {d}=百分比（ECharts 内置变量）
    }],
  });
  /* 需求⑤：点击扇区或图例 → 时间线按该 event_type 过滤。
   * 图例的坑：ECharts 图例点击的默认行为是"隐藏该扇区"，
   * 这里拦截 legendselectchanged 事件——跳转过滤之后立刻
   * dispatchAction 把图例选回来，图表不被拆坏。 */
  bindChartFilter(typeChart, "pie", name => App.showTimeline({ eventType: name }));

  /* ================================================================
   * ③ 图2：按小时聚合堆叠柱状图（需求3）
   * ================================================================
   * 小时桶 = timestamp 第 12~13 位字符（ISO8601: 2026-09-07T09:xx）。
   * timestamp 缺失/非字符串 → 整条跳过（聚合跳过 null 字段）。 */
  const hourMap = {};   // "09" -> {normal: n, anomaly: m}
  events.forEach(e => {
    const ts = safeField(e, "timestamp");
    if (typeof ts !== "string" || ts.length < 13) return;
    const hh = ts.slice(11, 13);
    if (!/^\d{2}$/.test(hh)) return;                  // 格式异常也跳过
    if (!hourMap[hh]) hourMap[hh] = { normal: 0, anomaly: 0 };
    if (isAnomalous(e)) hourMap[hh].anomaly++;
    else hourMap[hh].normal++;
  });
  const hours = Object.keys(hourMap).sort();
  const hourChart = chartOrResize("chart-hourly", dom => echarts.init(dom));
  hourChart.setOption({
    tooltip: { trigger: "axis" },
    legend: { bottom: 0 },
    grid: { left: 40, right: 16, top: 20, bottom: 44 },
    xAxis: { type: "category", data: hours.map(h => `${h}:00`) },
    yAxis: { type: "value", minInterval: 1 },
    series: [
      { name: "正常事件", type: "bar", stack: "total",
        data: hours.map(h => hourMap[h].normal),
        itemStyle: { color: BAR_NORMAL_COLOR }, barMaxWidth: 46 },
      { name: "异常事件", type: "bar", stack: "total",
        data: hours.map(h => hourMap[h].anomaly),
        itemStyle: { color: BAR_ANOMALY_COLOR }, barMaxWidth: 46,
        label: { show: true, position: "top", color: BAR_ANOMALY_COLOR } },
    ],
  });
  /* 点击某个小时的柱子 → 时间线按该小时过滤。
   * params.name 是横轴类目（"09:00"），截回两位小时数。 */
  hourChart.on("click", params => {
    if (params.name) App.showTimeline({ hour: params.name.slice(0, 2) });
  });
  /* 需求⑤"图例可点击"对本图同样生效：
   * 图例"异常事件" → 时间线仅看异常；"正常事件" → 清条件看全部
   * （时间线没有"仅正常"过滤器，映射到全部是最接近的语义，
   *   想改成别的映射改这一处即可）。
   * 同样要拦截默认的"隐藏系列"行为并立即选回（原理同饼图 bindChartFilter）。 */
  hourChart.on("legendselectchanged", params => {
    if (params.selected && params.selected[params.name] === false) {
      App.showTimeline({ anomalyOnly: params.name === "异常事件" });
      hourChart.dispatchAction({ type: "legendSelect", name: params.name });
    }
  });

  /* ================================================================
   * ④ 图3：severity 0~3 分布（需求4）
   * ================================================================
   * severity 可能缺失——契约必填，但缺了就归不到任何一档，
   * 直接跳过（不计入任何柱子），页面不报错。 */
  const sevCount = { 0: 0, 1: 0, 2: 0, 3: 0 };
  events.forEach(e => {
    const s = safeField(e, "severity");
    if (typeof s === "number" && s in sevCount) sevCount[s]++;
  });
  const sevChart = chartOrResize("chart-severity", dom => echarts.init(dom));
  sevChart.setOption({
    tooltip: {},
    grid: { left: 40, right: 16, top: 20, bottom: 24 },
    xAxis: {
      type: "category",
      data: [0, 1, 2, 3].map(k => `${k}`),            // 类目值就是档位数字
      axisLabel: { formatter: v => `${v} ${SEVERITY_LABELS[v]}` },
    },
    yAxis: { type: "value", minInterval: 1 },
    series: [{
      type: "bar", barMaxWidth: 52,
      data: [0, 1, 2, 3].map(k => ({
        value: sevCount[k],
        itemStyle: { color: SEVERITY_COLORS[k], borderRadius: [4, 4, 0, 0] },
      })),
      label: { show: true, position: "top" },
    }],
  });
  /* 点击某档柱子 → 时间线按 severity 过滤。
   * 用 params.dataIndex（0~3）而不是 name，避免字符串/数字转换坑。 */
  sevChart.on("click", params => {
    App.showTimeline({ severity: params.dataIndex });
  });
}

/**
 * 饼图"点击扇区 / 点击图例都跳转过滤"的统一绑定（需求⑤）。
 *
 * 为什么要专门写这个函数：
 *   ECharts 图例点击的默认行为是切换该扇区显示/隐藏（legendselectchanged），
 *   和我们要的"点图例跳转过滤"冲突。
 *   处理：监听 legendselectchanged——发现用户"取消选中"某个图例项时，
 *   1) 跳转时间线按该 name 过滤；2) dispatchAction 立即选回该图例项，
 *   这样图表完整保留，跳转效果也达成。扇区点击（click 事件）无冲突，
 *   直接绑。
 *
 * @param {ECharts} chart    图表实例
 * @param {string}  type     "pie"（本任务只有饼图用到图例拦截）
 * @param {Function} onPick  (name) => 跳转动作
 */
function bindChartFilter(chart, type, onPick) {
  chart.off("click");
  chart.on("click", params => { if (params.name) onPick(params.name); });
  if (type === "pie") {
    chart.off("legendselectchanged");
    chart.on("legendselectchanged", params => {
      if (params.selected && params.selected[params.name] === false) {
        onPick(params.name);
        chart.dispatchAction({ type: "legendSelect", name: params.name });
      }
    });
  }
}

/**
 * ECharts 实例复用工具（本项目的关键小函数，chain.js 也共用）。
 *
 * 解决的问题：ECharts 实例和 DOM 是绑定的。
 *   - 第一次渲染：init + setOption；
 *   - 窗口缩放 / 切 tab（容器从 display:none 变可见）后：
 *     实例内部的宽高缓存就过期了，必须 resize() 重算。
 *
 * 实现要点：
 *   getInstanceByDom(dom) 拿已有实例——重复 init 同一个 dom 会报 warning；
 *   window 上挂 "page-shown" 监听（app.js 切 tab 时派发），让图表
 *   在 tab 显示瞬间自动 resize。先 remove 旧监听再挂新的，防重复。
 */
function chartOrResize(domId, create) {
  const dom = document.getElementById(domId);
  let chart = echarts.getInstanceByDom(dom);
  if (!chart) chart = create(dom);
  else chart.resize();
  window.removeEventListener("page-shown", chart.__pageHandler || (() => {}));
  chart.__pageHandler = () => chart.resize();
  window.addEventListener("page-shown", chart.__pageHandler);
  return chart;
}
