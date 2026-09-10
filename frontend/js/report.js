/* ============================================================
 * report.js — 分析报告页（成员F）
 * ============================================================
 * 页面定位（本次需求）：
 *   上半部分：分析范围选择（默认"全部数据"）+ "开始分析"按钮；
 *   点击 → POST /api/analysis（数据层 getAnalysisReport，api.js）
 *   下半部分：把后端返回的结构化 JSON 渲染成报告卡片：
 *     一、攻击路径 —— 横向小流程图（节点色/箭头色复用攻击阶段配色）；
 *     二、攻击概述 —— summary 文字段；
 *     三、关键证据 —— 表格，event_id=数据库 id，点击行跳时间线详情；
 *     四、ATT&CK 映射 —— 阶段 → 技术编号标签组（附技术名称），
 *         evidence_event_ids 为数据库 id，点击 chip 弹事件详情；
 *     五、风险等级徽章 + 处置建议列表。
 *   报告区提供"复制为 Markdown"与"导出报告"（.md 下载）。
 *
 * 架构红线（需求原文）："LLM 调用属于后端，前端只消费结构化结果，
 * 禁止在前端直接调 LLM API。"
 *   本文件不做任何 LLM 请求，只渲染 getAnalysisReport 返回的结构。
 *   接真实 LLM 时：后端在 /api/analysis 里调 LLM 并解析成同一结构，
 *   前端零改动。演示模式（后端未连接）回退 api.js 内置的固定 mock JSON，
 *   页面顶部徽章说明数据来源，保证断网可答辩。
 *
 * id 口径（契约）：key_evidences[].event_id 与
 *   mitre_mapping[].evidence_event_ids 都是数据库 events.id（整数）；
 *   mock 阶段 = mock 事件数组的下标+1，与时间线/攻击链的 id 完全一致，
 *   因此点击证据能精确跳到对应事件。
 * ============================================================ */

/* ATT&CK 技术编号 → 名称（需求给定 10 项）。
 * 只用于展示；链上出现表外编号时回退显示编号本身，不丢信息。 */
const MITRE_TECHNIQUE_NAMES = {
  "T1190": "Exploit Public-Facing Application",
  "T1059": "Command and Scripting Interpreter",
  "T1547.001": "Registry Run Keys",
  "T1053": "Scheduled Task/Job",
  "T1068": "Exploitation for Privilege Escalation",
  "T1078": "Valid Accounts",
  "T1021": "Remote Services",
  "T1005": "Data from Local System",
  "T1071": "Application Layer Protocol",
  "T1041": "Exfiltration Over C2 Channel",
};

/* 风险等级 → 徽章配色（命中关键字即可，兼容"高危/高风险"等写法） */
const RISK_STYLES = [
  { kw: "严重", color: "#7f1d1d" },
  { kw: "危急", color: "#7f1d1d" },
  { kw: "高",   color: "#dc2626" },
  { kw: "中",   color: "#ea580c" },
  { kw: "低",   color: "#f59e0b" },
];

let REPORT_RESULT = null;   // 最近一次分析结果（复制/导出用）
let REPORT_LIVE = false;    // 结果来源：true=后端 /api/analysis，false=mock

/* ============================================================
 * 初始化：填分析范围下拉 + 绑定三个按钮
 * ============================================================ */
function initReport(data) {
  REPORT_RESULT = null;
  REPORT_LIVE = false;

  /* 分析范围下拉：默认"全部数据"，另列出数据中实际出现的主机
   * （展示键口径 host ?? host_map[ip] ?? ip，与时间线主机过滤一致）。
   * mock 阶段后端不感知 scope，选了主机也返回固定报告；
   * 真实接口会把 scope 放进 POST body（见 getAnalysisReport）。 */
  const scopeSel = document.getElementById("report-scope");
  const hosts = [...new Set(
    data.events.map(e => App.displayHostKey(e)).filter(Boolean)
  )].sort();
  hosts.forEach(h => {
    const opt = document.createElement("option");
    opt.value = h;
    opt.textContent = `仅看主机：${h}`;
    scopeSel.appendChild(opt);
  });

  document.getElementById("btn-analyze").addEventListener("click", runAnalysis);
  document.getElementById("btn-copy-report").addEventListener("click", copyReportMarkdown);
  document.getElementById("btn-export-report").addEventListener("click", exportReport);

  /* 报告区交互用事件委托绑在持久容器 #report 上：
   * 打字机每次 innerHTML 覆盖都会丢掉子元素上的监听器，
   * 委托到容器则一次绑定终身有效（打字期间点击也能响应）。 */
  document.getElementById("report").addEventListener("click", ev => {
    // 证据 chip（ATT&CK 映射区的 #id）→ 详情弹窗
    const chip = ev.target.closest(".evid-chip");
    if (chip) {
      App.openEventDetail(Number(chip.dataset.eid));
      return;
    }
    // 关键证据表行 → 切到时间线并展开对应事件（跨 tab 定位）
    const row = ev.target.closest(".evid-row");
    if (row) {
      const id = Number(row.dataset.eid);
      // 优先时间线内嵌定位（能看到 raw_log 原文，与攻击链互证）；
      // 时间线模块未就绪时退化为详情弹窗，保证"点了一定有反馈"。
      if (typeof App._locateTimelineEvent === "function" &&
          App._locateTimelineEvent(id)) return;
      App.openEventDetail(id);
    }
  });
}

/* ============================================================
 * 开始分析：POST /api/analysis → 渲染
 * ============================================================ */
async function runAnalysis() {
  const btn = document.getElementById("btn-analyze");
  const box = document.getElementById("report");

  btn.disabled = true;          // 分析期间禁用，防连点
  btn.textContent = "分析中…";
  box.innerHTML = '<p class="muted">正在提交分析请求（POST /api/analysis），汇聚证据、关联攻击链、生成报告…</p>';

  const scopeSel = document.getElementById("report-scope");
  const scope = scopeSel.value === "all"
    ? { scope: "all" }
    : { scope: "host", host: scopeSel.value };

  let report, mode, state, error;
  try {
    ({ report, mode, state, error } = await getAnalysisReport(scope));
  } catch (err) {
    box.innerHTML = `<p style="color:var(--anomaly)">分析请求失败：${App.esc(err.message)}</p>`;
    btn.disabled = false;
    btn.textContent = "开始分析";
    return;
  }

  /* 封箱规则（2026-09-09）：Live 模式下失败/空链如实展示，
   * 绝不静默换成固定 mock 报告。 */
  if (state === "error") {
    box.innerHTML = `<p style="color:var(--anomaly)">分析失败（Live 模式，不回退演示数据）：${App.esc(error || "未知错误")}</p>`;
    btn.disabled = false;
    btn.textContent = "开始分析";
    return;
  }
  if (state === "empty") {
    box.innerHTML = '<p class="muted">当前分析范围内未检测到攻击链，无法生成分析报告。</p>';
    btn.disabled = false;
    btn.textContent = "开始分析";
    return;
  }

  REPORT_RESULT = report;
  REPORT_LIVE = mode === "live";
  renderAnalysisReport();
}

/**
 * 渲染报告：打字机逐字输出（模拟 LLM 流式返回的观感），
 * 输出完成后再绑定交互（表格行跳转 / 证据 chip / 导出按钮解禁）——
 * 打字期间 HTML 还没写完，提前绑定监听器也会随 innerHTML 覆盖而失效。
 */
function renderAnalysisReport() {
  const btn = document.getElementById("btn-analyze");
  const box = document.getElementById("report");
  const html = buildReportHtml(REPORT_RESULT);

  box.innerHTML = "";
  const target = document.createElement("div");
  target.className = "report";
  box.appendChild(target);

  typeWriter(target, html, () => {
    document.getElementById("btn-copy-report").disabled = false;
    document.getElementById("btn-export-report").disabled = false;
    btn.disabled = false;
    btn.textContent = "重新分析";
  });
}

/* ============================================================
 * 报告 HTML 组装（所有动态文本一律过 App.esc，防 XSS）
 * ============================================================ */
function buildReportHtml(r) {
  /* ---------- 空值防御：任何字段缺失都只表现为"该区不渲染/显示-" ---------- */
  const path = Array.isArray(safeField(r, "attack_path")) ? r.attack_path : [];
  const mappings = Array.isArray(safeField(r, "mitre_mapping")) ? r.mitre_mapping : [];
  const evidences = Array.isArray(safeField(r, "key_evidences")) ? r.key_evidences : [];
  const recommendations = Array.isArray(safeField(r, "recommendations")) ? r.recommendations : [];
  const summary = safeField(r, "summary");
  const risk = safeField(r, "risk_level");

  /* ---------- 一、攻击路径：横向流程图 ---------- */
  const flowHtml = path.length === 0
    ? '<p class="muted">（后端未返回攻击路径）</p>'
    : `<div class="report-flow">${path.map((name, i) => {
        const nodeColor = pathNodeColor(path, mappings, i);
        const arrow = i === 0 ? "" : (() => {
          const stage = arrowStage(path.length, mappings, i - 1);
          return `<span class="flow-arrow" style="color:${App.stageColor(stage)}"` +
                 `${stage ? ` title="${App.esc(stage)}"` : ""}>➜</span>`;
        })();
        return `${arrow}<span class="flow-node" style="background:${nodeColor}">${App.esc(name)}</span>`;
      }).join("")}</div>` +
      `<p class="muted">节点色与箭头色复用攻击链页的攻击阶段配色（契约映射表）。</p>`;

  /* ---------- 三、关键证据表（行点击 → 时间线详情） ---------- */
  const evidenceRows = evidences.map(ev => {
    /* 注意 Number(null)===0 的 JS 坑：event_id 为 null（契约允许缺失）
     * 必须先判空再转数字，否则会渲染成 "#0" */
    const rawId = safeField(ev, "event_id");
    const id = (rawId === null || rawId === undefined) ? NaN : Number(rawId);
    const e = Number.isFinite(id) ? App.eventById(id) : null;   // 从已加载事件列表定位
    const reason = safeField(ev, "reason") ?? "";
    if (!e) {
      /* 事件不在当前数据范围（如后端按 scope 过滤了事件列表）：仍展示
       * reason，但 id 显示灰色且不可点——绝不显示错误或空行。
       * id 本身非法（缺失/非数字）时显示 "-"，不渲染 "#NaN"。 */
      const idLabel = Number.isFinite(id) ? `#${id}` : "-";
      return `<tr><td class="mono">${App.esc(idLabel)}</td>
        <td>-</td><td>-</td><td>-</td><td>-</td>
        <td>${App.esc(reason)} <span class="muted">（事件不在当前数据范围）</span></td></tr>`;
    }
    const sev = App.SEVERITY[e.severity] || App.SEVERITY[0];
    return `<tr class="evid-row" data-eid="${e.id}" title="点击跳转到攻击时间线查看完整证据">
      <td class="mono">#${e.id}</td>
      <td class="mono">${App.esc(App.fmtTime(e.timestamp))}</td>
      <td>${App.esc(App.displayHostKey(e) ?? "-")}</td>
      <td><span class="chip">${App.esc(e.event_type ?? "-")}</span></td>
      <td style="color:${SEVERITY_COLORS[e.severity] || "#334155"}"><b>${e.severity ?? "-"} ${sev.label}</b></td>
      <td>${App.esc(reason)}</td>
    </tr>`;
  }).join("");
  const evidenceHtml = evidences.length === 0
    ? '<p class="muted">（无关键证据）</p>'
    : `<table>
        <tr><th>事件 id</th><th>时间（UTC+8）</th><th>主机</th><th>类型</th><th>severity</th><th>证据说明</th></tr>
        ${evidenceRows}
      </table>
      <p class="muted">点击行跳转到攻击时间线对应事件（自动展开三区证据面板）。</p>`;

  /* ---------- 四、ATT&CK 映射：阶段 → 技术标签组 ---------- */
  const mitreRows = mappings.map(m => {
    const stage = safeField(m, "stage") ?? "-";
    const tid = safeField(m, "technique") ?? "-";
    const tname = MITRE_TECHNIQUE_NAMES[tid] || "未知技术编号";
    const ids = (Array.isArray(safeField(m, "evidence_event_ids")) ? m.evidence_event_ids : [])
      /* null/undefined 不参与转换（Number(null)===0 会渲染 "#0"） */
      .filter(id => id !== null && id !== undefined && Number.isFinite(Number(id)));
    const evidChips = ids.length
      ? ids.map(id =>
          `<span class="chip flag evid-chip" data-eid="${Number(id)}" title="点击查看事件详情">#${Number(id)}</span>`
        ).join(" ")
      : '<span class="muted">无证据 id</span>';
    return `<div class="mitre-row">
      <span class="lg-chip" style="background:${App.stageColor(stage)}">${App.esc(stage)}</span>
      <span class="mitre-tag"><b class="mono">${App.esc(tid)}</b> ${App.esc(tname)}</span>
      <span class="mitre-evid">证据事件：${evidChips}</span>
    </div>`;
  }).join("");
  const mitreHtml = mappings.length === 0
    ? '<p class="muted">（无 ATT&CK 映射）</p>' : mitreRows;

  /* ---------- 五、风险徽章 + 处置建议（单一章节，避免"五、"重复） ---------- */
  const riskColor = riskStyle(risk);
  const riskHtml = risk
    ? `<p>本次攻击风险等级：<span class="risk-badge" style="background:${riskColor}">${App.esc(risk)}</span></p>`
    : "";
  const recoHtml = recommendations.length === 0 ? "" : `
    <p><b>处置建议：</b></p>
    <ul>${recommendations.map(x =>
      `<li>${App.esc(typeof x === "string" ? x : JSON.stringify(x))}</li>`).join("")}</ul>`;

  /* ---------- 概述段 ---------- */
  const summaryHtml = summary
    ? `<h4>二、攻击概述</h4><p>${App.esc(summary)}</p>` : "";

  return `
    ${path.length ? '<h4>一、攻击路径</h4>' : ""}
    ${flowHtml}
    ${summaryHtml}
    ${evidences.length ? '<h4>三、关键证据</h4>' : ""}
    ${evidenceHtml}
    ${mappings.length ? '<h4>四、ATT&CK 技术映射</h4>' : ""}
    ${mitreHtml}
    ${risk || recommendations.length ? '<h4>五、风险等级与处置建议</h4>' : ""}
    ${riskHtml}
    ${recoHtml}
    <p class="muted">—— 报告生成于 ${App.esc(nowLabel())} ·
      ${REPORT_LIVE
        ? "数据来源：后端 POST /api/analysis（LLM 分析结果经后端解析为结构化 JSON，前端不直接调用 LLM API）"
        : "数据来源：前端演示模式（手动开启的 Demo，内置样例数据）"}</p>
  `;
}

/* ============================================================
 * 攻击路径配色辅助
 * ============================================================ */

/** 节点配色（与攻击链页同语义）：
 *  - 首节点（攻击者，名称含 attacker）→ 攻击者红；
 *  - C2 节点 → "Command and Control" 阶段色；
 *  - 其余节点 → "攻入该节点的箭头"的阶段色（即左侧箭头颜色）。 */
function pathNodeColor(path, mappings, i) {
  const name = String(path[i] ?? "").toLowerCase();
  if (name.includes("attacker") || name.includes("攻击")) return "#dc2626";
  if (name.includes("c2")) return App.stageColor("Command and Control");
  if (i === 0) return "#dc2626";
  const stage = arrowStage(path.length, mappings, i - 1);
  return stage ? App.stageColor(stage) : "#2563eb";
}

/**
 * 第 i 条箭头（path[i] → path[i+1]）对应的攻击阶段（启发式推断）。
 * 后端结构里 attack_path 与 mitre_mapping 是两个平行数组，没有
 * 逐跳的阶段标注；在 stage 不进契约前按语义关键词匹配：
 *   首跳 → Initial Access 类；末跳 → Exfiltration/C2 类；
 *   中间跳 → Lateral Movement 类；都匹配不到 → 按顺序取用。
 * mock 数据的 mitre_mapping 与链路顺序一致，配色与攻击链页互证。
 */
function arrowStage(pathLen, mappings, arrowIdx) {
  const stages = mappings.map(m => safeField(m, "stage")).filter(Boolean);
  if (stages.length === 0) return null;
  const find = kw => stages.find(s => String(s).toLowerCase().includes(kw));
  if (arrowIdx === 0) return find("initial") || find("exploit") || stages[0];
  if (arrowIdx === pathLen - 2) return find("exfil") || find("command") || stages[stages.length - 1];
  return find("lateral") || stages[Math.min(arrowIdx, stages.length - 1)];
}

/** 风险等级 → 徽章色（关键字匹配，未命中回退红） */
function riskStyle(risk) {
  const s = String(risk ?? "");
  const hit = RISK_STYLES.find(x => s.includes(x.kw));
  return hit ? hit.color : "#dc2626";
}

/* ============================================================
 * 报告交互：已改为 initReport 里对 #report 容器的事件委托
 * （打字机 innerHTML 覆盖不丢监听器），本节仅保留说明。
 * ============================================================ */

/* ============================================================
 * 复制为 Markdown / 导出报告
 * ============================================================ */

/** 报告 → Markdown 文本（复制与导出共用同一生成器，口径一致） */
function buildReportMarkdown(r) {
  const path = Array.isArray(safeField(r, "attack_path")) ? r.attack_path : [];
  const mappings = Array.isArray(safeField(r, "mitre_mapping")) ? r.mitre_mapping : [];
  const evidences = Array.isArray(safeField(r, "key_evidences")) ? r.key_evidences : [];
  const recommendations = Array.isArray(safeField(r, "recommendations")) ? r.recommendations : [];

  const lines = [];
  lines.push("# 恶意攻击行为溯源分析报告");
  lines.push("");
  lines.push(`> 生成时间：${nowLabel()} · 风险等级：${safeField(r, "risk_level") ?? "-"} · ` +
             `数据来源：${REPORT_LIVE ? "后端 LLM 分析（POST /api/analysis）" : "前端演示模式（mock）"}`);
  lines.push("");
  if (path.length) {
    lines.push("## 一、攻击路径");
    lines.push("");
    lines.push(path.join(" → "));
    lines.push("");
  }
  const summary = safeField(r, "summary");
  if (summary) {
    lines.push("## 二、攻击概述");
    lines.push("");
    lines.push(String(summary));
    lines.push("");
  }
  if (evidences.length) {
    lines.push("## 三、关键证据");
    lines.push("");
    lines.push("| 事件 id | 时间（UTC+8） | 主机 | 类型 | severity | 证据说明 |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    evidences.forEach(ev => {
      const rawId = safeField(ev, "event_id");
      const id = (rawId === null || rawId === undefined) ? NaN : Number(rawId);  // Number(null)=0 坑，同上
      const e = Number.isFinite(id) ? App.eventById(id) : null;
      lines.push(`| ${Number.isFinite(id) ? "#" + id : "-"} | ${e ? App.fmtTime(e.timestamp) : "-"} | ` +
        `${e ? App.displayHostKey(e) ?? "-" : "-"} | ${e ? e.event_type ?? "-" : "-"} | ` +
        `${e ? e.severity ?? "-" : "-"} | ${safeField(ev, "reason") ?? ""} |`);
    });
    lines.push("");
  }
  if (mappings.length) {
    lines.push("## 四、ATT&CK 技术映射");
    lines.push("");
    lines.push("| 攻击阶段 | 技术 | 技术名称 | 证据事件（数据库 id） |");
    lines.push("| --- | --- | --- | --- |");
    mappings.forEach(m => {
      const tid = safeField(m, "technique") ?? "-";
      const ids = (Array.isArray(safeField(m, "evidence_event_ids")) ? m.evidence_event_ids : [])
        .filter(id => id !== null && id !== undefined && Number.isFinite(Number(id)));
      lines.push(`| ${safeField(m, "stage") ?? "-"} | ${tid} | ${MITRE_TECHNIQUE_NAMES[tid] || "-"} | ` +
        `${ids.map(i => `#${i}`).join("、") || "-"} |`);
    });
    lines.push("");
  }
  const risk = safeField(r, "risk_level");
  /* 第五节标题逻辑与 HTML 版保持一致：risk 与建议任一存在才出节，
   * 避免"只有建议列表却悬空无标题"的情况 */
  if (risk || recommendations.length) {
    lines.push("## 五、风险等级与处置建议");
    lines.push("");
  }
  if (risk) {
    lines.push(`**风险等级：${risk}**`);
    lines.push("");
  }
  if (recommendations.length) {
    recommendations.forEach(x => lines.push(`- ${typeof x === "string" ? x : JSON.stringify(x)}`));
    lines.push("");
  }
  return lines.join("\n");
}

/** 通用文本复制（两级策略，与 app.js 的 copyEventJSON 同思路）：
 *  Clipboard API 需要 https/localhost 安全上下文；用 http.server
 *  部署到局域网 IP 演示时会被浏览器禁掉，回退 execCommand。 */
async function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) { /* 走回退 */ }
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (e) { /* 放弃 */ }
  ta.remove();
  return ok;
}

function copyReportMarkdown() {
  if (!REPORT_RESULT) return;
  const btn = document.getElementById("btn-copy-report");
  copyTextToClipboard(buildReportMarkdown(REPORT_RESULT)).then(ok => {
    btn.textContent = ok ? "已复制 ✓" : "复制失败";
    setTimeout(() => { btn.textContent = "复制为 Markdown"; }, 1500);
  });
}

/** 导出报告：下载 .md 文件（Blob + 隐藏 <a>，浏览器本地生成，无后端参与） */
function exportReport() {
  if (!REPORT_RESULT) return;
  const blob = new Blob([buildReportMarkdown(REPORT_RESULT)], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `溯源分析报告_${nowLabel().replace(/[-: ]/g, "")}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);   // 及时释放，避免内存泄漏
}

/* 当前时间标签（报告页脚/Markdown 头共用）："YYYY-MM-DD HH:MM" */
function nowLabel() {
  const d = new Date();
  const p = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/**
 * 打字机效果：模拟 LLM 流式输出的观感。
 *
 * 实现要点：
 *   - HTML 标签（<xxx>）整体跳过，只逐帧输出"可见字符"；
 *   - 每帧输出 CHUNK 个字符而不是 1 个：整份报告 HTML 有上万字符，
 *     2ms/字符要 20~30 秒——期间 innerHTML 每帧都被重写，物理点击
 *     会落在刚被替换掉的旧节点上（事件冒泡不到容器，点了没反应）。
 *     压缩到 ~6 秒：流式观感还在，交互很快进入稳定状态；
 *   - caret 是闪烁光标 span，结束后用完整 HTML 替换（顺带移除光标）；
 *   - 递归 setTimeout 而不是 setInterval：上一帧画完才开始计时，
 *     节奏更稳，且可随时停。
 */
const TYPE_CHUNK = 6;    // 每帧输出的可见字符数
const TYPE_INTERVAL = 6; // 帧间隔毫秒（6字符/6ms ≈ 1000字符/秒）

function typeWriter(target, html, done) {
  let i = 0;
  const caret = '<span class="caret">&nbsp;</span>';
  (function step() {
    if (i >= html.length) {
      target.innerHTML = html;   // 收尾：完整 HTML（去光标）
      done();
      return;
    }
    if (html[i] === "<") {
      i = html.indexOf(">", i) + 1;  // 标签整体输出，避免半个标签闪烁
    } else {
      i += TYPE_CHUNK;               // 一帧输出多个可见字符，缩短动画时长
    }
    target.innerHTML = html.slice(0, i) + caret;
    setTimeout(step, TYPE_INTERVAL);
  })();
}
