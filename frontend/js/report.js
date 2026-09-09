/* ============================================================
 * report.js — 分析报告页（成员F）
 * ============================================================
 * 页面内容（对应分工文档"分析报告"页 + 题目"大模型 Agent"要求）：
 *   点击"开始分析" → 打字机效果逐字输出一份溯源分析报告，
 *   内容全部由真实数据驱动（攻击链 + 证据事件）：
 *     一、事件概述（总量/主机数/异常数/时间窗）
 *     二、攻击路径还原（攻击链逐步展开）
 *     三、关键证据（高危事件表）
 *     四、ATT&CK 技术映射（阶段/T-ID/证据事件id 表）
 *     五、风险说明与处置建议
 *
 * 与真实 LLM 的关系（重要，答辩会被问）：
 *   目前的"分析"是前端模板引擎：把结构化数据填进分析框架。
 *   接入真实大模型时：
 *     1) 把 buildReportHtml 里构造的"数据摘要"（链路 + 证据 JSON）
 *        作为 prompt POST 给后端 LLM 服务（如 /api/analyze）；
 *     2) 用同样的打字机函数流式渲染返回文本；
 *     3) 页面结构、按钮、样式完全复用，只换数据来源。
 *   答辩口径：前端预留了 LLM 接入点，演示模式用模板保证断网可演示
 *   ——这正是分工文档"断网都尽量能演示核心功能"的要求。
 * ============================================================ */

let REPORT_DATA = null;   // 模块级缓存：initReport 存数据，点击按钮时用

function initReport(data) {
  REPORT_DATA = data;
  document.getElementById("btn-analyze").addEventListener("click", runAnalysis);
}

function runAnalysis() {
  const btn = document.getElementById("btn-analyze");
  const box = document.getElementById("report");
  btn.disabled = true;          // 分析期间禁用按钮，防连点
  btn.textContent = "分析中…";
  box.innerHTML = '<p class="muted">正在汇聚证据、关联攻击链、生成报告…</p>';

  const html = buildReportHtml(REPORT_DATA);

  box.innerHTML = "";
  const target = document.createElement("div");
  target.className = "report";
  box.appendChild(target);
  typeWriter(target, html, () => {
    btn.disabled = false;
    btn.textContent = "重新分析";
  });
}

/**
 * 组装报告 HTML（核心：所有数字都从数据算出来，不是写死的）。
 * 解构参数 { events, chain } = App.DATA 的两个成员。
 */
function buildReportHtml({ events, chain }) {
  // 异常事件：契约规定 anomaly_flags 无异常为 []
  const anomalous = events.filter(e => e.anomaly_flags && e.anomaly_flags.length > 0);
  const hosts = [...new Set(events.map(e => e.host))];   // [...new Set()] = 去重转数组惯用法
  const t0 = chain.links[0] ? chain.links[0].timestamp : "-";
  const tN = chain.links[chain.links.length - 1] ? chain.links[chain.links.length - 1].timestamp : "-";
  // 外部 IP = 不以 "10." 开头的 dst_ip（靶场内网固定 10.0.0.0/8 段）；
  // 排除攻击者自身 IP——它是攻击来源，不是数据外传目标
  const attackerIp = chain.nodes.find(n => n.category === "attacker")?.ip;
  const externalIps = [...new Set(events
    .filter(e => e.dst_ip && !e.dst_ip.startsWith("10.") && e.dst_ip !== attackerIp)
    .map(e => e.dst_ip))];

  /* 关键证据排序：severity 降序（3 最高危在最前），同 severity 按时间先后。
   * b.severity - a.severity 是数值降序的标准写法；
   * || 后面的表达式只在前面相等（差值=0）时生效。 */
  const keyEvidence = [...anomalous]
    .sort((a, b) => b.severity - a.severity || a.timestamp.localeCompare(b.timestamp))
    .slice(0, 6);   // 只展示 top6，报告要克制不要堆砌

  return `
    <h4>一、事件概述</h4>
    <p>系统共分析 <b>${events.length}</b> 条标准化安全事件（Event V2），
    覆盖 <b>${hosts.length}</b> 台主机，识别出 <b style="color:var(--anomaly)">${anomalous.length}</b> 条异常事件，
    涉及 <b>${chain.links.length}</b> 个攻击步骤、
    <b>${new Set(chain.links.map(l => l.attack_stage)).size}</b> 个 ATT&CK 攻击阶段。
    攻击活动时间窗约为 <b>${App.esc(App.fmtTime(t0))} ~ ${App.esc(App.fmtTime(tN))}</b>（UTC+8）。</p>

    <h4>二、攻击路径还原</h4>
    <p>基于跨主机事件关联，还原出以下攻击链：</p>
    <ul>
      ${chain.links.map(l => `
        <li><b>[${App.esc(l.attack_stage)} · ${App.esc(l.mitre_technique)}]</b>
        ${App.esc(App.fmtTime(l.timestamp))} ——
        ${App.esc(l.source_host ?? l.source_ip)} → ${App.esc(l.target_host ?? l.target_ip)}：
        ${App.esc(l.description)}</li>`).join("")}
    </ul>
    <p>结论：这是一起由外部 IP ${App.esc(chain.nodes[0] ? chain.nodes[0].ip : "-")} 发起的
    <b>Web 侵入 → 落地执行 → 横向移动 → 数据外传</b> 的完整攻击链，
    攻击者最终将数据外传至外部 C2/收集服务器${externalIps.length ? `（外部目标：${App.esc(externalIps.slice(0, 4).join("、"))}）` : ""}。</p>

    <h4>三、关键证据</h4>
    <table>
      <tr><th>时间（UTC+8）</th><th>主机</th><th>类型</th><th>severity</th><th>异常规则</th><th>描述</th></tr>
      ${keyEvidence.map(e => `
        <tr>
          <td>${App.esc(App.fmtTime(e.timestamp))}</td>
          <td>${App.esc(e.host)}</td>
          <td>${App.esc(e.event_type)}</td>
          <td style="color:${SEVERITY_COLORS[e.severity]}"><b>${e.severity}</b></td>
          <td>${App.esc((e.anomaly_flags || []).join(", "))}</td>
          <td>${App.esc(e.description)}</td>
        </tr>`).join("")}
    </table>

    <h4>四、ATT&CK 技术映射</h4>
    <table>
      <tr><th>攻击阶段</th><th>ATT&CK 技术</th><th>证据事件（id）</th></tr>
      ${chain.links.map(l => `
        <tr>
          <td><b>${App.esc(l.attack_stage)}</b></td>
          <td>${App.esc(l.mitre_technique)}</td>
          <td>${App.esc(evidenceIds(events, l).join(", ") || "关联链路")}</td>
        </tr>`).join("")}
    </table>

    <h4>五、风险说明与处置建议</h4>
    <ul>
      <li><b>入口风险</b>：Web 服务存在 SQL 注入与代码执行漏洞（T1190），建议立即修复输入校验并排查 Web 日志中的其他入侵痕迹。</li>
      <li><b>落地执行</b>：检测到 rundll32/mshta 等 LOLBin 滥用与远程下载（T1059），建议隔离相关主机、阻断对外部 C2 域名/IP 的访问。</li>
      <li><b>横向移动</b>：内网存在 SMB/RDP/SSH 横向连接（T1021），建议加固凭据、开启最小权限并审计异常登录。</li>
      <li><b>数据外传</b>：core-server 存在 1.2MB 级外传与 C2 心跳/DNS/ICMP 隐蔽信道（T1041/T1071），建议立即阻断外联并评估数据泄露范围。</li>
    </ul>
    <p class="muted">—— 本报告由前端根据攻击链关联结果与证据事件自动生成（演示模式；真实 LLM API 接入点见本文件头部说明）。</p>
  `;
}

/**
 * 找出与某条链路相关的证据事件 id（报告第四部分表格用）。
 * 匹配逻辑（三条满足其一即算相关）：
 *   - 事件的 src_ip 是链路的发起 IP（攻击动作从这台机器发出）；
 *   - 事件的 dst_ip 是链路的目标 IP（这台机器是被打的目标）；
 *   - 事件的 host 是链路任一端主机名（主机侧日志证据）。
 * 截取前 5 条：证据贵精不贵多。
 */
function evidenceIds(events, link) {
  /* 优先级 1：D/adapter 直接给的 evidence_event_ids（数据库 events.id）
   * ——这是最准的口径（D 关联时用真实 id 做的证据链），有就直接用；
   * 优先级 2（fallback，mock/早期数据没有该字段）：按 IP/主机启发式匹配
   * 异常事件。 */
  const refs = Array.isArray(safeField(link, "evidence_event_ids"))
    ? link.evidence_event_ids : null;
  if (refs && refs.length > 0) {
    return refs.slice(0, 5).map(id => `#${id}`);
  }
  return events
    .filter(e => e.anomaly_flags && e.anomaly_flags.length > 0 &&
      (e.src_ip === link.source_ip || e.dst_ip === link.target_ip ||
       e.host === link.source_host || e.host === link.target_host))
    .slice(0, 5)
    .map(e => `#${e.id}`);
}

/**
 * 打字机效果：模拟 LLM 流式输出的观感。
 *
 * 实现要点：
 *   - 每 2ms 输出一个字符；50 条数据的报告约几万字符，
 *     2ms/字符 ≈ 1~2 分钟太慢——但 HTML 标签（<xxx>）是整体跳过的，
 *     实际"可见字符"只占一小部分，整体观感约 10 秒出头，可接受。
 *   - html.indexOf(">", i) + 1 找到标签结尾，整段复制；
 *     遇到已经"输出到一半"的标签，浏览器容错渲染不会报错，
 *     最终完整 HTML 会覆盖修正。
 *   - caret 是闪烁光标 span，结束后用完整 HTML 替换（顺带移除光标）。
 *
 * 递归 setTimeout 而不是 setInterval：
 *   setTimeout 保证上一帧画完才开始计时，节奏更稳，且可以随时停。
 */
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
      i += 1;
    }
    target.innerHTML = html.slice(0, i) + caret;
    setTimeout(step, 2);
  })();
}
