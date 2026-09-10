/* ============================================================
 * chain.js — 攻击链页（成员F）
 * ============================================================
 * 页面内容（对应分工文档"攻击链"页要求，ECharts graph 力导向图）：
 *   左：关系图（layout:"force"）。节点=攻击者/主机/C2，
 *       箭头边=攻击动作，边label=动作名(阶段)+时间+T-ID；
 *       边颜色 = 攻击阶段色（严格照契约映射表，App.stageColor 容错查找）；
 *       节点颜色 = 最早一条"攻入该主机"的动作所处阶段（见下方说明）；
 *       仅有 IP、映射不到主机名的节点显示 IP + 灰色边框/灰字区分。
 *   顶部：阶段图例（只列链上实际出现的阶段，按攻击时间顺序），
 *         外加一句交互提示，答辩时不用口头解释配色规则。
 *   右：侧栏三态——攻击步骤卡片（默认）/ 节点相关事件 / 边证据事件。
 *       点击图上节点 → 侧栏列出该主机相关事件（host/IP 双口径匹配）；
 *       点击图上边（或步骤卡）→ 侧栏列出该动作的证据事件；
 *       事件卡点击 → 内嵌展开共享详情组件（App.buildEventDetailHTML，
 *       与时间线 tab 完全同一份，null 不渲染 / detail 中文标签 / raw_log 证据块），
 *       与时间线 tab 互相印证——这正是本页的验收标准。
 *
 * 三个契约/兼容点在这里落地：
 *   1) 主机展示：target_host ?? target_ip（映射不到主机名显示 IP，
 *      绝不把 IP 塞进 host 字段）；
 *   2) source_host === target_host 的"本机执行"环节：ECharts graph
 *      画不了自环边，挂一个"虚拟执行节点"在主机附近来表达（force 下
 *      不固定，靠边的牵引力自然贴着主机）；
 *   3) 端点解析 resolveEndpoint() 两级策略：优先 adapter 给的
 *      source/target 节点 id（2026-09-08 起真实接口会带），兜底按
 *      展示键（host ?? ip）匹配——纯 IP 链路（host=null）不会误匹配。
 *
 * 数据源：getAttackChain()（api.js，优先 GET /api/attack-chain，
 * 失败回退 mock/chain.json，结构经 normalizeChain 归一化）。
 * ============================================================ */

function renderChain(data) {
  const { chain, events } = data;

  const linksBox = document.getElementById("chain-links");
  const legendBox = document.getElementById("chain-legend");

  /* 封箱空态：Live 模式下关联引擎没跑出链（空库/无异常）→ 如实提示，
   * 不画空图也不换演示数据。 */
  if (!Array.isArray(chain.links) || chain.links.length === 0) {
    const msg = data.mode === "demo"
      ? "演示数据未包含攻击链。"
      : "未检测到攻击链（当前数据库中没有可关联的攻击行为）。";
    const graphDom = document.getElementById("chain-graph");
    if (graphDom) graphDom.innerHTML = `<p class="muted" style="padding:24px;text-align:center">${App.esc(msg)}</p>`;
    if (linksBox) linksBox.innerHTML = `<h3>攻击步骤（0）</h3><p class="muted">${App.esc(msg)}</p>`;
    return;
  }

  /* ================================================================
   * 端点解析（两级策略，见文件头说明③）——先定义，节点/边都要用
   * ================================================================ */
  function resolveEndpoint(l, side, i) {
    const ref = safeField(l, side);
    if (ref != null && chain.nodes.some(n => n.id === ref)) return ref;
    const host = safeField(l, `${side}_host`);
    const ip = safeField(l, `${side}_ip`);
    const key = host ?? ip;
    const node = chain.nodes.find(n => (n.host ?? n.ip) === key);
    return node ? node.id : (key ?? `unknown_${side}_${i}`);
  }

  /* ================================================================
   * 节点着色数据：每个节点"最早入边"的攻击阶段
   * ------------------------------------------------------------
   * 语义："攻击者是以什么阶段的动作打到这台机器的"——
   *   web-server 最早被 Initial Access 打中 → 红色；
   *   office/core 被 Lateral Movement 打中 → 蓝色；
   *   c2 被 Exfiltration 打中 → 深红。
   * 没有入边的是攻击源（attacker），沿用攻击者红。
   * 这样 8 阶段各一色（契约映射表）同时保留"攻击者/C2/受害主机"的直觉。
   * ================================================================ */
  const incomingStage = {};   // node.id → 最早入边的 attack_stage
  const incomingTime = {};    // node.id → 该入边时间（比较"最早"用）
  chain.links.forEach(l => {
    const tId = resolveEndpoint(l, "target", 0);
    const t = String(safeField(l, "timestamp") || "");
    if (incomingStage[tId] === undefined || t < incomingTime[tId]) {
      incomingStage[tId] = l.attack_stage;
      incomingTime[tId] = t;
    }
  });

  /* ---------- 节点初始坐标（force 布局的起点） ----------
   * 力导向会自动松弛，但初始位置决定大体走向：给 attack chain 一个
   * "左→右讲故事"的起点，力导只做局部微调，整条链一屏可读。
   * live 推导节点自带 x（api.js normalizeChain 布置），优先用它。 */
  const LAYOUT_X = {
    "attacker": 80, "web-server": 320, "office-pc-01": 560,
    "core-server": 800, "c2-server": 1000,
  };
  const LAYOUT_Y = { "attacker": 150, "web-server": 150, "office-pc-01": 310, "core-server": 150, "c2-server": 150 };

  const nodes = chain.nodes.map((n, i) => {
    const hasHostName = !!n.host;   // 契约：映射不到主机名的节点只有 IP
    const stage = safeField(incomingStage, n.id);
    const fill = stage ? App.stageColor(stage)
               : n.category === "attacker" ? "#dc2626"
               : "#2563eb";
    return {
      id: n.id,                     // ECharts 内部连线引用
      name: hasHostName ? n.host : n.ip,   // 契约回退：target_host ?? target_ip
      value: n,                     // 原始节点数据，tooltip/点击时取用
      x: n.x ?? LAYOUT_X[n.id] ?? 400 + (i % 5) * 180,   // force 初始位置
      y: n.y ?? LAYOUT_Y[n.id] ?? 180,
      symbolSize: n.category === "attacker" ? 54 : n.category === "c2" ? 48 : 44,
      itemStyle: {
        color: fill,
        // 灰框 + 灰字 = "仅有 IP、无主机映射"的视觉区分（需求①）
        borderColor: hasHostName ? "#ffffff" : "#9ca3af",
        borderWidth: hasHostName ? 2 : 3,
        shadowBlur: 6, shadowColor: "rgba(31,41,55,0.25)",
      },
      label: {
        show: true, position: "bottom",
        color: hasHostName ? "#1f2937" : "#6b7280",
        fontWeight: hasHostName ? 600 : 400,
      },
    };
  });

  /* ================================================================
   * 生成边：箭头 + 阶段色 + label（动作名+时间+T-ID）
   * ================================================================ */
  const edges = [];
  chain.links.forEach((l, i) => {
    const color = App.stageColor(l.attack_stage);   // 容错查找（大小写/变体也命中）
    const srcId = resolveEndpoint(l, "source", i);
    const dstId = resolveEndpoint(l, "target", i);
    // 边 label 三要素（需求①）：动作名=阶段、时间、ATT&CK 技术编号。
    // ECharts 的 label 是 zrender 纯文本渲染，无 XSS 风险，不用 esc。
    const labelText = `[${i + 1}] ${l.attack_stage ?? "?"} · ${l.mitre_technique ?? "?"}\n${App.fmtTime(l.timestamp)}`;
    const edgeCommon = {
      value: i,     // 记住这是第几条 link：点击/tooltip 回 chain.links 取详情
      lineStyle: { color, width: 2.5, curveness: 0.12 },
    };

    if (srcId === dstId) {
      /* "web-server → web-server 执行异常进程"：自环边画不出来，
       * 挂一个 roundRect 小节点表达"主机内部发生的事"。
       * force 布局下不固定位置——它只连这一条边，会被牵引着贴在主机旁。 */
      const execNodeId = `__exec_${i}`;
      nodes.push({
        id: execNodeId,
        name: `本机执行\n${l.mitre_technique ?? ""}`,
        value: { virtual: true, linkIndex: i },
        symbol: "roundRect", symbolSize: [96, 34],   // 数组 = [宽, 高]
        itemStyle: { color, borderColor: "#ffffff", borderWidth: 1 },
        label: { show: true, position: "inside", color: "#fff", fontSize: 10 },
      });
      edges.push({ source: srcId, target: execNodeId, ...edgeCommon,
        lineStyle: { ...edgeCommon.lineStyle, curveness: 0.3, type: "dashed" },
        label: { show: false },   // 动作信息在虚线另一头的卡片/tooltip里，这里不挤
      });
    } else {
      edges.push({ source: srcId, target: dstId, ...edgeCommon,
        label: {
          show: true, formatter: labelText,
          fontSize: 10, lineHeight: 14, color: "#334155",
          backgroundColor: "rgba(255,255,255,0.85)", borderRadius: 3, padding: [2, 4],
        },
      });
    }
  });

  /* ================================================================
   * 左侧：ECharts 力导向关系图
   * ================================================================ */
  const chart = chartOrResize("chain-graph", dom => echarts.init(dom));
  /* notMerge: true —— setOption 默认是合并模式，renderChain 被再次调用时
   * （live 刷新/外部联动重渲染）旧链的节点边会残留在图上（虚拟执行节点
   * 按 id 合并、数组按索引合并，链长变化时必然错位）。整图替换才安全。 */
  chart.setOption({
    tooltip: {
      // formatter 支持函数：按数据类型（node/edge）返回不同 HTML（先过 esc）
      formatter: p => {
        if (p.dataType === "edge") {
          const l = chain.links[p.data.value];
          if (!l) return "";
          return `<b>[${p.data.value + 1}] ${App.esc(l.attack_stage)}</b><br>` +
            `${App.esc(l.source_host ?? l.source_ip)} → ${App.esc(l.target_host ?? l.target_ip)}<br>` +
            `${App.esc(l.mitre_technique)} · ${App.esc(App.fmtTime(l.timestamp))}<br>` +
            `点击边查看证据事件<br>` + App.esc(l.description);
        }
        if (p.dataType === "node") {
          const n = p.data.value;
          if (n.virtual) return "本机执行环节（自环示意）：进程落地 + 远程下载";
          return `<b>${App.esc(n.host ?? n.ip)}${n.host ? "" : "（仅IP，无主机映射）"}</b><br>` +
            `IP: ${App.esc(n.ip)}<br>角色: ${App.esc(n.role)}` +
            (safeField(incomingStage, n.id) ? `<br>攻入阶段: ${App.esc(incomingStage[n.id])}` : "") +
            `<br>点击节点查看该主机相关事件`;
        }
        return "";
      },
    },
    series: [{
      type: "graph",
      layout: "force",                 // 需求：力导向图（初始坐标决定大体走向）
      roam: true,                      // 拖拽/滚轮缩放，答辩时可以拉近看
      force: {
        repulsion: 900,                // 节点间斥力：适中，避免节点挤成一团也不至于撒满屏
        edgeLength: [110, 190],        // 边的理想长度区间：短一些保证整链一屏读完
        gravity: 0.28,                 // 向心引力：偏大，把链条收在画布中央
        layoutAnimation: true,         // 松弛过程动画，演示时有"链条长出来"的效果
      },
      edgeSymbol: ["none", "arrow"],   // 有向图：起点无、终点箭头
      edgeSymbolSize: 14,
      data: nodes,
      links: edges,
    }],
  }, { notMerge: true });

  /* ================================================================
   * 顶部：阶段图例（需求②）
   * 只列链上实际出现的阶段，按攻击动作时间顺序（讲故事的顺序），
   * 颜色严格走 App.stageColor（契约映射表 + 容错）。
   * ================================================================ */
  const stageOrder = [];
  chain.links.forEach(l => {
    const s = l.attack_stage;
    if (s && !stageOrder.some(x => String(x).toLowerCase() === String(s).toLowerCase())) {
      stageOrder.push(s);
    }
  });
  legendBox.innerHTML =
    `<span class="muted">攻击阶段：</span>` +
    stageOrder.map(s =>
      `<span class="lg-chip" style="background:${App.stageColor(s)}">${App.esc(s)}</span>`).join("") +
    `<span class="muted legend-note">节点色 = 攻入该主机的阶段 · 灰框灰字 = 仅有 IP 无主机映射 · 点击节点/边查看证据</span>`;

  /* ================================================================
   * 右侧：侧栏三态（步骤 / 节点事件 / 边证据）
   * ================================================================ */

  /* 事件卡（侧栏通用），点击整卡 → 内嵌展开共享详情组件 */
  function evtCardHtml(e) {
    const sev = App.SEVERITY[e.severity] || App.SEVERITY[0];
    return `
      <div class="evt-item" data-eid="${e.id}">
        <div class="evt-head">
          <b>${App.esc(App.fmtTime(e.timestamp))}</b>
          <span class="chip">${App.esc(e.event_type ?? "?")}</span>
          <span class="chip">sev-${e.severity ?? "-"} ${sev.label}</span>
          ${App.flagBadges(e.anomaly_flags)}
        </div>
        <div class="desc">${App.esc(e.description ?? "")}</div>
      </div>`;
  }

  /** 事件卡点击委托：单开式展开详情面板（再点收起，换卡先收旧） */
  function bindEvtCards() {
    linksBox.querySelectorAll(".evt-item").forEach(card => {
      card.addEventListener("click", ev => {
        // 面板内部点击（含复制按钮）不参与切换——与时间线同规则
        if (ev.target.closest(".tl-detail") || ev.target.closest(".btn-copy")) return;
        const id = Number(card.dataset.eid);
        const existing = card.querySelector(".tl-detail");
        linksBox.querySelectorAll(".evt-item .tl-detail").forEach(p => { if (p !== existing) p.remove(); });
        linksBox.querySelectorAll(".evt-item.open").forEach(c => { if (c !== card) c.classList.remove("open"); });
        if (existing) { existing.remove(); card.classList.remove("open"); return; }
        const e = App.eventById(id);
        if (!e) return;
        card.classList.add("open");
        card.insertAdjacentHTML("beforeend", App.buildEventDetailHTML(e));
      });
    });
  }

  function bindBack() {
    const btn = document.getElementById("side-back");
    if (btn) btn.addEventListener("click", renderSteps);
  }

  /* ---------- 视图①：攻击步骤卡片（默认） ---------- */
  function renderSteps() {
    /* live 模式下每条 step 带 evidence_event_ids（数据库 events.id 数组，
     * D 产出）→ 渲染成可点击的证据 chip，点了直接开详情弹窗；
     * mock 没有该字段 → 不渲染 chip（降级为图上点边/点节点找证据）。 */
    linksBox.innerHTML = `<h3>攻击步骤（${chain.links.length}）</h3>` +
      chain.links.map((l, i) => {
        const color = App.stageColor(l.attack_stage);
        const evids = Array.isArray(safeField(l, "evidence_event_ids")) ? l.evidence_event_ids : [];
        const evidHtml = evids.length
          ? `<div class="evid">证据事件：${evids.map(id =>
              `<span class="chip flag evid-chip" data-eid="${id}" title="点击查看事件详情">#${id}</span>`).join(" ")}</div>`
          : "";
        return `
        <div class="chain-link-item clickable" data-edge="${i}" title="点击查看该动作的证据事件">
          <span class="stage" style="background:${color}">${App.esc(l.attack_stage)}</span>
          <span class="tid">${App.esc(l.mitre_technique)}</span>
          <div class="path">${App.esc(l.source_host ?? l.source_ip)} → ${App.esc(l.target_host ?? l.target_ip)}</div>
          <div class="muted">${App.esc(App.fmtTime(l.timestamp))} · ${App.esc(l.source_ip)} → ${App.esc(l.target_ip)}</div>
          <div class="desc">${App.esc(l.description)}</div>
          ${evidHtml}
        </div>`;
      }).join("");

    // 步骤卡点击 = 等效点击图上对应的边（需求④同一视图）
    linksBox.querySelectorAll("[data-edge]").forEach(card => {
      card.addEventListener("click", ev => {
        if (ev.target.closest(".evid-chip")) return;   // chip 自己的弹窗逻辑
        showEdgeEvidence(Number(card.dataset.edge));
      });
    });
    // 证据 chip → 详情弹窗（契约：定位事件一律用 id）
    linksBox.querySelectorAll(".evid-chip").forEach(chip => {
      chip.addEventListener("click", () => App.openEventDetail(chip.dataset.eid));
    });
  }

  /* ---------- 视图②：节点相关事件（需求③） ---------- */
  function showNodeEvents(n) {
    /* 匹配规则：host 同名 或 src_ip/dst_ip 等于节点 IP——
     * 主机侧事件（Sysmon）记 host，网络侧事件（PCAP）记 IP，两边都兜住。
     * 匹配条件逐项判空：n.host / n.ip 为 null 时不参与该条件的比较，
     * 避免 null === null 把不相干事件误匹配进来。 */
    const related = events.filter(e =>
      (n.host != null && e.host === n.host) ||
      (n.ip != null && (e.src_ip === n.ip || e.dst_ip === n.ip))
    ).sort((a, b) => String(safeField(a, "timestamp") || "").localeCompare(
        String(safeField(b, "timestamp") || "")));

    linksBox.innerHTML = `
      <button class="btn-back" id="side-back">← 返回攻击步骤</button>
      <h3>节点 ${App.esc(n.host ?? n.ip)} 相关事件（${related.length}）</h3>
      ${related.slice(0, 15).map(evtCardHtml).join("")}
      ${related.length === 0 ? '<p class="muted">无相关事件</p>' : ""}
      ${related.length > 15 ? `<p class="muted">仅显示前 15 条（共 ${related.length} 条），全部明细请到攻击时间线 tab 按主机过滤查看。</p>` : ""}
    `;
    bindBack();
    bindEvtCards();
  }

  /* ---------- 视图③：边的证据事件（需求④） ---------- */
  /**
   * 关联某条攻击动作的证据事件。三级优先级（命中高优先级就不再叠加低级，
   * 避免相邻动作的证据混叠——比如边1和边2都经过 web-server，
   * 宽窗口会把两边的结果变得一模一样，"互证"就失去精度了）：
   *   1) link.evidence_event_ids（D/adapter 给的数据库 id，最准）；
   *   2) IP 对完全匹配：e.src_ip === source_ip && e.dst_ip === target_ip
   *      （网络事件直接对口，不限时间——PCAP 事件 timestamp 与关联窗口
   *      可能有偏差）；
   *   3) 主机匹配 + 链路时间 ±15 分钟窗口（主机侧动作的时间邻近证据，
   *      典型如自环的"本机执行"环节——IP 对必然是自身，没有独立事件）。
   */
  function correlateLinkEvents(l) {
    const refs = Array.isArray(safeField(l, "evidence_event_ids")) ? l.evidence_event_ids : null;
    if (refs && refs.length > 0) {
      const direct = refs.map(id => App.eventById(id)).filter(Boolean);
      if (direct.length > 0) return direct;
    }
    const byTime = (a, b) => String(safeField(a, "timestamp") || "").localeCompare(
        String(safeField(b, "timestamp") || ""));
    // 优先级 2：IP 对精确匹配
    const byPair = events.filter(e =>
      l.source_ip != null && l.target_ip != null &&
      e.src_ip === l.source_ip && e.dst_ip === l.target_ip);
    if (byPair.length > 0) return byPair.sort(byTime);
    // 优先级 3：主机匹配 + 时间窗口
    const lt = Date.parse(safeField(l, "timestamp") || "");
    const WINDOW_MS = 15 * 60 * 1000;
    return events.filter(e => {
      const ts = Date.parse(safeField(e, "timestamp") || "");
      if (isNaN(lt) || isNaN(ts) || Math.abs(ts - lt) > WINDOW_MS) return false;
      return (l.source_host != null && e.host === l.source_host) ||
             (l.target_host != null && e.host === l.target_host);
    }).sort(byTime);
  }

  function showEdgeEvidence(i) {
    const l = chain.links[i];
    if (!l) return;
    const evids = correlateLinkEvents(l);
    const color = App.stageColor(l.attack_stage);
    linksBox.innerHTML = `
      <button class="btn-back" id="side-back">← 返回攻击步骤</button>
      <h3>攻击动作 [${i + 1}]</h3>
      <div class="chain-link-item edge-summary">
        <span class="stage" style="background:${color}">${App.esc(l.attack_stage ?? "?")}</span>
        <span class="tid">${App.esc(l.mitre_technique ?? "?")}</span>
        <div class="path">${App.esc(l.source_host ?? l.source_ip)} → ${App.esc(l.target_host ?? l.target_ip)}</div>
        <div class="muted">${App.esc(App.fmtTime(l.timestamp))} · ${App.esc(l.source_ip)} → ${App.esc(l.target_ip)}</div>
        <div class="desc">${App.esc(l.description ?? "")}</div>
      </div>
      <h3>证据事件（${evids.length}）</h3>
      <p class="muted">以下事件可在攻击时间线 tab 找到原文，互相印证。</p>
      ${evids.length ? evids.map(evtCardHtml).join("") : '<p class="muted">未找到直接关联的事件证据（该动作可能只有网络面/主机面单侧记录）。</p>'}
    `;
    bindBack();
    bindEvtCards();
  }

  /* ================================================================
   * 图交互绑定：点节点 → 视图②；点边 → 视图③
   * off 再 on，防止重复绑定（renderChain 可能被调用多次）。
   * App._chainApi 暴露侧栏视图与关联函数：供自动化测试与外部联动
   * （如后续"时间线跳攻击链"反向导航）复用，不新增全局作用域污染。
   * ================================================================ */
  chart.off("click");
  chart.on("click", p => {
    if (p.dataType === "node") {
      const n = p.data.value;
      if (n.virtual) return;               // 虚拟执行节点没有对应主机
      showNodeEvents(n);
    } else if (p.dataType === "edge") {
      showEdgeEvidence(p.data.value);
    }
  });

  App._chainApi = { renderSteps, showNodeEvents, showEdgeEvidence, correlateLinkEvents };

  renderSteps();   // 侧栏初始视图：攻击步骤
}
