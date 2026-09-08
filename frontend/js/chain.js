/* ============================================================
 * chain.js — 攻击链页（成员F）
 * ============================================================
 * 页面内容（对应分工文档"攻击链"页要求，ECharts graph 实现）：
 *   左：关系图。节点=主机（Attacker/Web-Server/Office-PC/Core/C2），
 *       箭头边=攻击步骤，边颜色=攻击阶段（配色照抄契约映射表）。
 *   右：攻击步骤卡片列表（阶段 / T-ID / 主机路径 / 时间 / 描述）。
 *   点击图上节点 → 下方联动列出该主机的相关证据事件，点事件可看详情。
 *
 * 两个契约点在这里落地：
 *   1) 主机展示：target_host ?? target_ip（chain.json 的 link 两个字段都有，
 *      用 ?? 回退，映射不到主机名也不至于显示空）；
 *   2) source_host === target_host 的"本机执行"环节：
 *      ECharts 的 graph 不会画起点=终点的自环边，
 *      所以用一个挂在主机下方的小方块"虚拟执行节点"来表达。
 * ============================================================ */

function renderChain(data) {
  const { chain, events } = data;

  /* ---------- 节点坐标（layout:'none' 手工布局） ----------
   * graph 有三种布局：force(力导)、circular(环形)、none(手工)。
   * 攻击链的方向性很强（左→右讲故事），力导布局每次刷新都不一样，
   * 演示效果不稳定，所以选 none + 固定坐标。
   * Office-PC 放低一档（y=290），让"横向移动"两条边在视觉上分叉。 */
  const LAYOUT_X = {
    "attacker": 80, "web-server": 310, "office-pc-01": 540,
    "core-server": 770, "c2-server": 980,
  };
  const LAYOUT_Y = { "attacker": 130, "web-server": 130, "office-pc-01": 290, "core-server": 130, "c2-server": 130 };

  const nodes = chain.nodes.map(n => ({
    id: n.id,                        // ECharts 内部引用用的 id（nodes/links 靠它连线）
    name: n.host ?? n.ip,            // 契约回退规则：有主机名显示主机名
    value: n,                        // 把原始节点数据塞进 value，tooltip/点击时取用
    x: LAYOUT_X[n.id] ?? 500,
    y: LAYOUT_Y[n.id] ?? 130,
    // 攻击者/红队节点画大一点突出；实体主机中等大小
    symbolSize: n.category === "attacker" ? 54 : n.category === "c2" ? 48 : 44,
    itemStyle: {
      color: n.category === "attacker" ? "#dc2626"   // 攻击者红
           : n.category === "c2" ? "#7f1d1d"          // C2 深红
           : "#2563eb",                                // 受害主机蓝
    },
    label: { show: true, position: "bottom", color: "#1f2937" }, // 名字标在节点下方
  }));

  /**
   * 边的公共样式。
   * 颜色 = 攻击阶段色（契约映射表）；label 显示步骤编号 [1]~[5]，
   * 和右侧卡片编号一一对应，答辩讲解时好指认。
   */
  function edgeStyle(color, i) {
    return {
      lineStyle: { color, width: 2.5, curveness: 0.1 }, // curveness 弧度，直线太生硬
      label: { show: true, formatter: `[${i + 1}]`, fontSize: 12, color, fontWeight: 700 },
      value: i,   // 记住这是第几条 link，tooltip 里回 chain.links 取详情
    };
  }

  /* ---------- 生成边 ----------
   * 按 host 匹配 chain.json 里的节点得到 ECharts 的 source/target id。
   * 找不到对应节点时直接用 host 字符串当 id（防御：数据缺节点不至于崩）。 */
  const edges = [];
  chain.links.forEach((l, i) => {
    const color = App.STAGE_COLORS[l.attack_stage] || "#64748b"; // 未知阶段兜底灰
    const srcNode = chain.nodes.find(n => n.host === l.source_host);
    const dstNode = chain.nodes.find(n => n.host === l.target_host);
    const srcId = srcNode ? srcNode.id : l.source_host;
    const dstId = dstNode ? dstNode.id : l.target_host;

    if (srcId === dstId) {
      /* "Web-Server → Web-Server 执行异常进程"：自环边画不出来，
       * 挂一个 roundRect 小节点在主机正下方（y + 190），
       * 用阶段色填充 + 白字，视觉上像"主机内部发生的事"。 */
      const execNodeId = `__exec_${i}`;
      const base = nodes.find(n => n.id === srcId);
      nodes.push({
        id: execNodeId, name: "异常进程执行\nrundll32 → mshta", value: { virtual: true },
        x: base.x, y: base.y + 190,
        symbol: "roundRect", symbolSize: [86, 30],   // symbolSize 传数组 = [宽, 高]
        itemStyle: { color },
        label: { show: true, position: "inside", color: "#fff", fontSize: 10 },
      });
      edges.push({ source: srcId, target: execNodeId, ...edgeStyle(color, i) });
    } else {
      edges.push({ source: srcId, target: dstId, ...edgeStyle(color, i) });
    }
  });

  /* ---------- 左侧：ECharts 关系图 ---------- */
  const chart = chartOrResize("chain-graph", dom => echarts.init(dom));
  chart.setOption({
    tooltip: {
      // formatter 支持函数：按数据类型（node/edge）返回不同 HTML
      formatter: p => {
        if (p.dataType === "edge") {
          const l = chain.links[p.data.value];   // value 存的是 link 下标
          if (!l) return "";
          return `<b>[${chain.links.indexOf(l) + 1}] ${App.esc(l.attack_stage)}</b><br>` +
            `${App.esc(l.source_host ?? l.source_ip)} → ${App.esc(l.target_host ?? l.target_ip)}<br>` +
            `${App.esc(l.mitre_technique)} · ${App.esc(App.fmtTime(l.timestamp))}<br>` +
            App.esc(l.description);
        }
        if (p.dataType === "node") {
          const n = p.data.value;
          if (n.virtual) return "本机执行环节：进程落地 + 远程下载";
          return `<b>${App.esc(n.host ?? n.ip)}</b><br>IP: ${App.esc(n.ip)}<br>角色: ${App.esc(n.role)}`;
        }
        return "";
      },
    },
    series: [{
      type: "graph",
      layout: "none",                  // 手工坐标（见文件头说明）
      roam: true,                      // 允许拖拽/滚轮缩放，答辩时可以拉近看
      edgeSymbol: ["none", "arrow"],   // 边两端符号：起点无、终点箭头 → 有向图
      edgeSymbolSize: 13,
      data: nodes,
      links: edges,
    }],
  });

  /* ---------- 右侧：攻击步骤卡片列表 ---------- */
  const linksBox = document.getElementById("chain-links");
  linksBox.innerHTML = chain.links.map((l, i) => {
    const color = App.STAGE_COLORS[l.attack_stage] || "#64748b";
    return `
      <div class="chain-link-item">
        <span class="stage" style="background:${color}">${App.esc(l.attack_stage)}</span>
        <span class="tid">${App.esc(l.mitre_technique)}</span>
        <div class="path">${App.esc(l.source_host ?? l.source_ip)} → ${App.esc(l.target_host ?? l.target_ip)}</div>
        <div class="muted">${App.esc(App.fmtTime(l.timestamp))} · ${App.esc(l.source_ip)} → ${App.esc(l.target_ip)}</div>
        <div class="desc">${App.esc(l.description)}</div>
      </div>`;
  }).join("");

  /* ---------- 节点点击：联动展示该节点相关证据事件 ----------
   * 匹配规则：host 同名 或 src_ip/dst_ip 等于节点 IP——
   * 因为主机侧事件（Sysmon）记 host，网络侧事件（PCAP）记 IP，
   * 两边都要兜住才能把"主机↔流量"证据串起来。 */
  const old = document.getElementById("node-events");
  if (old) old.remove();          // 重新渲染时清掉上次的联动面板
  chart.off("click");             // off 再 on，防止重复绑定
  chart.on("click", p => {
    if (p.dataType !== "node") return;
    const n = p.data.value;
    if (n.virtual) return;        // 虚拟执行节点没有对应主机，不联动

    const related = events.filter(e =>
      e.host === n.host || e.src_ip === n.ip || e.dst_ip === n.ip
    ).sort((a, b) => a.timestamp.localeCompare(b.timestamp));

    const box = document.createElement("div");
    box.id = "node-events";
    box.innerHTML = `
      <h3 style="margin:14px 0 8px">节点 ${App.esc(n.host ?? n.ip)} 相关事件（${related.length}）</h3>
      ${related.slice(0, 12).map(e => `
        <div class="chain-link-item" style="cursor:pointer" data-eid="${e.id}">
          <b>${App.esc(App.fmtTime(e.timestamp))}</b>
          <span class="chip">${App.esc(e.event_type)}</span>
          ${App.flagBadges(e.anomaly_flags)}
          <div class="desc">${App.esc(e.description)}</div>
        </div>`).join("")}
      ${related.length === 0 ? '<p class="muted">无相关事件</p>' : ""}
    `;
    /* 点击证据事件 → 打开详情弹窗。
     * data-eid 存事件 id——契约：前端定位事件一律用 id。 */
    box.querySelectorAll("[data-eid]").forEach(item =>
      item.addEventListener("click", () => App.openEventDetail(item.dataset.eid)));
    linksBox.parentNode.appendChild(box);
  });
}
