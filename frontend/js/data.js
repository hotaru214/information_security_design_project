/* ============================================================
 * data.js — 数据管理页（2026-09-10 平台化需求，成员C/F）
 * ============================================================
 * 两个功能区：
 *   上区·导入：批次名 + 多文件上传 -> POST /api/ingest（后端自动
 *              嗅探格式并解析入库，事件打 case_id）
 *   下区·批次：GET /api/batches 清单 + 每批「开始分析」->
 *              GET /api/attack-chain?case_id= 展示 D 关联摘要
 * 页眉的下拉（app.js 渲染）与本页共用同一 case 口径。
 * ============================================================ */

async function initDataManage() {
  await refreshBatchTable();
  document.getElementById("ingest-btn").addEventListener("click", runIngest);
}

async function refreshBatchTable() {
  const box = document.getElementById("batch-table");
  try {
    const resp = await getBatches();
    const list = resp.batches || [];
    if (list.length === 0) {
      box.innerHTML = '<p class="muted">数据库为空——先在上方导入数据。</p>';
      return;
    }
    box.innerHTML =
      '<table class="kv"><tr><th>批次</th><th>事件数</th><th>告警数</th><th>时间范围</th><th>来源</th><th>操作</th></tr>' +
      list.map(b =>
        `<tr><td>${App.esc(b.case_id)}</td><td>${b.count}</td><td>${b.alert_count}</td>` +
        `<td>${App.esc((b.first_ts || "").slice(0, 19))} 起</td>` +
        `<td>${App.esc(Object.keys(b.sources || {}).join(", "))}</td>` +
        `<td><button class="btn-ghost" onclick="analyzeBatch('${App.esc(b.case_id)}')">开始分析</button> ` +
        `<button class="btn-ghost" onclick="selectBatch('${App.esc(b.case_id)}')">切换显示</button></td></tr>`
      ).join("") + "</table>";
  } catch (err) {
    box.innerHTML = `<p style="color:var(--anomaly)">批次清单加载失败：${App.esc(err.message)}（后端未启动？）</p>`;
  }
}

async function runIngest() {
  const caseInput = document.getElementById("ingest-case");
  const filesInput = document.getElementById("ingest-files");
  const resultBox = document.getElementById("ingest-result");
  const caseId = caseInput.value.trim();
  if (!caseId) { resultBox.innerHTML = '<p style="color:var(--anomaly)">请先填写批次名称（case_id）。</p>'; return; }
  if (!filesInput.files.length) { resultBox.innerHTML = '<p style="color:var(--anomaly)">请选择至少一个数据文件。</p>'; return; }

  const fd = new FormData();
  fd.append("case_id", caseId);
  for (const f of filesInput.files) fd.append("files", f);

  const btn = document.getElementById("ingest-btn");
  btn.disabled = true;
  btn.textContent = "上传解析中…";
  resultBox.innerHTML = '<p class="muted">上传与解析中（大文件需要一点时间）…</p>';
  try {
    const resp = await fetchWithTimeout(`${API_BASE}/api/ingest`, 120000, { method: "POST", body: fd });
    const body = await resp.json();
    const rows = (body.per_file || []).map(pf =>
      `<tr><td>${App.esc(pf.file)}</td><td>${App.esc(pf.parser)}</td>` +
      `<td>${pf.error ? "失败" : pf.events + " 条"}</td>` +
      `<td>${App.esc(pf.error || "")}</td></tr>`).join("");
    resultBox.innerHTML =
      `<p>批次 <b>${App.esc(body.case_id)}</b> 导入完成：成功 ${body.imported} 条` +
      (body.failed ? `，解析失败 ${body.failed} 条` : "") + "</p>" +
      '<table class="kv"><tr><th>文件</th><th>解析器</th><th>事件数</th><th>说明</th></tr>' + rows + "</table>" +
      `<p class="muted">页眉下拉已可切换到批次 ${App.esc(body.case_id)}。</p>`;
    await refreshBatchTable();
    await fillCaseSelect();       // 新批次进入页眉下拉
    setCaseId(body.case_id);      // 自动切到新批次视图
  } catch (err) {
    resultBox.innerHTML = `<p style="color:var(--anomaly)">上传失败：${App.esc(err.message)}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "上传并解析入库";
  }
}

async function analyzeBatch(caseId) {
  const box = document.getElementById("analyze-area");
  box.innerHTML = `<p class="muted">正在对批次 ${App.esc(caseId)} 运行 D 关联引擎（约 2~3 秒）…</p>`;
  try {
    const resp = await fetchWithTimeout(
      `${API_BASE}/api/attack-chain?case_id=${encodeURIComponent(caseId)}`, ATTACK_CHAIN_TIMEOUT_MS);
    const body = await resp.json();
    const steps = body.meta ? body.meta.step_count : (body.links || []).length;
    const stages = {};
    (body.links || []).forEach(l => { stages[l.attack_stage] = (stages[l.attack_stage] || 0) + 1; });
    const hosts = [...new Set((body.nodes || []).map(n => n.host || n.ip).filter(Boolean))];
    box.innerHTML =
      `<p>批次 <b>${App.esc(caseId)}</b>：${body.meta.event_count} 条事件 -> ` +
      `<b>${steps}</b> 个攻击步骤、${(body.nodes || []).length} 个节点</p>` +
      `<p>阶段分布：${Object.entries(stages).map(([s, c]) => `${App.esc(s)} x${c}`).join("，") || "（无）"}</p>` +
      `<p>涉及节点：${hosts.map(h => App.esc(h)).join("、") || "（无）"}</p>` +
      `<p class="muted">完整力导向图与证据穿透：切到「攻击链」标签（当前 case 选择已同步）。</p>`;
    setCaseId(caseId);            // 攻击链页读同一 case 口径
    App.fillCaseSelect();         // 页眉下拉同步选中项
  } catch (err) {
    box.innerHTML = `<p style="color:var(--anomaly)">分析失败：${App.esc(err.message)}</p>`;
  }
}

function selectBatch(caseId) {
  setCaseId(caseId);
  location.reload();              // 切批次后整页刷新，四个页面统一按新 case 过滤
}
