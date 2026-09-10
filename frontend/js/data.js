/* ============================================================
 * data.js — 数据管理页（2026-09-10 平台化需求，成员C/F）
 * 2026-09-10晚 修复：①多文件上传 ②已选文件清单可见 ③成功后清空
 * 文件选择（防止再点按钮重复上传）。
 * ============================================================ */

async function initDataManage() {
  await refreshBatchTable();
  document.getElementById("ingest-btn").addEventListener("click", runIngest);

  /* 已选文件清单：选择变化即渲染（名称/大小），让用户看清选了什么 */
  const filesInput = document.getElementById("ingest-files");
  filesInput.addEventListener("change", renderIngestFileList);

  /* 拖拽上传：把一个或多个文件直接拖到"导入新数据"卡片上（比文件对话框直观） */
  const zone = document.getElementById("ingest-card");
  if (zone) {
    ["dragenter", "dragover"].forEach(t => zone.addEventListener(t, e => {
      e.preventDefault();
      zone.classList.add("dragover");
    }));
    ["dragleave", "drop"].forEach(t => zone.addEventListener(t, e => {
      e.preventDefault();
      zone.classList.remove("dragover");
    }));
    zone.addEventListener("drop", e => {
      if (e.dataTransfer && e.dataTransfer.files.length) {
        filesInput.files = e.dataTransfer.files;
        filesInput.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }
}

function formatSize(bytes) {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + " GB";
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + " MB";
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + " KB";
  return bytes + " B";
}

function renderIngestFileList() {
  const input = document.getElementById("ingest-files");
  const box = document.getElementById("ingest-file-list");
  if (!input.files.length) {
    box.textContent = "未选择文件";
    return;
  }
  const names = [...input.files].map(f => `${f.name}（${formatSize(f.size)}）`);
  const total = [...input.files].reduce((s, f) => s + f.size, 0);
  box.textContent = `已选 ${input.files.length} 个文件（共 ${formatSize(total)}）：${names.join("、")}`;
}

function clearIngestFiles() {
  const input = document.getElementById("ingest-files");
  input.value = "";                       // 清空选择，防止再点按钮重复上传
  renderIngestFileList();
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
        `<button class="btn-ghost" onclick="selectBatch('${App.esc(b.case_id)}')">切换显示</button> ` +
        `<button class="btn-ghost" onclick="deleteBatch('${App.esc(b.case_id)}')">删除</button></td></tr>`
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
  if (!filesInput.files.length) { resultBox.innerHTML = '<p style="color:var(--anomaly)">请先选择数据文件（当前未选择）。</p>'; return; }

  const fd = new FormData();
  fd.append("case_id", caseId);
  for (const f of filesInput.files) fd.append("files", f);

  const btn = document.getElementById("ingest-btn");
  btn.disabled = true;
  btn.textContent = `上传解析中（${filesInput.files.length} 个文件）…`;
  resultBox.innerHTML = '<p class="muted">上传与解析中（大文件需要一点时间）…</p>';
  try {
    const resp = await fetchWithTimeout(`${API_BASE}/api/ingest`, 300000, { method: "POST", body: fd });
    const body = await resp.json();
    const rows = (body.per_file || []).map(pf =>
      `<tr><td>${App.esc(pf.file)}</td><td>${App.esc(pf.parser)}</td>` +
      `<td>${pf.error ? "失败" : pf.events + " 条"}</td>` +
      `<td>${App.esc(pf.error || "")}</td></tr>`).join("");
    resultBox.innerHTML =
      `<p>批次 <b>${App.esc(body.case_id)}</b> 导入完成：成功 ${body.imported} 条` +
      (body.failed ? `，解析失败 ${body.failed} 条` : "") + "</p>" +
      '<table class="kv"><tr><th>文件</th><th>解析器</th><th>事件数</th><th>说明</th></tr>' + rows + "</table>" +
      '<p class="muted">文件选择已清空——如需继续上传请重新选择文件（同名批次会追加）。</p>';
    clearIngestFiles();                    // 修复③：成功后清空，避免再点重复上传
    await refreshBatchTable();
    await fillCaseSelect();                // 页眉下拉同步
    setCaseId(body.case_id);               // 自动切到新批次视图
    App.fillCaseSelect();
  } catch (err) {
    resultBox.innerHTML = `<p style="color:var(--anomaly)">上传失败：${App.esc(err.message)}（文件选择保留，可直接重试）</p>`;
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

async function deleteBatch(caseId) {
  if (!confirm(`确定删除批次 ${caseId} 的全部事件？此操作不可恢复。`)) return;
  const resp = await fetch(`${API_BASE}/api/ingest/${encodeURIComponent(caseId)}`, { method: "DELETE" });
  if (resp.status === 404) { alert("批次不存在（可能已删除）"); }
  else if (!resp.ok) { alert(`删除失败：HTTP ${resp.status}`); }
  await refreshBatchTable();
  await fillCaseSelect();
  location.reload();              // 当前展示批次被删时，整页回退"全部数据"
}
