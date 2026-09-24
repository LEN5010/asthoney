"use strict";
// 页面控制器：复用 app.js 的请求、布局与安全输出工具。
initLayout("attack");
initTooltip(document.getElementById("matrix"));

const matrixEl = document.getElementById("matrix");
const matrixMetaEl = document.getElementById("matrixMeta");
const evidenceListEl = document.getElementById("evidenceList");
const evidenceMetaEl = document.getElementById("evidenceMeta");
const lastUpdatedEl = document.getElementById("lastUpdated");

let currentMatrix = {};
let selectedTechnique = "";
function renderMatrix(matrix) {
  currentMatrix = matrix;
  const scrollLeft = matrixEl.scrollLeft;
  const tactics = matrix.tactics || [];
  document.getElementById("kpiTactics").textContent = String(matrix.tactics_covered ?? 0);
  document.getElementById("kpiTacticsTotal").textContent = String(matrix.tactics_total ?? tactics.length);
  document.getElementById("kpiTechniques").textContent = String(matrix.technique_count ?? 0);
  document.getElementById("kpiHits").textContent = String(matrix.total_observations ?? 0);
  matrixMetaEl.textContent = `${matrix.tactics_covered ?? 0}/${matrix.tactics_total ?? 0} 战术有观测`;

  matrixEl.innerHTML = tactics.map((tactic) => {
    const cells = (tactic.techniques || []).length
      ? tactic.techniques.map((item) => {
          const hot = item.count >= 3 ? "is-hot" : "is-hit";
          const evidence = (item.evidence || []).join(" · ");
          const tipHtml = `<strong>${escapeHtml(item.id)} ${escapeHtml(item.name)}</strong><div class="tip-row"><span class="k">次数</span><span>${item.count}</span></div>${evidence ? `<div class="tip-row"><span class="k">证据</span><span>${escapeHtml(truncate(evidence, 120))}</span></div>` : ""}`;
          const tip = escapeHtml(tipHtml);
          return `
            <button type="button" class="technique-cell ${hot}" data-technique="${escapeHtml(item.id)}" aria-pressed="${selectedTechnique === item.id}" data-tip="${tip}">
              <span class="tid">${escapeHtml(item.id)}</span>
              <span class="tname">${escapeHtml(item.name)}</span>
              <span class="tcount">${item.count} 次</span>
            </button>
          `;
        }).join("")
      : '<div class="technique-empty">未观测</div>';
    return `
      <div class="tactic-col">
        <div class="tactic-head">${escapeHtml(tactic.name)}<span class="tid">${escapeHtml(tactic.id)} · ${tactic.total_hits || 0} 次</span></div>
        ${cells}
      </div>
    `;
  }).join("");

  matrixEl.scrollLeft = scrollLeft;
  const evidence = [];
  tactics.forEach((tactic) => {
    (tactic.techniques || []).forEach((item) => {
      if (selectedTechnique && item.id !== selectedTechnique) return;
      (item.evidence || []).forEach((row) => {
        evidence.push({ tactic: tactic.name, technique: `${item.id} ${item.name}`, text: row, count: item.count });
      });
    });
  });
  evidenceMetaEl.textContent = `${selectedTechnique || "全部技术"} · ${evidence.length} 条`;
  if (!evidence.length) {
    evidenceListEl.innerHTML = '<div class="empty-state">暂无证据。可运行 scripts/demo_smoke.sh 注入一条完整攻击链。</div>';
    return;
  }
  evidenceListEl.innerHTML = evidence.map((item) => `
    <article class="list-item">
      <div class="list-item-head">
        <strong>${escapeHtml(item.technique)}</strong>
        <span class="pill neutral">${item.count} 次</span>
      </div>
      <div class="inline-meta mt-1">${escapeHtml(item.tactic)} · <span class="mono">${escapeHtml(item.text)}</span></div>
    </article>
  `).join("");
}

let refreshInFlight = false;
async function refresh() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const payload = await fetchJSON("/attack/matrix");
    renderMatrix(payload);
    clearInlineError(document.querySelector(".panel-grid"));
    lastUpdatedEl.textContent = `最近刷新 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;
  } catch (error) {
    lastUpdatedEl.textContent = `刷新失败: ${error.message || error}`;
    showInlineError(document.querySelector(".panel-grid"), refresh);
  } finally {
    refreshInFlight = false;
  }
}

document.getElementById("refreshBtn").addEventListener("click", refresh);
refresh();
connectEventStream(debounce(refresh, 280));
startPolling(refresh, 8000);

matrixEl.addEventListener('click', (event) => {
  const cell = event.target.closest('[data-technique]');
  if (!cell) return;
  selectedTechnique = cell.dataset.technique;
  renderMatrix(currentMatrix);
  matrixEl.querySelector(`[data-technique="${CSS.escape(selectedTechnique)}"]`)?.focus({preventScroll: true});
});
document.getElementById('clearTechnique').addEventListener('click', () => {
  selectedTechnique = ''; renderMatrix(currentMatrix);
});
