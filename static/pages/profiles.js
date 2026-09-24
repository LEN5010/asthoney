"use strict";
// 页面控制器：复用 app.js 的请求、布局与安全输出工具。
initLayout("profiles");

const profileRowsEl = document.getElementById("profileRows");
const profileCountEl = document.getElementById("profileCount");
const profileDetailEl = document.getElementById("profileDetail");
const detailMetaEl = document.getElementById("detailMeta");
const lastUpdatedEl = document.getElementById("lastUpdated");
let profiles = [];
let selectedIp = null;

function renderDetail(profile) {
  if (!profile) {
    detailMetaEl.textContent = "选择一个来源";
    profileDetailEl.innerHTML = '<div class="empty-state">点击左侧来源，查看为什么是这个分数。</div>';
    return;
  }
  const band = riskBandMeta(profile.risk_band);
  detailMetaEl.textContent = profile.source_ip;
  const components = (profile.score_components || []).map((item) => {
    const pct = item.max ? Math.round((item.score / item.max) * 100) : 0;
    return `
      <div class="score-row">
        <div class="score-row-head"><span>${escapeHtml(item.label)}</span><span class="mono">${item.score}/${item.max}</span></div>
        <div class="score-track"><div class="score-fill ${band.severity}" style="width:${pct}%;"></div></div>
      </div>
    `;
  }).join("");
  const techniques = (profile.techniques || []).map((item) => `<span class="chip"><span class="mono">${escapeHtml(item.id)}</span>&nbsp;${escapeHtml(item.name)}</span>`).join("");
  const hosts = (profile.visited_hosts || []).map((item) => `<span class="hop">${escapeHtml(item)}</span>`).join('<span class="arrow">→</span>');
  const sessionLink = (profile.session_ids || []).map((id) => `<a class="link-button small" href="/session/view?session_id=${encodeURIComponent(id)}">${escapeHtml(truncate(id, 22))}</a>`).join(" ");
  profileDetailEl.innerHTML = `
    <div class="analysis-kv"><div class="k">风险分</div><div class="v">${profile.risk_score} · ${severityPill(profile.risk_band)}</div></div>
    <div class="score-stack my-3">${components}</div>
    <div class="analysis-kv"><div class="k">访问主机</div><div class="v"><span class="path-flow">${hosts || "—"}</span></div></div>
    <div class="analysis-kv mt-2"><div class="k">映射技术</div><div class="v tag-row">${techniques || "—"}</div></div>
    <div class="footnote">${profile.likely_non_human ? "研判标记为疑似非真人 Agent。" : "未见自动化 Agent 特征。"} 隔离为模拟动作，不触碰真实网络。</div>
    <div class="mt-3">${sessionLink}</div>
  `;
}

let lastRenderKey = "";

function renderProfiles(items) {
  profiles = items;
  profileCountEl.textContent = `${items.length} 个画像`;
  document.getElementById("kpiTotal").textContent = String(items.length);
  document.getElementById("kpiQuarantined").textContent = String(items.filter((item) => item.quarantined).length);
  document.getElementById("kpiHigh").textContent = String(items.filter((item) => item.risk_band === "high" || item.risk_band === "critical").length);
  if (!items.length) {
    if (lastRenderKey !== "empty") {
      lastRenderKey = "empty";
      profileRowsEl.innerHTML = '<div class="empty-state">暂无画像。运行 scripts/demo_smoke.sh 后刷新。</div>';
      renderDetail(null);
    }
    return;
  }
  if (!selectedIp || !items.some((item) => item.source_ip === selectedIp)) {
    selectedIp = items[0].source_ip;
  }
  const renderKey = JSON.stringify(items) + "|" + selectedIp;
  if (renderKey === lastRenderKey) return;
  lastRenderKey = renderKey;
  profileRowsEl.innerHTML = items.map((item) => {
    const band = riskBandMeta(item.risk_band);
    const techniques = (item.techniques || []).slice(0, 3).map((row) => row.id).join(" ");
    const active = item.source_ip === selectedIp;
    return `
      <div class="table-row${active ? " is-selected" : ""}" data-ip="${escapeHtml(item.source_ip)}">
        <div data-label="来源">
          <div class="cell-main mono">${escapeHtml(item.source_ip)}</div>
          <div class="cell-sub">${item.likely_non_human ? "疑似自动化 Agent" : "人工/未判定"}</div>
        </div>
        <div data-label="风险">${severityPill(item.risk_band)} <span class="mono">${item.risk_score}</span></div>
        <div class="mono" data-label="会话">${item.sessions}</div>
        <div class="mono" data-label="命令">${item.command_count}</div>
        <div class="mono inline-meta" data-label="战术">${escapeHtml(techniques || "—")}</div>
        <div data-label="状态">${item.quarantined ? '<span class="pill serious">模拟隔离</span>' : '<span class="pill good">观察中</span>'}</div>
        <div data-label="操作"><button class="link-button" type="button" data-select="${escapeHtml(item.source_ip)}" aria-pressed="${active}">依据</button></div>
      </div>
    `;
  }).join("");
  profileRowsEl.querySelectorAll("[data-select]").forEach((button) => {
    button.addEventListener("click", () => {
      selectedIp = button.getAttribute("data-select");
      renderProfiles(profiles);
    });
  });
  renderDetail(items.find((item) => item.source_ip === selectedIp) || items[0]);
}

let refreshInFlight = false;
async function refresh() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const payload = await fetchJSON("/profiles");
    renderProfiles(payload.profiles || []);
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
