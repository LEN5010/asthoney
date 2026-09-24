"use strict";
// 页面控制器：复用 app.js 的请求、布局与安全输出工具。
initLayout("overview");
initTooltip(document.getElementById("graphCanvas"));

const els = {
  kpiConnections: document.getElementById("kpiConnections"),
  kpiAssets: document.getElementById("kpiAssets"),
  kpiJit: document.getElementById("kpiJit"),
  kpiAlerts: document.getElementById("kpiAlerts"),
  kpiCritical: document.getElementById("kpiCritical"),
  kpiTrap: document.getElementById("kpiTrap"),
  kpiQuarantine: document.getElementById("kpiQuarantine"),
  alertsList: document.getElementById("alertsList"),
  alertCount: document.getElementById("alertCount"),
  actionsList: document.getElementById("actionsList"),
  actionCount: document.getElementById("actionCount"),
  sessionRows: document.getElementById("sessionRows"),
  graphCanvas: document.getElementById("graphCanvas"),
  graphMeta: document.getElementById("graphMeta"),
  typeCounts: document.getElementById("typeCounts"),
  typeMeta: document.getElementById("typeMeta"),
  legend: document.getElementById("legend"),
  lastUpdated: document.getElementById("lastUpdated"),
  liveFeed: document.getElementById("liveFeed"),
  liveMeta: document.getElementById("liveMeta"),
  theaterRoles: document.getElementById("theaterRoles"),
  theaterRationale: document.getElementById("theaterRationale"),
  theaterStage: document.getElementById("theaterStage"),
  theaterBtn: document.getElementById("theaterBtn"),
  engagementList: document.getElementById("engagementList"),
  engagementMeta: document.getElementById("engagementMeta"),
};
const liveItems = [];
const graphHot = { assetId: "", fromId: "", toId: "" };
const THEATER_ROLES = [
  { role: "analyst", title: "意图分析" },
  { role: "planner", title: "欺骗规划" },
  { role: "actor", title: "终端仿真" },
  { role: "critic", title: "响应来源" },
];

function renderTheater(trace) {
  const steps = (trace && trace.steps) || [];
  const byRole = new Map(steps.map((step) => [step.role, step]));
  let current = "";
  steps.forEach((step) => { current = step.role; });
  els.theaterRoles.innerHTML = THEATER_ROLES.map((item) => {
    const step = byRole.get(item.role);
    const on = step ? " is-on" : "";
    const active = step && item.role === current ? " is-current" : "";
    const detail = step ? (step.detail || step.evidence || step.strategy || "") : "等待这一步";
    return `
      <div class="theater-role${on}${active}">
        <div class="role-kicker">${String(THEATER_ROLES.indexOf(item) + 1).padStart(2,"0")}</div>
        <div class="role-name">${escapeHtml(step ? step.title : item.title)}</div>
        <div class="role-detail" title="${escapeHtml(detail)}">${escapeHtml(truncate(detail, 32))}</div>
      </div>
    `;
  }).join("");
  const planner = byRole.get("planner");
  const command = trace && trace.raw_input ? trace.raw_input : "";
  if (planner) {
    const clue = planner.planted_clue ? ` 线索：${planner.planted_clue}` : "";
    els.theaterRationale.textContent = `${command ? command + " — " : ""}${planner.detail || ""}${clue}`;
  }
}

renderTheater(null);

function timelineToLiveEvent(item) {
  const kind = item.kind;
  let type = "session.activity";
  if (kind === "intent") type = "intent.detected";
  if (kind === "alert") type = "alert.raised";
  if (kind === "action") type = "action.executed";
  return {
    type,
    ts: item.created_at,
    data: {
      category: item.category,
      summary: item.detail || item.title,
      raw_input: item.raw_input,
      session_id: item.session_id,
      source: item.source_ip,
      alert_type: item.title,
      reason: typeof item.detail === "string" ? item.detail : item.title,
    },
  };
}

function replaceLiveItems(events, meta) {
  liveItems.length = 0;
  events.slice(0, 18).forEach((item) => liveItems.push(item));
  if (meta) els.liveMeta.textContent = meta;
  renderLive(false);
}

function pushLiveEvent(event) {
  if (event.type === "stream.ready") {
    const replay = ((event.data && event.data.replay) || []).filter((item) => item && item.type !== "stream.ready");
    const stage = [...replay].reverse().find((item) => item.type === "demo.stage");
    if (stage?.data?.done) { clearTimeout(demoRecovery); els.theaterBtn.disabled = false; }
    if (replay.length) {
      replaceLiveItems(replay.slice().reverse(), `已连接 · 回放 ${replay.length} 条`);
    } else {
      els.liveMeta.textContent = liveItems.length ? `已连接 · 图库 ${liveItems.length} 条` : "已连接 · 等待新事件";
    }
    return;
  }
  if (event.id && liveItems.some((item) => item.id === event.id)) return;
  liveItems.unshift(event);
  if (liveItems.length > 18) liveItems.pop();
  renderLive(true);
}

async function loadTimelineFeed() {
  if (liveItems.length) return;
  try {
    const payload = await fetchJSON("/timeline?limit=18");
    const events = (payload.timeline || []).map(timelineToLiveEvent);
    if (events.length) replaceLiveItems(events, `图库回放 ${events.length} 条`);
  } catch (error) {
    // 时间线只是实时流的回退，失败时保持空态即可。
  }
}

function renderLive(markFresh) {
  if (!liveItems.length) {
    els.liveFeed.innerHTML = '<div class="empty-state">等待诱捕事件。连接 2222 端口或运行 scripts/demo_smoke.sh 后，这里会逐条弹出。</div>';
    return;
  }
  const previousScroll = els.liveFeed.scrollTop;
  const previousHeight = els.liveFeed.scrollHeight;
  els.liveFeed.innerHTML = liveItems.map((event, index) => {
    const meta = eventMeta(event.type);
    return `
      <article class="live-item${markFresh && index === 0 ? " is-fresh" : ""}">
        <span class="live-dot ${meta.severity}"></span>
        <div>
          <div class="live-title">${escapeHtml(meta.label)}</div>
          <div class="live-summary">${escapeHtml(liveEventSummary(event))}</div>
        </div>
        <span class="timeline-time">${event.ts ? fmtTime(event.ts) : ""}</span>
      </article>
    `;
  }).join("");
  els.liveFeed.scrollTop = previousScroll > 0 && markFresh ? previousScroll + (els.liveFeed.scrollHeight - previousHeight) : previousScroll;
}

function alertDetailLine(alert) {
  const details = alert.details || {};
  const parts = [];
  if (details.tool_name) parts.push(`工具 <b class="mono">${escapeHtml(details.tool_name)}</b>`);
  if (details.category) parts.push(`意图 <b>${escapeHtml(intentMeta(details.category).label)}</b>`);
  if (details.session_id) parts.push(`会话 <b class="mono">${escapeHtml(truncate(details.session_id, 24))}</b>`);
  if (details.summary) parts.push(escapeHtml(truncate(details.summary, 60)));
  return parts.join(" · ");
}

function renderAlerts(alerts) {
  els.alertCount.textContent = `${alerts.length} 条`;
  els.kpiAlerts.textContent = String(alerts.length);
  els.kpiCritical.textContent = String(alerts.filter((a) => a.severity === "critical").length);
  if (!alerts.length) {
    els.alertsList.innerHTML = '<div class="empty-state">暂无告警</div>';
    return;
  }
  els.alertsList.innerHTML = alerts.slice(0, 8).map((alert) => `
    <article class="list-item">
      <div class="list-item-head">
        <strong>${escapeHtml(alertTypeLabel(alert.alert_type))}</strong>
        <span class="row-flex">
          ${severityPill(alert.severity)}
          <span class="timeline-time">${fmtTime(alert.created_at)}</span>
        </span>
      </div>
      <div class="inline-meta mt-1">来源 <b class="mono">${escapeHtml(alert.source || "unknown")}</b>${alertDetailLine(alert) ? " · " + alertDetailLine(alert) : ""}</div>
      <details class="raw-details">
        <summary>原始详情</summary>
        <div class="mono-block">${escapeHtml(JSON.stringify(alert.details || {}, null, 2))}</div>
      </details>
    </article>
  `).join("");
}

function renderActions(actions) {
  els.actionCount.textContent = `${actions.length} 条`;
  if (!actions.length) {
    els.actionsList.innerHTML = '<div class="empty-state">暂无隔离动作</div>';
    return;
  }
  els.actionsList.innerHTML = actions.slice(0, 5).map((action) => `
    <article class="list-item">
      <div class="list-item-head">
        <strong>模拟隔离 <span class="mono">${escapeHtml(action.source || "unknown")}</span></strong>
        <span class="timeline-time">${fmtTime(action.created_at)}</span>
      </div>
      <div class="inline-meta mt-1">${escapeHtml(action.reason || "")}</div>
    </article>
  `).join("");
}

const liveSelect = document.getElementById("liveSessionSelect");
const liveTerminal = document.getElementById("liveTerminal");
const liveLink = document.getElementById("liveSessionLink");
let observedSession = "";
let lastTerminalText = "";
let liveRequest = 0;
liveSelect.addEventListener("change", () => { renderEngagements(latestSessions); });
let latestSessions = [];
function renderEngagements(sessions) {
  latestSessions = sessions;
  const items = sessions.filter(s => s.protocol === "ssh" && !/^(theater-|demo-|sec-smoke)/.test(s.session_id));
  const selected = liveSelect.value;
  liveSelect.innerHTML = '<option value="">跟随最新 SSH</option>' + items.map(s =>
    `<option value="${escapeHtml(s.session_id)}">${escapeHtml(s.session_id.slice(0,8))} · ${escapeHtml(s.current_hostname || s.source_ip)}</option>`).join("");
  if (items.some(s => s.session_id === selected)) liveSelect.value = selected;
  const id = liveSelect.value || items.find(s => s.command_count > 0)?.session_id || items[0]?.session_id || "";
  if (id !== observedSession) {
    observedSession = id; lastTerminalText = "";
    renderTheater(null);
    els.theaterRationale.textContent = "";
    els.theaterStage.textContent = id ? "读取当前会话决策…" : "等待输入";
    liveTerminal.textContent = id ? "读取会话…" : "等待 Agent 接入并发送命令…";
  }
  els.engagementMeta.textContent = id ? id.slice(0,8) : "等待接入";
  liveLink.href = id ? `/session/view?session_id=${encodeURIComponent(id)}` : "/sessions/view";
  void refreshLiveTerminal();
}
async function refreshLiveTerminal() {
  const id = observedSession;
  if (!id) return;
  const request = ++liveRequest;
  try {
    const detail = await fetchJSON(`/sessions/${encodeURIComponent(id)}`);
    if (request !== liveRequest || id !== observedSession) return;
    const text = (detail.transcript || []).slice(-80).map(item =>
      item.direction === "attacker_to_maze" ? `$ ${item.payload}` : item.payload || "").join("\n");
    if (text === lastTerminalText) return;
    const atBottom = !lastTerminalText || liveTerminal.scrollHeight - liveTerminal.scrollTop - liveTerminal.clientHeight < 30;
    liveTerminal.textContent = text || "等待第一条命令…"; lastTerminalText = text;
    if (atBottom) liveTerminal.scrollTop = liveTerminal.scrollHeight;
    try {
      const decisions = await fetchJSON(`/sessions/${encodeURIComponent(id)}/decisions`);
      if (request !== liveRequest || id !== observedSession) return;
      const trace = decisions.decisions?.at(-1);
      renderTheater(trace || null);
      els.theaterStage.textContent = trace ? `SSH · ${id.slice(0,8)}` : "等待输入";
    } catch (error) {
      if (id === observedSession) els.theaterStage.textContent = "决策暂不可用";
    }
  } catch (error) { if (id === observedSession) liveTerminal.textContent = `会话读取失败：${error.message}`; }
}

function renderSessions(sessions) {
  if (!sessions.length) {
    els.sessionRows.innerHTML = '<div class="empty-state">暂无 SSH 会话</div>';
    return;
  }
  els.sessionRows.innerHTML = sessions.slice(0, 6).map((session) => {
    const hops = [session.entry_hostname, ...(session.visited_hosts || [])].filter(Boolean);
    const path = hops.length
      ? `<span class="path-flow">${hops.map((h) => `<span class="hop">${escapeHtml(truncate(h, 18))}</span>`).join('<span class="arrow">→</span>')}</span>`
      : '<span class="inline-meta">—</span>';
    return `
      <div class="table-row">
        <div data-label="会话">
          <div class="cell-main mono">${escapeHtml(truncate(session.session_id, 22))}</div>
          <div class="cell-sub">${escapeHtml(session.protocol || "ssh")} · ${escapeHtml(session.entry_hostname || session.entry_asset_id || "unknown")}</div>
        </div>
        <div class="mono" data-label="来源">${escapeHtml(session.source_ip || "unknown")}</div>
        <div class="mono" data-label="命令数">${escapeHtml(session.command_count ?? 0)}</div>
        <div data-label="攻击路径">${path}</div>
        <div class="inline-meta" data-label="最后活动">${timeAgo(session.last_seen)}</div>
        <div data-label="操作"><a class="link-button" href="/session/view?session_id=${encodeURIComponent(session.session_id)}">回放</a></div>
      </div>
    `;
  }).join("");
}

function renderTypeCounts(typeCounts, total) {
  const entries = Object.entries(typeCounts || {}).sort((a, b) => b[1] - a[1]);
  els.typeMeta.textContent = `${entries.length} 类`;
  if (!entries.length) {
    els.typeCounts.innerHTML = '<div class="empty-state">暂无资产分布</div>';
    return;
  }
  const max = Math.max(...entries.map(([, count]) => count));
  els.typeCounts.innerHTML = entries.map(([type, count]) => {
    const meta = assetTypeMeta(type);
    return `
      <div class="bar-row">
        <div class="bar-row-head">
          <span class="name"><span class="swatch" style="background:${meta.color};"></span>${escapeHtml(meta.label)}</span>
          <span class="value">${count}</span>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round((count / max) * 100)}%; background:${meta.color};"></div></div>
      </div>
    `;
  }).join("");
}

function isJit(asset) {
  const metadata = asset.metadata || {};
  return metadata.jit_synthesized === true || metadata.jit_synthesized === "true";
}

function nodeTip(asset) {
  const meta = assetTypeMeta(asset.asset_type);
  const lure = (asset.metadata || {}).lure;
  const rows = [
    `<strong>${escapeHtml(asset.hostname || asset.asset_id)}</strong>`,
    `<div class="tip-row"><span class="k">地址</span><span class="mono">${escapeHtml(asset.ip_address || "—")}</span></div>`,
    `<div class="tip-row"><span class="k">类型</span><span>${escapeHtml(meta.label)}</span></div>`,
    `<div class="tip-row"><span class="k">画像</span><span>${escapeHtml(asset.persona || "—")}</span></div>`,
  ];
  if (lure) rows.push(`<div class="tip-row"><span class="k">诱饵</span><span>${escapeHtml(lure)}</span></div>`);
  if (isJit(asset)) rows.push(`<div class="tip-row"><span class="k">来源</span><span>JIT 即时合成</span></div>`);
  return rows.join("");
}

function renderGraph(graph) {
  const assets = (graph.assets || []).slice().sort((a, b) => String(a.asset_id).localeCompare(String(b.asset_id)));
  const edges = graph.edges || [];
  els.graphMeta.textContent = `${assets.length} 资产 / ${edges.length} 路径 · JIT ${graph.jit_synthesized_assets ?? 0}`;
  if (!assets.length) {
    els.graphCanvas.innerHTML = "";
    return;
  }

  const columnTitles = ["入口网关", "预置资产", "JIT 合成", "扩展目标"];
  const columnX = [120, 372, 624, 876];
  const grouped = [[], [], [], []];
  assets.forEach((asset) => {
    const type = asset.asset_type || "";
    let index = 1;
    if (type === "edge_gateway") index = 0;
    else if (isJit(asset)) index = 2;
    else if (type === "oss_gateway" || type === "cloud_proxy") index = 3;
    grouped[index].push(asset);
  });

  const width = 1000;
  const rowGap = 84;
  const maxRows = Math.max(...grouped.map((group) => group.length), 1);
  const height = Math.max(420, 70 + maxRows * rowGap);
  const positions = new Map();
  grouped.forEach((group, columnIndex) => {
    const start = (height - (group.length - 1) * rowGap) / 2;
    group.forEach((asset, rowIndex) => {
      positions.set(asset.asset_id, {
        x: columnX[columnIndex],
        y: Math.round(group.length === 1 ? height / 2 + 10 : start + rowIndex * rowGap),
        asset,
      });
    });
  });

  const nodeW = 172;
  const nodeH = 52;
  const jitIds = new Set(assets.filter(isJit).map((asset) => asset.asset_id));

  const edgeMarks = edges.map((edge) => {
    const from = positions.get(edge.from_asset_id);
    const to = positions.get(edge.to_asset_id);
    if (!from || !to) return "";
    const jitEdge = jitIds.has(edge.to_asset_id);
    const hotEdge = graphHot.fromId && graphHot.toId && graphHot.fromId !== graphHot.toId
      && edge.from_asset_id === graphHot.fromId && edge.to_asset_id === graphHot.toId;
    const stroke = hotEdge ? "var(--accent)" : jitEdge ? "var(--cat-1)" : "var(--ink-3)";
    const dash = hotEdge ? "" : jitEdge ? 'stroke-dasharray="6 4"' : "";
    const hotClass = hotEdge ? ' class="hot-edge"' : "";
    let d;
    let midX;
    let midY;
    if (Math.abs(from.x - to.x) < 10) {
      const bend = 96;
      d = `M ${from.x + nodeW / 2} ${from.y} C ${from.x + nodeW / 2 + bend} ${from.y}, ${to.x + nodeW / 2 + bend} ${to.y}, ${to.x + nodeW / 2} ${to.y}`;
      midX = from.x + nodeW / 2 + bend * 0.78;
      midY = (from.y + to.y) / 2;
    } else {
      const [src, dst] = from.x < to.x ? [from, to] : [to, from];
      const x1 = src.x + nodeW / 2;
      const x2 = dst.x - nodeW / 2;
      const bend = (x2 - x1) * 0.45;
      const start = from.x < to.x ? [x1, src.y] : [x2, dst.y];
      const end = from.x < to.x ? [x2, dst.y] : [x1, src.y];
      const c1 = from.x < to.x ? [x1 + bend, src.y] : [x2 - bend, dst.y];
      const c2 = from.x < to.x ? [x2 - bend, dst.y] : [x1 + bend, src.y];
      d = `M ${start[0]} ${start[1]} C ${c1[0]} ${c1[1]}, ${c2[0]} ${c2[1]}, ${end[0]} ${end[1]}`;
      midX = (x1 + x2) / 2;
      midY = (src.y + dst.y) / 2;
    }
    const label = ""; // Edge details remain available in data; labels would overlap at desktop scale.
    return `<path d="${d}" fill="none" stroke="${stroke}" stroke-width="${hotEdge ? 2.4 : 1.6}" opacity="0.9" ${dash}${hotClass} marker-end="url(#arrowHead)"></path>${label}`;
  }).join("");

  const nodeMarks = Array.from(positions.values()).map(({ x, y, asset }) => {
    const meta = assetTypeMeta(asset.asset_type);
    const jit = isJit(asset);
    const hotNode = graphHot.assetId && asset.asset_id === graphHot.assetId;
    const ring = hotNode
      ? `<circle class="hot-ring" cx="${x}" cy="${y}" r="38" fill="none" stroke="${meta.color}" stroke-width="2"></circle>`
      : "";
    return `
      <g data-tip="${escapeHtml(nodeTip(asset))}" style="cursor: default;" tabindex="0">
        ${ring}
        <rect x="${x - nodeW / 2}" y="${y - nodeH / 2}" width="${nodeW}" height="${nodeH}" rx="9"
          style="fill: var(--surface-raised); stroke: ${meta.color}; stroke-width: 2;" ${jit ? 'stroke-dasharray="6 4"' : ""}></rect>
        <text x="${x}" y="${y - 4}" text-anchor="middle" font-size="14.5" font-weight="600" style="fill: var(--ink);">${escapeHtml(truncate(asset.hostname || asset.asset_id, 20))}</text>
        <text x="${x}" y="${y + 14}" text-anchor="middle" font-size="12" style="fill: var(--ink-3);">${escapeHtml(truncate(asset.ip_address || "", 18))} · ${escapeHtml(meta.label)}</text>
      </g>
    `;
  }).join("");

  const headers = columnTitles.map((title, index) =>
    `<text x="${columnX[index]}" y="30" text-anchor="middle" font-size="11" letter-spacing="2" style="fill: var(--ink-3);">${title}</text>`
  ).join("");
  const rails = columnX.slice(0, -1).map((x, i) =>
    `<line x1="${(x + columnX[i + 1]) / 2}" y1="46" x2="${(x + columnX[i + 1]) / 2}" y2="${height - 16}" stroke="var(--grid)" stroke-width="1" stroke-dasharray="2 6"></line>`
  ).join("");

  els.graphCanvas.setAttribute("viewBox", `0 0 ${width} ${height}`);
  els.graphCanvas.innerHTML = `
    <defs>
      <marker id="arrowHead" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
        <path d="M0,1 L8,4.5 L0,8" fill="none" stroke="var(--ink-3)" stroke-width="1.4"></path>
      </marker>
    </defs>
    ${rails}
    ${headers}
    ${edgeMarks}
    ${nodeMarks}
  `;

  const presentTypes = [...new Set(assets.map((asset) => asset.asset_type))];
  els.legend.innerHTML = presentTypes.map((type) => {
    const meta = assetTypeMeta(type);
    return `<div class="legend-item"><span class="legend-swatch" style="background:${meta.color};"></span>${escapeHtml(meta.label)}</div>`;
  }).join("") + '<div class="legend-item jit"><span class="legend-swatch"></span>JIT 即时合成</div>';
}

// Refresh panels independently: retain last-good content and mark only failed panels.
let refreshInFlight = false;
let latestAssetCount = 0;
const renderKeys = new Map();
function changed(key, payload, render) {
  const fingerprint = JSON.stringify(payload);
  if (renderKeys.get(key) === fingerprint) return;
  render(payload); renderKeys.set(key, fingerprint);
}
async function refresh() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  let failed = 0;
  const tasks = [
    ["/status", ".kpi-row", (status) => {
      latestAssetCount = status.honeypot_assets ?? 0;
      els.kpiConnections.textContent = String(status.active_connections ?? 0);
      els.kpiAssets.textContent = String(latestAssetCount);
      els.kpiTrap.textContent = String(status.mcp_trap_hits ?? 0);
      els.kpiQuarantine.textContent = String(status.quarantined_sources ?? 0);
    }],
    ["/alerts", ".alerts-panel", (data) => changed("alerts", data.alerts || [], renderAlerts)],
    ["/actions", "#actionsList", (data) => changed("actions", data.actions || [], renderActions)],
    ["/sessions", ".engagement-panel", (data) => {
      changed("sessions", data.sessions || [], renderSessions);
      renderEngagements(data.sessions || []);
    }],
    ["/graph/overview", ".topology-panel", (graph) => {
      els.kpiJit.textContent = String(graph.jit_synthesized_assets ?? 0);
      changed("graph", {graph, hot: {...graphHot}}, ({graph}) => renderGraph(graph));
      changed("types", graph.type_counts || {}, (types) => renderTypeCounts(types, (graph.assets || []).length));
    }],
  ];
  try {
    await Promise.all(tasks.map(async ([url, selector, render]) => {
      const container = document.querySelector(selector);
      try { render(await fetchJSON(url)); clearInlineError(container); }
      catch (error) { failed++; showInlineError(container, refresh); }
    }));
    els.lastUpdated.textContent = `${failed ? "部分数据未更新 · " : "同步于 "}${new Date().toLocaleTimeString("zh-CN", {hour12:false})}`;
  } finally { refreshInFlight = false; }
}

let demoRecovery = null;
const scheduleRefresh = debounce(refresh, 280);
document.getElementById("refreshBtn").addEventListener("click", refresh);
document.getElementById("resetDemoBtn").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const accepted = await appDialog({ title: "重置演示", message: "将断开当前 SSH/TCP 连接、停止备用剧本，清空会话、告警、画像和动态资产，恢复初始拓扑。模型配置保持不变。", confirm: "确认重置", danger: true });
  if (!accepted) return;
  button.disabled = true;
  button.textContent = "重置中…";
  try {
    const result = await fetchJSON("/history/purge", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({confirm: true}) });
    if (!result.ok) throw new Error(result.message || "重置失败");
    window.location.reload();
  } catch (error) {
    toast(error.message || "重置失败");
    button.disabled = false;
    button.textContent = "重置演示";
  }
});
els.theaterBtn.addEventListener("click", async () => {
  if (els.theaterBtn.disabled) return;
  els.theaterBtn.disabled = true;
  clearTimeout(demoRecovery);
  demoRecovery = setTimeout(() => { els.theaterBtn.disabled = false; toast("演示状态确认超时，可刷新数据后重试；服务端会阻止重复运行。"); }, 180000);
  els.theaterStage.textContent = "正在注入演示序列…";
  try {
    const result = await fetchJSON("/demo/theater", { method: "POST" });
    els.theaterStage.textContent = `注入中 · ${result.session_id}`;
  } catch (error) {
    clearTimeout(demoRecovery);
    els.theaterBtn.disabled = false;
    els.theaterStage.textContent = `注入失败: ${error.message || error}`;
  }
});
refresh();
loadTimelineFeed();
connectEventStream((event) => {
  pushLiveEvent(event);
  if (event.type === "terminal.output") {
    scheduleRefresh();
    return;
  }
  if (event.type === "agent.trace") {
    const data = event.data || {};
    if (data.session_id !== observedSession) { scheduleRefresh(); return; }
    graphHot.assetId = data.to_asset_id || data.asset_id || graphHot.assetId;
    graphHot.fromId = data.from_asset_id || "";
    graphHot.toId = data.to_asset_id || "";
    renderTheater(data);
    els.theaterStage.textContent = `SSH · ${(data.session_id || "").slice(0,8)}`;
    scheduleRefresh();
    return;
  }
  if (event.type === "demo.stage") {
    const data = event.data || {};
    if (data.done) {
      clearTimeout(demoRecovery);
      els.theaterBtn.disabled = false;
      const sessionId = data.session_id || "";
      els.theaterStage.innerHTML = sessionId
        ? `${escapeHtml(data.stage || "演示结束")} · <a href="/session/view?session_id=${encodeURIComponent(sessionId)}">打开会话解释</a>`
        : escapeHtml(data.stage || "演示结束");
    } else {
      els.theaterStage.textContent = `${data.stage || "播放中"}${data.payload ? " · " + data.payload : ""}`;
    }
    scheduleRefresh();
    return;
  }
  if (event.type !== "stream.ready") scheduleRefresh();
}, { onState: (state) => { els.liveMeta.textContent = state === "connected" ? "实时流已连接" : state === "reconnecting" ? "连接中断 · 正在重连" : "连接中…"; } });
startPolling(refresh, 8000);
