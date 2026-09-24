"use strict";
// 页面控制器：复用 app.js 的请求、布局与安全输出工具。
initLayout("sessions");

const params = new URLSearchParams(window.location.search);
const sessionId = params.get("session_id");
const sessionMetaEl = document.getElementById("sessionMeta");
const sessionChipsEl = document.getElementById("sessionChips");
const terminalScreenEl = document.getElementById("terminalScreen");
const replayMetaEl = document.getElementById("replayMeta");
const replayProgressEl = document.getElementById("replayProgress");
const analysisCardEl = document.getElementById("analysisCard");
const analysisSourceEl = document.getElementById("analysisSource");
const intentListEl = document.getElementById("intentList");
const intentMetaEl = document.getElementById("intentMeta");
const decisionListEl = document.getElementById("decisionList");
const decisionMetaEl = document.getElementById("decisionMeta");
const worldCardEl = document.getElementById("worldCard");
const worldMetaEl = document.getElementById("worldMeta");
const revealWorldBtn = document.getElementById("revealWorldBtn");
const controlsResultEl = document.getElementById("controlsResult");
const playBtn = document.getElementById("playBtn");
const pauseBtn = document.getElementById("pauseBtn");
const stepBtn = document.getElementById("stepBtn");
const resetBtn = document.getElementById("resetBtn");
const reanalyzeBtn = document.getElementById("reanalyzeBtn");
const controlsBtn = document.getElementById("controlsBtn");
const speedButtons = document.querySelectorAll("[data-speed]");

let transcript = [];
let decisions = [];
let replayIndex = 0;
let renderedReplayIndex = 0;
let replayTimer = null;
let replaySpeed = 700;

function buildTerminalLine(item) {
  const meta = `<div class="terminal-line meta">${fmtTime(item.created_at)} · ${escapeHtml(item.hostname || "unknown")}</div>`;
  if (item.direction === "attacker_to_maze") {
    return `${meta}<div class="terminal-line prompt">${escapeHtml(item.prompt || "$ ")}<span class="cmd">${escapeHtml(item.payload || "")}</span></div>`;
  }
  const outputLine = item.payload ? `<div class="terminal-line output">${escapeHtml(item.payload)}</div>` : "";
  return `${meta}${outputLine}`;
}

function updateReplayMeta() {
  replayMetaEl.textContent = `${replayIndex}/${transcript.length} 事件`;
  const pct = transcript.length ? Math.round((replayIndex / transcript.length) * 100) : 0;
  replayProgressEl.style.width = `${pct}%`;
}

function renderReplayFrame() {
  if (!transcript.length) {
    terminalScreenEl.innerHTML = '<div class="empty-state">暂无对话数据</div>';
    return;
  }
  if (replayIndex < renderedReplayIndex) {
    terminalScreenEl.innerHTML = '<div class="empty-state replay-placeholder">点击播放或单步，查看攻击者输入与蜜罐响应。</div>';
    renderedReplayIndex = 0;
  }
  if (replayIndex === 0) {
    terminalScreenEl.innerHTML = '<div class="empty-state replay-placeholder">点击播放或单步，查看攻击者输入与蜜罐响应。</div>';
    renderedReplayIndex = 0;
    renderDecisions();
    return;
  }
  const items = transcript.slice(renderedReplayIndex, replayIndex);
  if (items.length) {
    terminalScreenEl.querySelector(".replay-placeholder")?.remove();
    terminalScreenEl.insertAdjacentHTML("beforeend", items.map(buildTerminalLine).join(""));
    terminalScreenEl.scrollTop = terminalScreenEl.scrollHeight;
  }
  renderedReplayIndex = replayIndex;
  renderDecisions();
}

function activeDecisionIndex() {
  const seen = transcript.slice(0, replayIndex).filter((item) => item.direction === "attacker_to_maze").length;
  return seen - 1;
}

function renderDecisions() {
  decisionMetaEl.textContent = `${decisions.length} 条`;
  if (!decisions.length) {
    decisionListEl.innerHTML = '<div class="empty-state">这条会话还没有决策轨迹</div>';
    return;
  }
  const active = activeDecisionIndex();
  decisionListEl.innerHTML = decisions.map((decision, index) => {
    const steps = decision.steps || [];
    const lines = steps.map((step) => `<div class="role-line"><b>${escapeHtml(step.title || step.role || "")}</b> ${escapeHtml(step.detail || "")}</div>`).join("");
    return `
      <article class="decision-item${index === active ? " is-active" : ""}">
        <div class="timeline-head">
          <strong class="mono">${escapeHtml(truncate(decision.raw_input || "空输入", 42))}</strong>
          <span class="timeline-time">${escapeHtml(decision.strategy || "")}</span>
        </div>
        ${lines}
      </article>
    `;
  }).join("");
  const current = decisionListEl.querySelector(".is-active");
  if (current && !decisionListEl.closest("[hidden]")) {
    const top = current.offsetTop - decisionListEl.offsetTop;
    if (top < decisionListEl.scrollTop || top + current.offsetHeight > decisionListEl.scrollTop + decisionListEl.clientHeight) decisionListEl.scrollTop = top;
  }
}

function stopReplay() {
  if (replayTimer) {
    clearInterval(replayTimer);
    replayTimer = null;
  }
}

function stepReplay() {
  if (replayIndex >= transcript.length) {
    stopReplay();
    return;
  }
  replayIndex += 1;
  renderReplayFrame();
  updateReplayMeta();
}

function startReplay() {
  stopReplay();
  replayTimer = setInterval(() => {
    if (replayIndex >= transcript.length) {
      stopReplay();
      return;
    }
    stepReplay();
  }, replaySpeed);
}

function resetReplay() {
  stopReplay();
  replayIndex = 0;
  renderedReplayIndex = 0;
  updateReplayMeta();
  renderReplayFrame();
}

playBtn.addEventListener("click", startReplay);
pauseBtn.addEventListener("click", stopReplay);
stepBtn.addEventListener("click", stepReplay);
resetBtn.addEventListener("click", resetReplay);
speedButtons.forEach((button) => {
  button.addEventListener("click", () => {
    replaySpeed = Number(button.getAttribute("data-speed")) || 700;
    speedButtons.forEach((item) => item.classList.toggle("is-active", item === button));
    if (replayTimer) startReplay();
  });
});

function renderAnalysis(analysis) {
  const source = analysis.analysis_source || "unknown";
  analysisSourceEl.textContent = source === "dashscope" ? "大模型研判" : source === "heuristic" ? "启发式研判" : source;
  analysisSourceEl.className = `pill ${source === "dashscope" ? "good" : "warning"}`;
  const confidence = Math.round((Number(analysis.confidence) || 0) * 100);
  const techniques = (analysis.techniques || []).map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("");
  const reasons = (analysis.likely_non_human_reasons || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const actions = (analysis.suggested_actions || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  analysisCardEl.innerHTML = `
    <div class="analysis-kv"><div class="k">结论摘要</div><div class="v">${escapeHtml(analysis.summary || "暂无结论")}</div></div>
    <div class="analysis-kv"><div class="k">攻击目的</div><div class="v">${escapeHtml(analysis.objective || "未知")}</div></div>
    ${analysis.threat_score != null ? `<div class="analysis-kv"><div class="k">可解释风险分</div><div class="v">${escapeHtml(String(analysis.threat_score))} · ${severityPill(analysis.threat_band || analysis.risk_level)}</div></div>` : ""}
    <div class="analysis-kv">
      <div class="k">风险与置信度</div>
      <div class="v row-flex">
        ${severityPill(analysis.risk_level)}
        <span class="row-flex">
          <span class="confidence-track mt-0"><span class="confidence-fill" style="display:block; width:${confidence}%;"></span></span>
          <span class="timeline-time">${confidence}%</span>
        </span>
      </div>
    </div>
    <div class="analysis-kv">
      <div class="k">非真人 Agent 判定</div>
      <div class="v">
        <span class="pill ${analysis.likely_non_human_test_agent ? "critical" : "good"}">${analysis.likely_non_human_test_agent ? "疑似自动化 Agent" : "未见 Agent 特征"}</span>
        ${reasons ? `<ul class="action-list mt-2">${reasons}</ul>` : ""}
      </div>
    </div>
    ${techniques ? `<div class="analysis-kv"><div class="k">战术手段</div><div class="v tag-row">${techniques}</div></div>` : ""}
    ${actions ? `<div class="analysis-kv"><div class="k">处置建议</div><ul class="action-list">${actions}</ul></div>` : ""}
  `;
}

function renderIntents(intents) {
  intentMetaEl.textContent = `${intents.length} 条`;
  if (!intents.length) {
    intentListEl.innerHTML = '<div class="empty-state">暂无意图数据</div>';
    return;
  }
  intentListEl.innerHTML = intents.map((intent) => {
    const meta = intentMeta(intent.category);
    const confidence = Math.round((Number(intent.confidence) || 0) * 100);
    return `
      <div class="timeline-item ${meta.severity}">
        <div class="timeline-head">
          <strong>${escapeHtml(meta.label)}</strong>
          <span class="timeline-time">${fmtTime(intent.created_at)}</span>
        </div>
        <div class="timeline-body">
          <span class="mono">${escapeHtml(truncate(intent.raw_input || "", 46))}</span><br>
          ${escapeHtml(intent.summary || "")}
          <div class="confidence-track"><div class="confidence-fill" style="width:${confidence}%;"></div></div>
        </div>
      </div>
    `;
  }).join("");
}

function renderWorld(world) {
  if (!world || world.available === false) {
    worldMetaEl.textContent = "无快照";
    revealWorldBtn.hidden = true;
    worldCardEl.innerHTML = `<div class="empty-state">${escapeHtml(world && world.reason ? world.reason : "这条连接已经结束，世界没有留在内存里。")}</div>`;
    return;
  }
  const sourceLabel = world.source === "live" ? "在线" : "快照";
  const hosts = Array.isArray(world.hosts) ? world.hosts : [];
  worldMetaEl.textContent = `${sourceLabel} · ${world.hostname || "host"} · ${world.cwd || "/"}`;
  revealWorldBtn.hidden = false;
  const created = new Set(world.created || []);
  const planted = new Set(world.planted || []);
  const files = (world.files || []).slice(0, 12).map((file) => {
    const mark = created.has(file.path) ? "新建" : planted.has(file.path) ? "规划写入" : "模板";
    return `<div class="role-line"><b class="mono">${escapeHtml(file.path)}</b> · ${mark}<br>${escapeHtml(truncate(file.preview || "", 90))}</div>`;
  }).join("");
  const hostLine = hosts.map((host) => {
    const current = host.asset_id && host.asset_id === world.active_asset_id ? "（当前）" : "";
    return `${host.hostname || host.asset_id || "host"}${current}`;
  }).join("、");
  worldCardEl.innerHTML = `
    <div class="analysis-kv"><div class="k">当前目录</div><div class="v mono">${escapeHtml(world.cwd || "/")}</div></div>
    <div class="analysis-kv"><div class="k">身份</div><div class="v">${escapeHtml(world.username || "svc-backup")} @ ${escapeHtml(world.hostname || "")} · ${escapeHtml(world.asset_type || "")}</div></div>
    ${hostLine ? `<div class="analysis-kv"><div class="k">到过的主机</div><div class="v">${escapeHtml(hostLine)}</div></div>` : ""}
    <div class="decision-list">${files || '<div class="empty-state">这台主机还没有可读文件</div>'}</div>
  `;
}

async function loadWorld() {
  try {
    renderWorld(await fetchJSON(`/sessions/${encodeURIComponent(sessionId)}/world`));
  } catch (error) {
    worldMetaEl.textContent = "失败";
    worldCardEl.textContent = `世界加载失败: ${error.message}`;
  }
}
revealWorldBtn.addEventListener("click", loadWorld);

async function loadDecisions() {
  try {
    const payload = await fetchJSON(`/sessions/${encodeURIComponent(sessionId)}/decisions`);
    decisions = payload.decisions || [];
    renderDecisions();
  } catch (error) {
    decisionListEl.innerHTML = `<div class="empty-state">决策轨迹加载失败: ${escapeHtml(String(error.message || error))}</div>`;
  }
}

async function loadAnalysis() {
  if (reanalyzeBtn.disabled) return;
  reanalyzeBtn.disabled = true;
  analysisSourceEl.textContent = "研判中…";
  analysisSourceEl.className = "pill neutral";
  try {
    const analysis = await fetchJSON(`/sessions/${encodeURIComponent(sessionId)}/analysis`);
    renderAnalysis(analysis);
  } catch (error) {
    analysisSourceEl.textContent = "失败";
    analysisCardEl.innerHTML = `<div class="empty-state">攻击研判加载失败: ${escapeHtml(String(error.message || error))}</div>`;
  } finally { reanalyzeBtn.disabled = false; }
}

reanalyzeBtn.addEventListener("click", loadAnalysis);

controlsBtn.addEventListener("click", async () => {
  controlsBtn.disabled = true;
  controlsResultEl.textContent = "联动控制执行中…";
  try {
    const result = await fetchJSON(`/sessions/${encodeURIComponent(sessionId)}/analysis/controls`, { method: "POST" });
    const alerts = (result.alerts || []).length;
    const actions = (result.actions || []).length;
    controlsResultEl.textContent = alerts || actions
      ? `联动完成：新增告警 ${alerts} 条、模拟隔离动作 ${actions} 条。`
      : "联动完成：本次研判未达到触发条件，或该会话已处理过。";
  } catch (error) {
    controlsResultEl.textContent = `联动失败: ${error.message || error}`;
  } finally {
    controlsBtn.disabled = false;
  }
});

async function loadSession() {
  if (!sessionId) {
    sessionMetaEl.textContent = "缺少 session_id 参数";
    sessionChipsEl.innerHTML = '请从 <a href="/sessions/view">会话列表</a> 选择一条会话进入回放。';
    terminalScreenEl.innerHTML = '<div class="empty-state">缺少 session_id 参数，没有可回放的数据</div>';
    analysisCardEl.innerHTML = '<div class="empty-state">缺少会话，无法研判</div>';
    analysisSourceEl.textContent = "不可用";
    [playBtn, pauseBtn, stepBtn, resetBtn, reanalyzeBtn, controlsBtn, revealWorldBtn].forEach((btn) => {
      btn.disabled = true;
    });
    return;
  }
  try {
    const detail = await fetchJSON(`/sessions/${encodeURIComponent(sessionId)}`);
    const session = detail.session || {};
    let previousPrompt = "$ ";
    transcript = (detail.transcript || []).map((item) => {
      if (item.direction === "attacker_to_maze") return { ...item, prompt: previousPrompt };
      if (item.prompt) previousPrompt = item.prompt;
      return item;
    });
    sessionMetaEl.textContent = truncate(session.session_id || "unknown", 36);
    sessionChipsEl.innerHTML = `
      <span class="tag-row">
        <span class="chip">${sessionLabel(session.session_id)}</span>
      <span class="chip">会话 <span class="mono">&nbsp;${escapeHtml(truncate(session.session_id || "unknown", 26))}</span></span>
        <span class="chip">来源 <span class="mono">&nbsp;${escapeHtml(session.source_ip || "unknown")}</span></span>
        <span class="chip">入口 <span class="mono">&nbsp;${escapeHtml(session.entry_hostname || session.entry_asset_id || "unknown")}</span></span>
        <span class="chip">始于 ${fmtTime(session.created_at)}</span>
        <span class="chip">${transcript.length} 个事件</span>
      </span>
    `;
    updateReplayMeta();
    renderReplayFrame();
    renderIntents(detail.intents || []);
    void loadDecisions();
    void loadWorld();

  } catch (error) {
    sessionMetaEl.textContent = `加载失败: ${error.message || error}`;
    terminalScreenEl.innerHTML = `<div class="empty-state">会话加载失败: ${escapeHtml(String(error.message || error))}</div>`;
    analysisCardEl.innerHTML = '<div class="empty-state">会话不可用，无法研判</div>';
    analysisSourceEl.textContent = "失败";
    [playBtn, pauseBtn, stepBtn, resetBtn, reanalyzeBtn, controlsBtn, revealWorldBtn].forEach((btn) => { btn.disabled = true; });
  }
}

loadSession();
connectEventStream(event => {
  if (event.type === "terminal.output" && event.data?.session_id === sessionId) void loadSession();
});

// Inspector tabs preserve loaded data and expose a complete keyboard interaction.
const inspectorTabs = [...document.querySelectorAll('[role="tab"]')];
function selectInspector(index) {
  inspectorTabs.forEach((tab, i) => {
    tab.setAttribute('aria-selected', String(i === index));
    tab.tabIndex = i === index ? 0 : -1;
    document.getElementById(tab.getAttribute('aria-controls')).hidden = i !== index;
  });
}
inspectorTabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectInspector(index));
  tab.addEventListener('keydown', (event) => {
    let next = index;
    if (event.key === 'ArrowRight') next = (index + 1) % inspectorTabs.length;
    else if (event.key === 'ArrowLeft') next = (index + inspectorTabs.length - 1) % inspectorTabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = inspectorTabs.length - 1;
    else return;
    event.preventDefault(); selectInspector(next); inspectorTabs[next].focus();
  });
});
