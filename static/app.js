/* ASTHONEY 前端共享层：布局、标签映射、格式化、悬浮提示、请求工具 */

/** Local, dependency-free navigation marks. */
function navIcon(name) {
  const paths = {
    overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    sessions: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 9 3 3-3 3m6 0h5"/>',
    attack: '<path d="M4 4h16v16H4zM4 9h16M4 14h16M9 4v16M14 4v16"/>',
    profiles: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
    docs: '<path d="M5 2h9l5 5v15H5zM14 2v6h5M8 12h8M8 16h8"/>',
  };
  return `<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.docs}</svg>`;
}

/** Native dialog provides focus trapping and Escape cancellation without browser prompts. */
function appDialog({ title, message, confirm = "确认", danger = false }) {
  return new Promise((resolve) => {
    const dialog = document.createElement("dialog");
    dialog.className = "app-dialog";
    dialog.innerHTML = `<form method="dialog"><h2>${escapeHtml(title)}</h2>
      <p>${escapeHtml(message)}</p><div class="dialog-actions">
      <button class="button" value="cancel">取消</button>
      <button class="button ${danger ? "danger-ghost" : "primary"}" value="confirm">${escapeHtml(confirm)}</button></div></form>`;
    document.body.append(dialog);
    const previous = document.activeElement;
    dialog.addEventListener("close", () => {
      const confirmed = dialog.returnValue === "confirm";
      dialog.remove(); previous?.focus(); resolve(confirmed);
    }, { once: true });
    dialog.showModal();
  });
}

function toast(message) {
  document.querySelector(".toast")?.remove();
  const node = document.createElement("div");
  node.className = "toast";
  node.setAttribute("role", "status");
  node.textContent = message;
  document.body.append(node);
  window.setTimeout(() => node.remove(), 4500);
}

/** Reserved IDs from the built-in rehearsal scripts are labelled, not mistaken for live traffic. */
function sessionLabel(id) {
  return /^(theater-|demo-|sec-smoke-|acceptance-)/.test(String(id || "")) ? "演示 / 测试" : "诱捕会话";
}

/* ---------- 资产类型（分类色，固定槽位，颜色跟随实体） ---------- */
const ASSET_TYPE_META = {
  edge_gateway: { label: "边缘网关", color: "var(--cat-1)" },
  linux_server: { label: "Linux 服务器", color: "var(--cat-2)" },
  database_server: { label: "数据库服务器", color: "var(--cat-3)" },
  oss_gateway: { label: "OSS 网关", color: "var(--cat-4)" },
  secret_store: { label: "密钥存储", color: "var(--cat-5)" },
  cloud_proxy: { label: "云代理", color: "var(--cat-6)" },
  file_server: { label: "文件服务器", color: "var(--cat-7)" },
};

function assetTypeMeta(type) {
  return ASSET_TYPE_META[type] || { label: type || "未知类型", color: "var(--ink-3)" };
}

/* ---------- 意图类别（严重度与后端 _intent_severity 一致） ---------- */
const INTENT_META = {
  lateral_movement: { label: "横向移动", severity: "critical" },
  credential_access: { label: "凭证获取", severity: "critical" },
  tool_transfer: { label: "工具投递", severity: "serious" },
  cloud_recon: { label: "云面侦察", severity: "serious" },
  collection: { label: "数据收集", severity: "serious" },
  discovery: { label: "环境探测", severity: "warning" },
  interactive_shell: { label: "交互命令", severity: "warning" },
  web_probe: { label: "Web 探测", severity: "good" },
  generic_probe: { label: "一般探测", severity: "good" },
  idle: { label: "空闲", severity: "good" },
};

function intentMeta(category) {
  return INTENT_META[category] || { label: category || "未知", severity: "neutral" };
}

const ALERT_TYPE_LABELS = {
  agent_oriented_mcp_trap: "MCP 逻辑诱饵命中",
  high_risk_intent_detected: "高危意图检测",
  suspected_non_human_test_agent: "疑似非真人 Agent",
};

function alertTypeLabel(type) {
  return ALERT_TYPE_LABELS[type] || type || "未知告警";
}

function severityClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "serious";
  if (normalized === "medium") return "warning";
  if (normalized === "low") return "good";
  return "neutral";
}

function severityPill(value) {
  const label = { critical: "严重", high: "高危", medium: "中危", low: "低危" }[String(value).toLowerCase()] || value || "未知";
  return `<span class="pill ${severityClass(value)}">${escapeHtml(label)}</span>`;
}

/* ---------- 基础工具 ---------- */
function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function truncate(value, max) {
  const text = String(value ?? "");
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/* Neo4j 时间戳带 9 位小数，先裁剪到毫秒再解析 */
function parseTs(value) {
  if (!value) return null;
  const trimmed = String(value).replace(/\.(\d{3})\d+/, ".$1");
  const date = new Date(trimmed);
  return Number.isNaN(date.getTime()) ? null : date;
}

function fmtTime(value) {
  const date = parseTs(value);
  if (!date) return "—";
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function timeAgo(value) {
  const date = parseTs(value);
  if (!date) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}

async function fetchJSON(url, options) {
  const resp = await fetch(url, options);
  const payload = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(payload.detail || payload.message || `HTTP ${resp.status}`);
  }
  return payload;
}

/* ---------- 导航 ---------- */
const NAV_ITEMS = [
  { id: "overview", href: "/", label: "总体态势", icon: "overview", badge: "Graph" },
  { id: "sessions", href: "/sessions/view", label: "SSH 会话", icon: "sessions", badge: "Replay" },
  { id: "attack", href: "/attack/view", label: "攻击矩阵", icon: "attack", badge: "ATT&CK" },
  { id: "profiles", href: "/profiles/view", label: "攻击者画像", icon: "profiles", badge: "Risk" },
  { id: "docs", href: "/docs", label: "API 文档", icon: "docs", badge: "OpenAPI" },
];

function renderNav(activePath) {
  const list = document.querySelector(".nav-list");
  if (!list) return;
  list.innerHTML = NAV_ITEMS.map((item) => `
    <a class="nav-link${item.id === activePath ? " is-active" : ""}" data-nav="${item.id}" href="${item.href}">
      ${navIcon(item.icon)}<span>${item.label}</span><span class="nav-badge">${item.badge}</span>
    </a>
  `).join("");
}

const EVENT_META = {
  "session.activity": { label: "会话活动", severity: "warning" },
  "intent.detected": { label: "意图检出", severity: "serious" },
  "alert.raised": { label: "告警产生", severity: "critical" },
  "action.executed": { label: "模拟隔离", severity: "serious" },
  "history.purged": { label: "历史清空", severity: "warning" },
  "stream.ready": { label: "事件流就绪", severity: "good" },
  "agent.trace": { label: "智能体轨迹", severity: "good" },
  "demo.stage": { label: "答辩阶段", severity: "warning" },
};

function eventMeta(type) {
  return EVENT_META[type] || { label: type || "事件", severity: "neutral" };
}

function liveEventSummary(event) {
  const data = event.data || {};
  if (event.type === "stream.ready") {
    return `回放缓冲 ${((data.replay || []).length)} 条 · 订阅者 ${data.subscribers ?? 0}`;
  }
  if (event.type === "intent.detected") {
    return `${intentMeta(data.category).label} · ${truncate(data.raw_input || data.summary || "", 48)}`;
  }
  if (event.type === "alert.raised") {
    return `${alertTypeLabel(data.alert_type)} · ${data.source || "unknown"}`;
  }
  if (event.type === "action.executed") {
    return `隔离 ${data.source || "unknown"} · ${truncate(data.reason || "", 40)}`;
  }
  if (event.type === "session.activity") {
    const prefix = data.is_new_session ? "新会话" : "命令";
    return `${prefix} ${truncate(data.session_id || "", 18)} · ${truncate(data.payload || "", 40)}`;
  }
  if (event.type === "history.purged") return "会话、告警与 JIT 资产已清空";
  if (event.type === "agent.trace") {
    const planner = (data.steps || []).find((step) => step.role === "planner");
    return `${truncate(data.raw_input || "", 24)} · ${truncate((planner && planner.detail) || data.strategy || "", 42)}`;
  }
  if (event.type === "demo.stage") return `${data.stage || "阶段"} · ${truncate(data.payload || "", 40)}`;
  return truncate(JSON.stringify(data), 80);
}

function connectEventStream(onEvent, options = {}) {
  const ignoreHeartbeat = options.ignoreHeartbeat !== false;
  const reportState = (state) => { document.documentElement.dataset.stream = state; options.onState?.(state); };
  let reconnectTimer = null;
  const HEARTBEAT_TIMEOUT = 40000;
  let socket = null;
  let stopped = false;
  let delay = 800;
  let heartbeatTimer = null;

  const clearHeartbeat = () => {
    if (heartbeatTimer) {
      window.clearTimeout(heartbeatTimer);
      heartbeatTimer = null;
    }
  };
  const armHeartbeat = () => {
    clearHeartbeat();
    heartbeatTimer = window.setTimeout(() => {
      if (socket) socket.close();
    }, HEARTBEAT_TIMEOUT);
  };

  const connect = () => {
    if (stopped) return;
    reportState("connecting");
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const next = new WebSocket(`${protocol}://${window.location.host}/ws/events`);
    socket = next;
    next.onopen = () => { delay = 800; armHeartbeat(); reportState("connected"); };
    next.onmessage = (message) => {
      armHeartbeat();
      let event;
      try {
        event = JSON.parse(message.data);
      } catch (error) {
        return;
      }
      if (ignoreHeartbeat && event.type === "stream.heartbeat") return;
      if (event.type === "history.purged") {
        // Discard panel caches and selections, including in other open tabs.
        window.setTimeout(() => window.location.reload(), 200);
        return;
      }
      onEvent(event);
    };
    next.onerror = () => { next.close(); };
    next.onclose = () => {
      clearHeartbeat();
      if (socket === next) socket = null;
      if (stopped) return;
      reportState("reconnecting");
      reconnectTimer = window.setTimeout(connect, delay);
      delay = Math.min(delay * 1.6, 8000);
    };
  };
  connect();
  return () => {
    stopped = true;
    window.clearTimeout(reconnectTimer);
    clearHeartbeat();
    if (socket) socket.close();
  };
}

function debounce(fn, wait) {
  let timer = null;
  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), wait);
  };
}

/* ---------- 轮询：页面隐藏时暂停，在飞请求不重叠 ---------- */
function startPolling(fn, interval) {
  let inFlight = false;
  const tick = async () => {
    if (document.hidden || inFlight) return;
    inFlight = true;
    try {
      await fn();
    } finally {
      inFlight = false;
    }
  };
  tick();
  const timer = window.setInterval(tick, interval);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) tick();
  });
  return () => window.clearInterval(timer);
}

/* ---------- 内联错误条（带重试） ---------- */
function showInlineError(container, onRetry) {
  if (!container) return;
  if (container.querySelector(":scope > .error-bar")) return;
  const bar = document.createElement("div");
  bar.className = "error-bar";
  const text = document.createElement("span");
  text.textContent = "数据加载失败，请检查控制面连接。";
  const retry = document.createElement("button");
  retry.className = "link-button small";
  retry.type = "button";
  retry.textContent = "重试";
  retry.addEventListener("click", () => {
    bar.remove();
    onRetry();
  });
  bar.append(text, retry);
  container.prepend(bar);
}

function clearInlineError(container) {
  const bar = container && container.querySelector(":scope > .error-bar");
  if (bar) bar.remove();
}

function riskBandMeta(band) {
  const normalized = String(band || "low").toLowerCase();
  if (normalized === "critical") return { label: "严重", severity: "critical" };
  if (normalized === "high") return { label: "高危", severity: "serious" };
  if (normalized === "medium") return { label: "中危", severity: "warning" };
  return { label: "低危", severity: "good" };
}

/* ---------- 布局与侧栏状态 ---------- */
function initLayout(activePath) {
  document.documentElement.removeAttribute("data-theme");
  localStorage.removeItem("theme");
  const appShell = document.querySelector(".app-shell");
  const toggle = document.querySelector("[data-sidebar-toggle]");
  const sidebar = document.querySelector(".sidebar");
  renderNav(activePath);
  document.querySelectorAll("[data-nav]").forEach((link) => {
    if (link.getAttribute("data-nav") === activePath) link.classList.add("is-active");
  });
  if (toggle && appShell) {
    toggle.setAttribute("aria-expanded", "false");
    const setOpen = (open) => {
      appShell.classList.toggle("sidebar-open", open);
      toggle.setAttribute("aria-expanded", String(open));
    };
    toggle.addEventListener("click", () => setOpen(!appShell.classList.contains("sidebar-open")));
    const mask = document.createElement("div");
    mask.className = "sidebar-mask";
    mask.addEventListener("click", () => setOpen(false));
    appShell.appendChild(mask);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && appShell.classList.contains("sidebar-open")) setOpen(false);
    });
  }
  const shellStatusEl = document.getElementById("shellStatus");
  const healthDotEl = document.getElementById("healthDot");
  if (shellStatusEl || healthDotEl) {
    const refreshShell = async () => {
      try {
        const [health, status] = await Promise.all([fetchJSON("/healthz"), fetchJSON("/status")]);
        if (healthDotEl) {
          healthDotEl.className = `health-dot ${health.status === "ok" ? "ok" : "degraded"}`;
          healthDotEl.textContent = health.status === "ok" ? "系统正常" : "运行降级";
        }
        if (shellStatusEl) {
          const listeners = (health.listeners || []).map((item) => item.port).join(" / ") || "—";
          shellStatusEl.innerHTML = `
            <div class="shell-status-row"><span>图数据库</span><span class="value">${health.graph_db ? "在线" : "离线"}</span></div>
            <div class="shell-status-row"><span>诱捕端口</span><span class="value">${escapeHtml(listeners)}</span></div>
            <div class="shell-status-row"><span>大模型接口</span><span class="value">${status.dashscope_configured ? "已配置" : "降级模式"}</span></div>
            <div class="shell-status-row"><span>陷阱命中</span><span class="value">${status.mcp_trap_hits ?? 0}</span></div>
            <div class="shell-status-row"><span>隔离来源</span><span class="value">${status.quarantined_sources ?? 0}</span></div>
          `;
        }
      } catch (error) {
        if (healthDotEl) {
          healthDotEl.className = "health-dot degraded";
          healthDotEl.textContent = "控制面不可达";
        }
      }
    };
    startPolling(refreshShell, 10000);
  }
}

/* ---------- 悬浮提示（拓扑节点等） ---------- */
function initTooltip(container) {
  let tip = document.querySelector(".viz-tooltip");
  if (!tip) {
    tip = document.createElement("div");
    tip.className = "viz-tooltip";
    document.body.appendChild(tip);
  }
  const move = (event) => {
    const pad = 14;
    const rect = tip.getBoundingClientRect();
    let x = event.clientX + pad;
    let y = event.clientY + pad;
    if (x + rect.width > window.innerWidth - 8) x = event.clientX - rect.width - pad;
    if (y + rect.height > window.innerHeight - 8) y = event.clientY - rect.height - pad;
    tip.style.left = `${x}px`;
    tip.style.top = `${y}px`;
  };
  container.addEventListener("pointerover", (event) => {
    const target = event.target.closest("[data-tip]");
    if (!target || !container.contains(target)) return;
    tip.innerHTML = target.getAttribute("data-tip");
    tip.style.display = "block";
    move(event);
  });
  container.addEventListener("pointermove", (event) => {
    if (tip.style.display === "block") move(event);
  });
  container.addEventListener("pointerout", (event) => {
    const target = event.target.closest("[data-tip]");
    if (target) tip.style.display = "none";
  });
  container.addEventListener("focusin", (event) => {
    const target = event.target.closest("[data-tip]");
    if (!target || !container.contains(target)) return;
    tip.innerHTML = target.getAttribute("data-tip");
    tip.style.display = "block";
    const rect = target.getBoundingClientRect();
    move({ clientX: rect.left + rect.width / 2, clientY: rect.bottom });
  });
  container.addEventListener("focusout", (event) => {
    const target = event.target.closest("[data-tip]");
    if (target) tip.style.display = "none";
  });
}
