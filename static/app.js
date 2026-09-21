/* ASTHONEY 前端共享层：布局、标签映射、格式化、悬浮提示、鉴权请求 */

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
  return `<span class="pill ${severityClass(value)}">${escapeHtml(value || "unknown")}</span>`;
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

/* ---------- 控制面鉴权请求（SR-02） ---------- */
async function adminFetch(url, options = {}) {
  let token = localStorage.getItem("adminToken") || "";
  if (!token) {
    const input = window.prompt("请输入控制面管理令牌（X-Admin-Token）", "");
    if (input === null) throw new Error("已取消：需要管理令牌");
    token = input.trim();
    localStorage.setItem("adminToken", token);
  }
  const headers = { ...(options.headers || {}), "X-Admin-Token": token };
  const resp = await fetch(url, { ...options, headers });
  const payload = await resp.json().catch(() => ({}));
  if (resp.status === 401) {
    localStorage.removeItem("adminToken");
    throw new Error("令牌无效，请重试");
  }
  if (!resp.ok) {
    throw new Error(payload.detail || payload.message || `HTTP ${resp.status}`);
  }
  return payload;
}

/* ---------- 导航 ---------- */
const NAV_ITEMS = [
  { id: "overview", href: "/", label: "总体态势", badge: "Graph" },
  { id: "sessions", href: "/sessions/view", label: "SSH 会话", badge: "Replay" },
  { id: "attack", href: "/attack/view", label: "攻击矩阵", badge: "ATT&CK" },
  { id: "profiles", href: "/profiles/view", label: "攻击者画像", badge: "Risk" },
  { id: "docs", href: "/docs", label: "API 文档", badge: "OpenAPI" },
];

function renderNav(activePath) {
  const list = document.querySelector(".nav-list");
  if (!list) return;
  list.innerHTML = NAV_ITEMS.map((item) => `
    <a class="nav-link${item.id === activePath ? " is-active" : ""}" data-nav="${item.id}" href="${item.href}">
      <span>${item.label}</span><span class="nav-badge">${item.badge}</span>
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
  let socket = null;
  let stopped = false;
  let delay = 800;

  const connect = () => {
    if (stopped) return;
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${protocol}://${window.location.host}/ws/events`);
    socket.onopen = () => { delay = 800; };
    socket.onmessage = (message) => {
      let event;
      try {
        event = JSON.parse(message.data);
      } catch (error) {
        return;
      }
      if (ignoreHeartbeat && event.type === "stream.heartbeat") return;
      onEvent(event);
    };
    socket.onclose = () => {
      if (stopped) return;
      window.setTimeout(connect, delay);
      delay = Math.min(delay * 1.6, 8000);
    };
  };
  connect();
  return () => {
    stopped = true;
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

function riskBandMeta(band) {
  const normalized = String(band || "low").toLowerCase();
  if (normalized === "critical") return { label: "严重", severity: "critical" };
  if (normalized === "high") return { label: "高危", severity: "serious" };
  if (normalized === "medium") return { label: "中危", severity: "warning" };
  return { label: "低危", severity: "good" };
}

/* ---------- 布局与侧栏状态 ---------- */
function initLayout(activePath) {
  const appShell = document.querySelector(".app-shell");
  const toggle = document.querySelector("[data-sidebar-toggle]");
  renderNav(activePath);
  document.querySelectorAll("[data-nav]").forEach((link) => {
    if (link.getAttribute("data-nav") === activePath) link.classList.add("is-active");
  });
  if (toggle && appShell) {
    toggle.addEventListener("click", () => appShell.classList.toggle("sidebar-open"));
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
    refreshShell();
    setInterval(refreshShell, 10000);
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
}
