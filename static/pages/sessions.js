"use strict";
// 页面控制器：复用 app.js 的请求、布局与安全输出工具。
initLayout("sessions");

const sessionRowsEl = document.getElementById("sessionRows");
const sessionCountEl = document.getElementById("sessionCount");
const lastUpdatedEl = document.getElementById("lastUpdated");
const purgeHistoryBtn = document.getElementById("purgeHistoryBtn");

let loadedSessions = [];
let lastRowsKey = "";

function renderSessions(sessions) {
  loadedSessions = sessions;
  const query = document.getElementById("sessionSearch").value.trim().toLowerCase();
  const sort = document.getElementById("sessionSort").value;
  sessions = sessions.filter((row) => `${row.session_id} ${row.source_ip}`.toLowerCase().includes(query)).slice();
  sessions.sort((a, b) => sort === "commands" ? (b.command_count || 0) - (a.command_count || 0) : sort === "source" ? String(a.source_ip).localeCompare(String(b.source_ip), "en", {numeric: true}) : (parseTs(b.last_seen)?.getTime() || 0) - (parseTs(a.last_seen)?.getTime() || 0));
  sessionCountEl.textContent = `${sessions.length} / ${loadedSessions.length} 条会话`;
  const key = JSON.stringify(sessions);
  if (lastRowsKey === key) return;
  lastRowsKey = key;
  if (!sessions.length) {
    sessionRowsEl.innerHTML = '<div class="empty-state">没有匹配的会话。可调整搜索条件，或从总体态势运行演示链。</div>';
    return;
  }
  sessionRowsEl.innerHTML = sessions.map((session) => {
    const hops = [session.entry_hostname, ...(session.visited_hosts || [])].filter(Boolean);
    const path = hops.length
      ? `<span class="path-flow">${hops.map((h) => `<span class="hop">${escapeHtml(truncate(h, 16))}</span>`).join('<span class="arrow">→</span>')}</span>`
      : '<span class="inline-meta">—</span>';
    return `
      <div class="table-row">
        <div data-label="会话">
          <div class="cell-main mono">${escapeHtml(truncate(session.session_id, 24))}</div>
          <div class="cell-sub">${sessionLabel(session.session_id)} · ${escapeHtml(session.protocol || "ssh")} · 始于 ${fmtTime(session.created_at)}</div>
        </div>
        <div class="mono" data-label="来源">${escapeHtml(session.source_ip || "unknown")}</div>
        <div class="mono" data-label="命令数">${escapeHtml(session.command_count ?? 0)}</div>
        <div data-label="攻击路径">${path}</div>
        <div class="mono inline-meta" data-label="最近命令" title="${escapeHtml(session.last_payload || "")}">${escapeHtml(truncate(session.last_payload || "—", 30))}</div>
        <div class="inline-meta" data-label="最后活动">${timeAgo(session.last_seen)}</div>
        <div data-label="操作"><a class="link-button" href="/session/view?session_id=${encodeURIComponent(session.session_id)}">回放</a></div>
      </div>
    `;
  }).join("");
}

let refreshInFlight = false;
async function refresh() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const payload = await fetchJSON("/sessions");
    renderSessions(payload.sessions || []);
    clearInlineError(document.querySelector(".panel-grid"));
    lastUpdatedEl.textContent = `最近刷新 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;
  } catch (error) {
    lastUpdatedEl.textContent = `刷新失败: ${error.message || error}`;
    showInlineError(document.querySelector(".panel-grid"), refresh);
  } finally {
    refreshInFlight = false;
  }
}

purgeHistoryBtn.addEventListener("click", async () => {
  const accepted = await appDialog({ title: "清空历史记录", message: "将断开当前连接并停止剧本，删除会话、告警、处置记录和动态资产，恢复初始拓扑。配置保留，此操作不可撤销。", confirm: "确认清空", danger: true });
  if (!accepted) return;
  purgeHistoryBtn.disabled = true;
  purgeHistoryBtn.textContent = "清理中…";
  try {
    const payload = await fetchJSON("/history/purge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    });
    if (!payload.ok) throw new Error(payload.message || "清理失败");
    await refresh();
    toast("历史记录已清空");
    lastUpdatedEl.textContent = `历史已清空 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`;
  } catch (error) {
    lastUpdatedEl.textContent = `清理失败: ${error.message || error}`;
  } finally {
    purgeHistoryBtn.disabled = false;
    purgeHistoryBtn.textContent = "清空历史";
  }
});

refresh();
startPolling(refresh, 5000);

document.getElementById("sessionSearch").addEventListener("input", () => renderSessions(loadedSessions));
document.getElementById("sessionSort").addEventListener("change", () => renderSessions(loadedSessions));
document.getElementById("refreshBtn").addEventListener("click", refresh);
