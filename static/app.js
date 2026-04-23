function initLayout(activePath) {
  const appShell = document.querySelector(".app-shell");
  const toggle = document.querySelector("[data-sidebar-toggle]");
  const navLinks = document.querySelectorAll("[data-nav]");
  navLinks.forEach((link) => {
    if (link.getAttribute("data-nav") === activePath) {
      link.classList.add("is-active");
    }
  });
  if (toggle && appShell) {
    toggle.addEventListener("click", () => {
      appShell.classList.toggle("sidebar-open");
    });
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}

function severityClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "danger";
  if (normalized === "medium") return "warning";
  return "success";
}
