// shared helpers
const API = "/api";

function getToken() {
  return localStorage.getItem("cs_token");
}

function setToken(t) {
  localStorage.setItem("cs_token", t);
}

function clearToken() {
  localStorage.removeItem("cs_token");
  localStorage.removeItem("cs_uname");
}

function requireLogin() {
  if (!getToken()) {
    window.location.href = "/login";
    return false;
  }
  return true;
}

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;

  const res = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (res.status === 401) {
    clearToken();
    window.location.href = "/login";
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "request failed");
  return data;
}

function riskBadge(lvl) {
  if (!lvl) return "-";
  const cls =
    lvl === "High Risk" ? "badge-high" :
    lvl === "Suspicious" ? "badge-suspicious" : "badge-normal";
  return `<span class="badge ${cls}">${lvl}</span>`;
}

function logout() {
  clearToken();
  window.location.href = "/login";
}

function icon(name) {
  const common = 'xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75" aria-hidden="true"';
  const paths = {
    home: '<path stroke-linecap="round" stroke-linejoin="round" d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1v-9.5z"/>',
    events: '<path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h10M4 18h14"/>',
    threats: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 3 4 6v6c0 4.5 3.2 8.2 8 9 4.8-.8 8-4.5 8-9V6l-8-3z"/><path stroke-linecap="round" d="M12 9v4M12 16h.01"/>',
    inv: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2m-6 9 2 2 4-4"/>',
    audit: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l2.5 2.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/>',
  };
  return `<svg ${common}>${paths[name] || ""}</svg>`;
}

function navHtml(active) {
  const uname = localStorage.getItem("cs_uname") || "admin";
  const items = [
    { id: "home", href: "/", label: "Overview", icon: "home" },
    { id: "events", href: "/events", label: "Events", icon: "events" },
    { id: "threats", href: "/threats", label: "Threats", icon: "threats" },
    { id: "inv", href: "/investigations", label: "Cases", icon: "inv" },
    { id: "audit", href: "/audit", label: "Audit", icon: "audit" },
  ];
  const links = items.map((item) => `
    <a href="${item.href}" class="nav-link ${active === item.id ? "active" : ""}">
      ${icon(item.icon)}
      <span class="nav-label">${item.label}</span>
    </a>`).join("");

  return `
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">Cyber<span>Shield</span></div>
      <div class="brand-sub">Ops console</div>
    </div>
    <nav aria-label="Primary">${links}</nav>
    <div class="sidebar-foot">
      <div class="user-chip">
        <span class="user-dot" aria-hidden="true"></span>
        <span class="user-name">${uname}</span>
      </div>
      <button type="button" class="btn btn-ghost" onclick="logout()">Sign out</button>
    </div>
  </aside>`;
}
