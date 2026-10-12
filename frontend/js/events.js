async function loadEvents() {
  if (!requireLogin()) return;
  document.getElementById("shell").innerHTML =
    navHtml("events") +
    `<main class="main">
      <div class="topbar">
        <div class="page-heading">
          <h1>Events</h1>
          <p class="lede">Collected process and file events stored in MySQL.</p>
        </div>
      </div>
      <section class="panel">
        <div class="panel-head">
          <h3>Event log</h3>
          <span class="meta">up to 100</span>
        </div>
        <div class="panel-body">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Type</th><th>Exe</th><th>PID</th><th>PPID</th>
                <th>State</th><th>CPU%</th><th>Mem MB</th><th>Risk</th><th>Time</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
      </section>
    </main>`;

  const data = await api("/events?limit=100");
  document.getElementById("rows").innerHTML = (data.events || []).map(e => `
    <tr>
      <td>${e.eid}</td><td>${e.etype}</td><td>${e.exe_name || "-"}</td>
      <td>${e.pid ?? "-"}</td><td>${e.ppid ?? "-"}</td><td>${e.proc_state || "-"}</td>
      <td>${e.cpu_pct ?? "-"}</td><td>${e.mem_mb ?? "-"}</td>
      <td>${riskBadge(e.risk_lvl)}</td><td>${e.ts || ""}</td>
    </tr>`).join("") || `<tr><td class="empty" colspan="10">No events collected yet.</td></tr>`;
}
loadEvents();
