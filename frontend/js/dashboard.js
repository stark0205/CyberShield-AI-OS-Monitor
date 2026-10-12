async function loadDashboard() {
  if (!requireLogin()) return;
  document.getElementById("shell").innerHTML =
    navHtml("home") +
    `<main class="main">
      <div class="topbar">
        <div class="page-heading">
          <h1>Overview</h1>
          <p class="lede">Live process events and AI risk labels from the OS monitor pipeline.</p>
        </div>
        <div class="toolbar">
          <div class="field-inline">
            <label for="collectSource">Collect source</label>
            <select id="collectSource" class="select">
              <option value="sample">Sample JSON</option>
              <option value="c">C live monitor</option>
              <option value="python">Python (psutil)</option>
            </select>
          </div>
          <button type="button" class="btn" id="btnCollect">Collect events</button>
        </div>
      </div>
      <section class="risk-board" id="cards" aria-label="Risk summary"></section>
      <section class="panel">
        <div class="panel-head">
          <h3>Recent events</h3>
          <span class="meta" id="eventsMeta">last 15</span>
        </div>
        <div class="panel-body">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Type</th><th>Exe</th><th>State</th>
                <th>CPU%</th><th>Mem</th><th>Risk</th><th>Time</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
      </section>
    </main>`;

  document.getElementById("btnCollect").onclick = async () => {
    const source = document.getElementById("collectSource").value;
    const btn = document.getElementById("btnCollect");
    btn.disabled = true;
    btn.textContent = "Collecting…";
    try {
      await api(`/collect?source=${encodeURIComponent(source)}`, { method: "POST" });
      await refresh();
    } finally {
      btn.disabled = false;
      btn.textContent = "Collect events";
    }
  };

  await refresh();
}

async function refresh() {
  const summary = await api("/threats/summary");
  const stats = await api("/events/stats");
  const high = summary["High Risk"] ?? 0;
  document.getElementById("cards").innerHTML = `
    <div class="risk-hero">
      <div class="eyebrow">High risk</div>
      <div class="value">${high}</div>
      <p class="hint">Alerts that need investigation before they age out of the queue.</p>
    </div>
    <div class="metrics-rail">
      <div class="metric">
        <span class="label">Events</span>
        <span class="value">${stats.total}</span>
      </div>
      <div class="metric">
        <span class="label">Normal</span>
        <span class="value is-ok">${summary.Normal ?? 0}</span>
      </div>
      <div class="metric">
        <span class="label">Suspicious</span>
        <span class="value is-warn">${summary.Suspicious ?? 0}</span>
      </div>
    </div>
  `;

  const data = await api("/events?limit=15");
  const rows = (data.events || []).map(e => `
    <tr>
      <td>${e.eid}</td>
      <td>${e.etype}</td>
      <td>${e.exe_name || "-"}</td>
      <td>${e.proc_state || "-"}</td>
      <td>${e.cpu_pct ?? "-"}</td>
      <td>${e.mem_mb ?? "-"}</td>
      <td>${riskBadge(e.risk_lvl)}</td>
      <td>${e.ts || ""}</td>
    </tr>`).join("");
  document.getElementById("rows").innerHTML =
    rows || `<tr><td class="empty" colspan="8">No events yet. Choose a source and collect.</td></tr>`;
}

loadDashboard();
