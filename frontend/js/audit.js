async function loadAudit() {
  if (!requireLogin()) return;
  document.getElementById("shell").innerHTML =
    navHtml("audit") +
    `<main class="main">
      <div class="topbar">
        <div class="page-heading">
          <h1>Audit</h1>
          <p class="lede">Who collected events, opened cases, or recorded responses.</p>
        </div>
      </div>
      <section class="panel">
        <div class="panel-head">
          <h3>Activity log</h3>
          <span class="meta">append-only</span>
        </div>
        <div class="panel-body">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>User</th><th>Action</th><th>Detail</th><th>Time</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
      </section>
    </main>`;

  const data = await api("/audit");
  document.getElementById("rows").innerHTML = (data.audit || []).map(a => `
    <tr>
      <td>${a.log_id}</td>
      <td>${a.uname || a.uid || "-"}</td>
      <td>${a.action}</td>
      <td>${a.detail || ""}</td>
      <td>${a.ts || ""}</td>
    </tr>`).join("") || `<tr><td class="empty" colspan="5">No audit rows yet.</td></tr>`;
}
loadAudit();
