async function loadThreats() {
  if (!requireLogin()) return;
  document.getElementById("shell").innerHTML =
    navHtml("threats") +
    `<main class="main">
      <div class="topbar">
        <div class="page-heading">
          <h1>Threats</h1>
          <p class="lede">AI risk labels for each event — open a case when something looks wrong.</p>
        </div>
      </div>
      <section class="panel">
        <div class="panel-head">
          <h3>Labeled threats</h3>
          <span class="meta">classifier output</span>
        </div>
        <div class="panel-body">
          <table>
            <thead>
              <tr>
                <th>TID</th><th>Exe</th><th>Type</th><th>Risk</th><th>Conf</th><th>Action</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
      </section>
    </main>`;

  const data = await api("/threats");
  document.getElementById("rows").innerHTML = (data.threats || []).map(t => `
    <tr>
      <td>${t.tid}</td>
      <td>${t.exe_name || "-"}</td>
      <td>${t.etype || "-"}</td>
      <td>${riskBadge(t.risk_lvl)}</td>
      <td>${t.confidence ?? "-"}</td>
      <td><button type="button" class="btn" onclick="openInv(${t.tid})">Investigate</button></td>
    </tr>`).join("") || `<tr><td class="empty" colspan="6">No threats yet — collect events first.</td></tr>`;
}

async function openInv(tid) {
  const notes = prompt("Notes for investigation:", "Checking this alert");
  if (notes === null) return;
  await api("/investigate", {
    method: "POST",
    body: JSON.stringify({ tid, notes }),
  });
  alert("Investigation opened");
  window.location.href = "/investigations";
}

loadThreats();
