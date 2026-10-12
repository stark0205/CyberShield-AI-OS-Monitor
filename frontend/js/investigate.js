async function loadInv() {
  if (!requireLogin()) return;
  document.getElementById("shell").innerHTML =
    navHtml("inv") +
    `<main class="main">
      <div class="topbar">
        <div class="page-heading">
          <h1>Cases</h1>
          <p class="lede">Investigations opened from threats — respond, then close when done.</p>
        </div>
      </div>
      <section class="panel">
        <div class="panel-head">
          <h3>Open & closed</h3>
          <span class="meta">investigations</span>
        </div>
        <div class="panel-body">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Exe</th><th>Risk</th><th>Status</th><th>Notes</th><th>Actions</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
      </section>
    </main>`;

  const data = await api("/investigations");
  document.getElementById("rows").innerHTML = (data.investigations || []).map(i => `
    <tr>
      <td>${i.inv_id}</td>
      <td>${i.exe_name || "-"}</td>
      <td>${riskBadge(i.risk_lvl)}</td>
      <td><span class="status-pill">${i.status}</span></td>
      <td>${i.notes || ""}</td>
      <td>
        <div class="actions">
          <button type="button" class="btn" onclick="respond(${i.inv_id})">Respond</button>
          <button type="button" class="btn btn-ghost" onclick="closeInv(${i.inv_id})">Close</button>
        </div>
      </td>
    </tr>`).join("") || `<tr><td class="empty" colspan="6">No investigations yet.</td></tr>`;
}

async function respond(inv_id) {
  const action_type = prompt("Action type (e.g. kill process, isolate):", "kill process");
  if (!action_type) return;
  const description = prompt("Description:", "") || "";
  await api("/respond", {
    method: "POST",
    body: JSON.stringify({ inv_id, action_type, description }),
  });
  alert("Response saved");
}

async function closeInv(inv_id) {
  await api("/investigate/" + inv_id, {
    method: "PUT",
    body: JSON.stringify({ status: "Closed" }),
  });
  loadInv();
}

loadInv();
