async function doLogin(e) {
  e.preventDefault();
  const uname = document.getElementById("uname").value.trim();
  const password = document.getElementById("password").value;
  const err = document.getElementById("err");
  err.textContent = "";

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uname, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      err.textContent = data.detail || "login failed";
      return;
    }
    localStorage.setItem("cs_token", data.token);
    localStorage.setItem("cs_uname", data.uname);
    window.location.href = "/";
  } catch (ex) {
    err.textContent = "cannot reach server";
  }
}

document.getElementById("form").addEventListener("submit", doLogin);
