// Shared helpers for every page.
export async function api(path, body) {
  const opts = body === undefined
    ? { method: "GET" }
    : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  let res;
  try { res = await fetch(path, opts); } catch { throw new Error("Cannot reach the server. Check your internet connection."); }
  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok) {
    const err = new Error(data.error || "Something went wrong");
    err.status = res.status;
    throw err;
  }
  return data;
}

export const homeFor = (role) => (role === "admin" ? "/admin.html" : role === "student" ? "/student.html" : "/teacher.html");

// Call at the top of each protected page. Returns the logged-in user, or redirects away.
export async function requireUser(roles) {
  let me;
  try { me = (await api("/api/me")).user; } catch { location.replace("/"); return new Promise(() => {}); }
  if (me.mustChange) { location.replace("/change-password.html"); return new Promise(() => {}); }
  if (roles && !roles.includes(me.role)) { location.replace(homeFor(me.role)); return new Promise(() => {}); }
  return me;
}

export async function logout() {
  try { await api("/api/logout", {}); } catch {}
  location.replace("/");
}

export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function say(el, text, kind) {
  el.textContent = text || "";
  el.className = "msg" + (kind ? " " + kind : "");
}

// A small popup that asks for one line of text. Resolves to the text, or null if cancelled.
export function askText({ title, note = "", label = "", type = "text", ok = "OK" }) {
  return new Promise((resolve) => {
    const d = document.createElement("dialog");
    d.innerHTML = `<form method="dialog"><h3 style="margin:0 0 6px"></h3><p class="muted" style="margin:0 0 6px"></p>
      <label></label><input type="${type}" autocomplete="off" required>
      <div class="btns"><button type="button" class="ghost" data-x>Cancel</button><button>${esc(ok)}</button></div></form>`;
    d.querySelector("h3").textContent = title;
    d.querySelector("p").textContent = note;
    d.querySelector("label").textContent = label;
    const input = d.querySelector("input");
    let value = null;
    d.querySelector("[data-x]").onclick = () => d.close();
    d.querySelector("form").addEventListener("submit", () => { value = input.value; });
    d.addEventListener("close", () => { d.remove(); resolve(value); });
    document.body.append(d);
    d.showModal();
    input.focus();
  });
}

// Institution logo (header) and developer credit (footer) on every page.
// Every page loads this file, so future pages get both automatically.
// Put the logo file at public/logo.png. If it is missing, the logo is simply left out.
(() => {
  const logo = document.createElement("img");
  logo.src = "/logo.png";
  logo.alt = "Institution logo";
  logo.onerror = () => logo.remove();
  const header = document.querySelector("header.top");
  if (header) {
    logo.className = "logo";
    const h1 = header.querySelector("h1");
    h1.classList.add("brand");
    h1.prepend(logo);
  } else {
    logo.className = "logo big";
    const holder = document.querySelector(".narrow");
    if (holder) holder.prepend(logo);
  }
  const foot = document.createElement("footer");
  foot.className = "credit";
  foot.textContent = "Developed by R LALRINAWMA";
  document.body.append(foot);
})();
