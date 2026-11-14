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
  const login = roles && roles.includes("student") ? "/" : "/staff";
  try { me = (await api("/api/me")).user; } catch { location.replace(login); return new Promise(() => {}); }
  if (me.mustChange) { location.replace("/change-password.html"); return new Promise(() => {}); }
  if (roles && !roles.includes(me.role)) { location.replace(homeFor(me.role)); return new Promise(() => {}); }
  return me;
}

export async function logout() {
  let role = "";
  try { role = (await api("/api/me")).user.role; } catch {}
  try { await api("/api/logout", {}); } catch {}
  location.replace(!role || role === "student" ? "/" : "/staff");
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

// Pick who takes an optional paper (used by the admin and by the paper's own teacher).
// onSaved() runs after a successful save.
export async function enrolDialog(subjectId, onSaved) {
  let data;
  try { data = await api("/api/enrolment?subjectId=" + encodeURIComponent(subjectId)); } catch (e) { alert(e.message); return; }
  const picked = new Set(data.enrolled);
  const d = document.createElement("dialog");
  d.innerHTML = `<form method="dialog"><h3 style="margin:0 0 4px"></h3>
    <p class="muted" style="margin:0 0 8px">Tick the students who take this paper. Only they appear in its attendance and marks lists.</p>
    <input class="search" placeholder="Search name or roll no." autocomplete="off">
    <div class="row" style="margin:8px 0 0;gap:6px"><button type="button" class="ghost sm" data-all>Tick all shown</button><button type="button" class="ghost sm" data-none>Untick all shown</button></div>
    <div class="checks"></div><p class="muted" data-count style="margin:6px 0 0"></p><p class="msg" data-msg></p>
    <div class="btns"><button type="button" class="ghost" data-x>Cancel</button><button type="submit">Save</button></div></form>`;
  d.querySelector("h3").textContent = `${data.subject.name} (${data.subject.class})`;
  const list = d.querySelector(".checks"), search = d.querySelector(".search"), count = d.querySelector("[data-count]");
  const shown = () => { const q = search.value.trim().toLowerCase(); return data.students.filter((s) => !q || s.name.toLowerCase().includes(q) || String(s.rollNo).toLowerCase().includes(q)); };
  const draw = () => {
    list.innerHTML = shown().map((s) => `<label class="chk"><input type="checkbox" value="${esc(s.studentId)}" ${picked.has(s.studentId) ? "checked" : ""}><span class="roll">${esc(s.rollNo)}</span><span class="nm">${esc(s.name)}</span></label>`).join("") || `<p class="muted">No students found.</p>`;
    count.textContent = `${picked.size} of ${data.students.length} students ticked`;
  };
  list.addEventListener("change", (e) => { if (e.target.type === "checkbox") { e.target.checked ? picked.add(e.target.value) : picked.delete(e.target.value); count.textContent = `${picked.size} of ${data.students.length} students ticked`; } });
  search.addEventListener("input", draw);
  d.querySelector("[data-all]").onclick = () => { shown().forEach((s) => picked.add(s.studentId)); draw(); };
  d.querySelector("[data-none]").onclick = () => { shown().forEach((s) => picked.delete(s.studentId)); draw(); };
  d.querySelector("[data-x]").onclick = () => d.close();
  d.querySelector("form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = d.querySelector("[data-msg]");
    try { await api("/api/enrolment", { subjectId, studentIds: [...picked] }); d.close(); if (onSaved) await onSaved(picked.size); }
    catch (err) { say(msg, err.message, "err"); }
  });
  d.addEventListener("close", () => d.remove());
  document.body.append(d); draw(); d.showModal();
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
  foot.textContent = "Develop by R LALRINAWMA";
  document.body.append(foot);
})();
