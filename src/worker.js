// DIET Student Management System: backend (Cloudflare Worker + D1)
// Phase 1: login, sessions, roles, password change, first-admin setup, teacher accounts.

const PBKDF2_ITERATIONS = 20000;       // kept modest so a login fits the free plan's CPU limit
const SESSION_DAYS = 7;
const MAX_FAILS_ANY = 40;           // wrong passwords allowed per Login ID from anywhere, per 10 minutes
const MAX_FAILS = 6;                   // wrong passwords allowed ...
const FAIL_WINDOW = 10 * 60;           // ... per 10 minutes
const ROLES = ["admin", "teacher", "coordinator", "student"];

// ---------- small helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
const fail = (status, error) => json({ error }, status);
const now = () => Math.floor(Date.now() / 1000);

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(bits)}`;
}
async function checkPassword(password, stored) {
  const [kind, iters, salt, hash] = stored.split("$");
  if (kind !== "pbkdf2") return false;
  const bits = await pbkdf2(password, unb64(salt), parseInt(iters, 10));
  const a = new Uint8Array(bits), b = unb64(hash);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];   // constant-time compare
  return diff === 0;
}
async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
const normLogin = (s) => String(s || "").trim().replace(/\s+/g, "_").toLowerCase();

function getCookie(request, name) {
  const m = (request.headers.get("cookie") || "").match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? m[1] : null;
}
const sessionCookie = (value, maxAge) =>
  `sid=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;

async function readBody(request) {
  try { return await request.json(); } catch { return null; }
}

// ---------- sessions ----------
async function createSession(env, userId) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const expires = now() + SESSION_DAYS * 86400;
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(await sha256hex(token), userId, expires).run();
  return { token, maxAge: SESSION_DAYS * 86400 };
}

// Returns the logged-in user or null. One indexed read per request.
async function currentUser(request, env) {
  const token = getCookie(request, "sid");
  if (!token) return null;
  return env.DB.prepare(
    `SELECT u.id, u.login, u.name, u.role, u.student_id, u.must_change
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(await sha256hex(token), now()).first();
}

// ---------- route handlers ----------
const handlers = {};

// One-time creation of the very first admin. Needs the SETUP_KEY secret; refuses once any admin exists.
handlers["POST /api/setup"] = async (request, env) => {
  const body = await readBody(request);
  if (!body) return fail(400, "Bad request");
  if (!env.SETUP_KEY || body.key !== env.SETUP_KEY) return fail(403, "Wrong setup key");
  const existing = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").first();
  if (existing.n > 0) return fail(409, "An admin already exists");
  const login = normLogin(body.loginId), name = String(body.name || "").trim();
  if (!login || !name || String(body.password || "").length < 8) return fail(400, "Need loginId, name and a password of 8+ characters");
  await env.DB.prepare("INSERT INTO users (login, name, role, pw, must_change) VALUES (?, ?, 'admin', ?, 0)")
    .bind(login, name, await hashPassword(body.password)).run();
  return json({ ok: true });
};

handlers["POST /api/login"] = async (request, env) => {
  const body = await readBody(request);
  const login = normLogin(body && (body.loginId ?? body.login));
  const password = String((body && body.password) || "");
  const portal = body && body.portal === "staff" ? "staff" : "student";
  if (!login || !password) return fail(400, "Enter your Login ID and password");

  // Slow down guessing. Wrong attempts are counted per Login ID from one connection (so a student
  // elsewhere cannot lock the admin out) and, with a much higher limit, per Login ID overall.
  const t = now();
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const keyIp = `${login}|${ip}`, keyAll = `*${login}`;
  const recs = await env.DB.prepare("SELECT login, fails, window_start FROM login_fail WHERE login IN (?, ?)").bind(keyIp, keyAll).all();
  for (const r of recs.results) {
    const limit = r.login === keyAll ? MAX_FAILS_ANY : MAX_FAILS;
    if (t - r.window_start < FAIL_WINDOW && r.fails >= limit) return fail(429, "Too many wrong attempts. Please wait 10 minutes and try again.");
  }

  const user = await env.DB.prepare("SELECT id, name, role, student_id, must_change, pw FROM users WHERE login = ?").bind(login).first();
  // Always do the hashing work so timing does not reveal which Login IDs exist.
  const ok = user ? await checkPassword(password, user.pw)
                  : (await checkPassword(password, "pbkdf2$" + PBKDF2_ITERATIONS + "$AAAAAAAAAAAAAAAAAAAAAA==$" + "A".repeat(43) + "="), false);
  if (!ok) {
    const bump = (key) => env.DB.prepare(
      `INSERT INTO login_fail (login, fails, window_start) VALUES (?, 1, ?)
       ON CONFLICT(login) DO UPDATE SET
         fails = CASE WHEN ? - window_start >= ? THEN 1 ELSE fails + 1 END,
         window_start = CASE WHEN ? - window_start >= ? THEN ? ELSE window_start END`
    ).bind(key, t, t, FAIL_WINDOW, t, FAIL_WINDOW, t);
    await env.DB.batch([bump(keyIp), bump(keyAll)]);
    return fail(401, "Wrong Login ID or password");
  }
  // Right password, wrong door: say where to go (only someone who knows the password sees this).
  const isStaff = user.role !== "student";
  if (portal === "student" && isStaff) return fail(403, "Teachers and admin use the staff login page. Ask the admin for its address.");
  if (portal === "staff" && !isStaff) return fail(403, "Students use the student login page.");

  await env.DB.prepare("DELETE FROM login_fail WHERE login IN (?, ?)").bind(keyIp, keyAll).run();
  // Tidy expired sessions now and then (about 1 login in 20).
  if (Math.random() < 0.05) await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(t).run();

  const { token, maxAge } = await createSession(env, user.id);
  return json(
    { user: { name: user.name, role: user.role, studentId: user.student_id, mustChange: !!user.must_change } },
    200, { "set-cookie": sessionCookie(token, maxAge) }
  );
};

handlers["POST /api/logout"] = async (request, env) => {
  const token = getCookie(request, "sid");
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256hex(token)).run();
  return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
};

handlers["GET /api/me"] = async (request, env, user) =>
  json({ user: { name: user.name, role: user.role, studentId: user.student_id, mustChange: !!user.must_change } });

handlers["POST /api/change-password"] = async (request, env, user) => {
  const body = await readBody(request);
  if (!body) return fail(400, "Bad request");
  const newPw = String(body.newPassword || "");
  if (newPw.length < 8) return fail(400, "New password must be at least 8 characters");
  const row = await env.DB.prepare("SELECT pw FROM users WHERE id = ?").bind(user.id).first();
  if (!(await checkPassword(String(body.oldPassword || ""), row.pw))) return fail(403, "Current password is wrong");
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET pw = ?, must_change = 0 WHERE id = ?").bind(await hashPassword(newPw), user.id),
    // sign out every other device
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?")
      .bind(user.id, await sha256hex(getCookie(request, "sid"))),
  ]);
  return json({ ok: true });
};

// ----- admin: teachers -----
handlers["GET /api/admin/teachers"] = async (request, env, user) => {
  const rows = await env.DB.prepare(
    `SELECT u.id, u.login, u.name, u.role,
            (SELECT group_concat(subject_id) FROM subjects WHERE teacher_id = u.id) AS subjects
       FROM users u WHERE u.role IN ('teacher','coordinator') ORDER BY u.name`
  ).all();
  return json({ teachers: rows.results });
};

handlers["POST /api/admin/teachers"] = async (request, env, user) => {
  const body = await readBody(request);
  if (!body) return fail(400, "Bad request");
  const login = normLogin(body.loginId), name = String(body.name || "").trim();
  const role = body.role === "coordinator" ? "coordinator" : "teacher";
  const password = String(body.password || "");
  if (!login || !name) return fail(400, "Name and login are required");
  if (password.length < 8) return fail(400, "Password must be at least 8 characters");
  if (await env.DB.prepare("SELECT 1 FROM users WHERE login = ?").bind(login).first()) return fail(409, "That login already exists");

  const res = await env.DB.prepare("INSERT INTO users (login, name, role, pw, must_change) VALUES (?, ?, ?, ?, 1)")
    .bind(login, name, role, await hashPassword(password)).run();
  if (body.subjectId) {
    await env.DB.prepare("UPDATE subjects SET teacher_id = ? WHERE subject_id = ?")
      .bind(res.meta.last_row_id, String(body.subjectId)).run();
  }
  return json({ ok: true, id: res.meta.last_row_id });
};

// Reset any account's password (teacher by userId, student by studentId).
handlers["POST /api/admin/reset-password"] = async (request, env, user) => {
  const body = await readBody(request);
  if (!body) return fail(400, "Bad request");
  const password = String(body.password || "");
  if (password.length < 8) return fail(400, "Password must be at least 8 characters");
  const target = body.studentId
    ? await env.DB.prepare("SELECT id FROM users WHERE student_id = ?").bind(String(body.studentId)).first()
    : await env.DB.prepare("SELECT id FROM users WHERE id = ? AND role <> 'admin'").bind(Number(body.userId)).first();
  if (!target) return fail(404, "Account not found");
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET pw = ?, must_change = 1 WHERE id = ?").bind(await hashPassword(password), target.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(target.id),
  ]);
  return json({ ok: true });
};

// ----- admin: students -----
const CLASSES = ["I Sem", "II Sem", "III Sem", "IV Sem"];
const SEM_OF = { "I Sem": "1", "II Sem": "2", "III Sem": "3", "IV Sem": "4", "Alumni": "Completed" };
// Intakes that keep the plain "<Class>_<Roll>" ID. Any other batch gets "<Batch>_<Class>_<Roll>".
const LEGACY_BATCHES = ["2025-2027", "2026-2028"];
const IMPORT_CHUNK = 5;               // passwords are hashed per student, so keep requests small

function makeStudentId(cls, roll, batch) {
  const base = `${cls}_${roll}`.replace(/\s+/g, "_");
  return batch && !LEGACY_BATCHES.includes(batch) ? `${batch}_${base}`.replace(/\s+/g, "_") : base;
}

handlers["GET /api/admin/students"] = async (request, env) => {
  const rows = await env.DB.prepare(
    `SELECT s.student_id AS studentId, s.name, s.roll_no AS rollNo, s.class, s.semester, s.batch, u.login
       FROM students s LEFT JOIN users u ON u.student_id = s.student_id
      ORDER BY s.class, CAST(s.roll_no AS INTEGER), s.student_id`
  ).all();
  return json({ students: rows.results });
};

// Import in small chunks. Existing students (same ID) are updated, never given a new password.
handlers["POST /api/admin/students/import"] = async (request, env) => {
  const body = await readBody(request);
  const list = body && body.students;
  if (!Array.isArray(list) || list.length === 0 || list.length > IMPORT_CHUNK) return fail(400, `Send 1 to ${IMPORT_CHUNK} students at a time`);
  const results = [], stmts = [];
  for (const s of list) {
    const name = String(s.name || "").trim();
    let roll = String(s.rollNo ?? "").trim();
    if (/^\d$/.test(roll)) roll = "0" + roll;
    const cls = String(s.class || "").trim();
    const batch = String(s.batch || "").trim();
    if (!name || !roll || !CLASSES.includes(cls)) { results.push({ name, status: "skipped", reason: "needs name, roll number and a class of I Sem to IV Sem" }); continue; }
    const id = makeStudentId(cls, roll, batch);
    const exists = await env.DB.prepare("SELECT 1 FROM students WHERE student_id = ?").bind(id).first();
    if (exists) {
      stmts.push(env.DB.prepare("UPDATE students SET name=?, roll_no=?, class=?, semester=?, batch=? WHERE student_id=?")
        .bind(name, roll, cls, SEM_OF[cls], batch || null, id));
      stmts.push(env.DB.prepare("UPDATE users SET name=? WHERE student_id=?").bind(name, id));
      results.push({ studentId: id, status: "updated" });
    } else {
      const pw = await hashPassword(`${id}_123`);
      stmts.push(env.DB.prepare("INSERT INTO students (student_id, name, roll_no, class, semester, batch) VALUES (?,?,?,?,?,?)")
        .bind(id, name, roll, cls, SEM_OF[cls], batch || null));
      stmts.push(env.DB.prepare("INSERT INTO users (login, name, role, pw, must_change, student_id) VALUES (?,?,'student',?,1,?)")
        .bind(normLogin(id), name, pw, id));
      results.push({ studentId: id, status: "created" });
    }
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json({ results });
};

handlers["POST /api/admin/students/delete"] = async (request, env) => {
  const body = await readBody(request);
  const id = String((body && body.studentId) || "");
  if (!id) return fail(400, "Bad request");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM att_marks WHERE student_id = ?").bind(id),
    env.DB.prepare("DELETE FROM marks WHERE student_id = ?").bind(id),
    env.DB.prepare("DELETE FROM past_results WHERE student_id = ?").bind(id),
    env.DB.prepare("DELETE FROM subject_students WHERE student_id = ?").bind(id),
    env.DB.prepare("DELETE FROM users WHERE student_id = ?").bind(id),
    env.DB.prepare("DELETE FROM students WHERE student_id = ?").bind(id),
  ]);
  return json({ ok: true });
};

// Delete many students at once: everyone, or only one class. Removes their logins, attendance, marks and past results.
handlers["POST /api/admin/students/delete-many"] = async (request, env) => {
  const body = await readBody(request);
  if (!body || body.confirm !== "DELETE") return fail(400, "Type DELETE to confirm");
  const cls = String(body.class || "");
  if (cls && !CLASSES.includes(cls) && cls !== "Alumni") return fail(400, "Unknown class");
  const where = cls ? "WHERE class = ?" : "";
  const bind = (st) => (cls ? st.bind(cls) : st);
  const count = await bind(env.DB.prepare(`SELECT COUNT(*) AS n FROM students ${where}`)).first();
  const ids = `SELECT student_id FROM students ${where}`;
  await env.DB.batch([
    bind(env.DB.prepare(`DELETE FROM att_marks WHERE student_id IN (${ids})`)),
    bind(env.DB.prepare(`DELETE FROM marks WHERE student_id IN (${ids})`)),
    bind(env.DB.prepare(`DELETE FROM past_results WHERE student_id IN (${ids})`)),
    bind(env.DB.prepare(`DELETE FROM subject_students WHERE student_id IN (${ids})`)),
    bind(env.DB.prepare(`DELETE FROM users WHERE role = 'student' AND student_id IN (${ids})`)),
    bind(env.DB.prepare(`DELETE FROM students ${where}`)),
  ]);
  return json({ ok: true, deleted: count.n });
};

handlers["POST /api/admin/users/delete"] = async (request, env) => {
  const body = await readBody(request);
  const r = await env.DB.prepare("DELETE FROM users WHERE id = ? AND role IN ('teacher','coordinator')").bind(Number(body && body.userId)).run();
  return json({ ok: true, deleted: r.meta.changes });
};

// ----- admin: subjects -----
handlers["GET /api/admin/subjects"] = async (request, env) => {
  const rows = await env.DB.prepare(
    `SELECT s.subject_id AS subjectId, s.name, s.class, s.optional, s.teacher_id AS teacherId, u.name AS teacherName,
            (SELECT COUNT(*) FROM subject_students e WHERE e.subject_id = s.subject_id) AS enrolled
       FROM subjects s LEFT JOIN users u ON u.id = s.teacher_id ORDER BY s.class, s.subject_id`
  ).all();
  return json({ subjects: rows.results });
};

handlers["POST /api/admin/subjects"] = async (request, env) => {
  const body = await readBody(request);
  const id = String((body && body.subjectId) || "").trim().toUpperCase().replace(/\s+/g, "");
  const name = String((body && body.name) || "").trim();
  const cls = String((body && body.class) || "").trim();
  if (!id || !name || !CLASSES.includes(cls)) return fail(400, "Subject ID, name and class are required");
  if (await env.DB.prepare("SELECT 1 FROM subjects WHERE subject_id = ?").bind(id).first()) return fail(409, "That subject ID already exists");
  await env.DB.prepare("INSERT INTO subjects (subject_id, name, class, optional) VALUES (?,?,?,?)").bind(id, name, cls, body.optional ? 1 : 0).run();
  return json({ ok: true, subjectId: id });
};

handlers["POST /api/admin/subjects/assign"] = async (request, env) => {
  const body = await readBody(request);
  const teacherId = body && body.teacherId ? Number(body.teacherId) : null;
  if (teacherId && !(await env.DB.prepare("SELECT 1 FROM users WHERE id = ? AND role IN ('teacher','coordinator')").bind(teacherId).first())) return fail(404, "Teacher not found");
  const r = await env.DB.prepare("UPDATE subjects SET teacher_id = ? WHERE subject_id = ?").bind(teacherId, String(body.subjectId || "")).run();
  return r.meta.changes ? json({ ok: true }) : fail(404, "Subject not found");
};

handlers["POST /api/admin/subjects/update"] = async (request, env) => {
  const body = await readBody(request);
  const id = String((body && body.subjectId) || ""), name = String((body && body.name) || "").trim();
  const cls = String((body && body.class) || "").trim();
  if (!id || !name || !CLASSES.includes(cls)) return fail(400, "Subject name and class are required");
  const r = await env.DB.prepare("UPDATE subjects SET name = ?, class = ?, optional = ? WHERE subject_id = ?").bind(name, cls, body.optional ? 1 : 0, id).run();
  return r.meta.changes ? json({ ok: true }) : fail(404, "Subject not found");
};

handlers["POST /api/admin/subjects/delete"] = async (request, env) => {
  const body = await readBody(request);
  const sid = String((body && body.subjectId) || "");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM subject_students WHERE subject_id = ?").bind(sid),
    env.DB.prepare("DELETE FROM subjects WHERE subject_id = ?").bind(sid),
  ]);
  return json({ ok: true });
};

// ----- admin: timetable -----
const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
handlers["GET /api/admin/timetable"] = async (request, env) => {
  const rows = await env.DB.prepare("SELECT class, day, p1, p2, p3, p4 FROM timetable").all();
  return json({ timetable: rows.results });
};
handlers["POST /api/admin/timetable"] = async (request, env) => {
  const body = await readBody(request);
  if (!body || !CLASSES.includes(body.class) || !DAYS.includes(body.day)) return fail(400, "Pick a class and a day");
  const p = [1, 2, 3, 4].map((i) => String(body["p" + i] || "").trim() || null);
  await env.DB.prepare(
    `INSERT INTO timetable (class, day, p1, p2, p3, p4) VALUES (?,?,?,?,?,?)
     ON CONFLICT(class, day) DO UPDATE SET p1=excluded.p1, p2=excluded.p2, p3=excluded.p3, p4=excluded.p4`
  ).bind(body.class, body.day, ...p).run();
  return json({ ok: true });
};

// ----- admin: end of semester -----
const PROMOTE_DAYS_GUARD = 60;
handlers["GET /api/admin/promote-preview"] = async (request, env) => {
  const counts = await env.DB.prepare("SELECT class, COUNT(*) AS n FROM students WHERE class <> 'Alumni' GROUP BY class").all();
  const last = await env.DB.prepare("SELECT MAX(last_promoted_on) AS d FROM students").first();
  const sess = await env.DB.prepare("SELECT COUNT(*) AS n FROM att_sessions").first();
  return json({ counts: counts.results, lastPromotedOn: last.d, attendanceSessions: sess.n });
};

handlers["POST /api/admin/promote"] = async (request, env) => {
  const body = await readBody(request);
  if (!body || body.confirm !== "PROMOTE") return fail(400, "Type PROMOTE to confirm");
  const today = new Date(Date.now() + 5.5 * 3600 * 1000).toISOString().slice(0, 10);   // India date
  const last = await env.DB.prepare("SELECT MAX(last_promoted_on) AS d FROM students").first();
  if (last.d && !body.force) {
    const days = (Date.parse(today) - Date.parse(last.d)) / 86400000;
    if (days < PROMOTE_DAYS_GUARD) return fail(409, `Students were already promoted on ${last.d}. Running it again would move them up a second time.`);
  }
  const [r] = await env.DB.batch([env.DB.prepare(
    `UPDATE students SET
       semester = CASE class WHEN 'IV Sem' THEN 'Completed' WHEN 'III Sem' THEN '4' WHEN 'II Sem' THEN '3' ELSE '2' END,
       class    = CASE class WHEN 'IV Sem' THEN 'Alumni' WHEN 'III Sem' THEN 'IV Sem' WHEN 'II Sem' THEN 'III Sem' ELSE 'II Sem' END,
       last_promoted_on = ?
     WHERE class IN ('I Sem','II Sem','III Sem','IV Sem')`
  ).bind(today), env.DB.prepare("DELETE FROM subject_students")]);
  return json({ ok: true, promoted: r.meta.changes });
};

// Delete every attendance session on or before a date (their per-student rows go with them).
handlers["POST /api/admin/clear-attendance"] = async (request, env) => {
  const body = await readBody(request);
  const before = String((body && body.before) || "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(before)) return fail(400, "Pick a date");
  await env.DB.prepare("DELETE FROM att_marks WHERE session_id IN (SELECT id FROM att_sessions WHERE date <= ?)").bind(before).run();
  const r = await env.DB.prepare("DELETE FROM att_sessions WHERE date <= ?").bind(before).run();
  return json({ ok: true, deletedSessions: r.meta.changes });
};

// ----- admin: past results (import in chunks of up to 50 rows) -----
handlers["POST /api/admin/past-results/import"] = async (request, env) => {
  const body = await readBody(request);
  const rows = body && body.rows;
  if (!Array.isArray(rows) || rows.length === 0 || rows.length > 50) return fail(400, "Send 1 to 50 rows at a time");
  const num = (v, d) => (isFinite(parseFloat(v)) ? parseFloat(v) : d);
  const stmts = [];
  let skipped = 0;
  for (const r of rows) {
    if (!r.studentId || !r.pastSemester || !r.subjectId) { skipped++; continue; }
    stmts.push(env.DB.prepare(
      `INSERT OR REPLACE INTO past_results (student_id, past_semester, subject_id, subject_name, internal_obtained, internal_full, external_obtained, external_full, status)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).bind(String(r.studentId), String(r.pastSemester), String(r.subjectId), String(r.subjectName || r.subjectId),
      num(r.internalObtained, 0), num(r.internalFull, 100), num(r.externalObtained, 0), num(r.externalFull, 100), String(r.status || "PASSED")));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true, saved: stmts.length, skipped });
};


// =====================================================================
// Teacher portal: subjects, roster, attendance, marks, summary, register
// =====================================================================
const todayIST = () => new Date(Date.now() + 5.5 * 3600 * 1000).toISOString().slice(0, 10);
const isDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
const qs = (request, k) => new URL(request.url).searchParams.get(k) || "";

// The subject, if this user may work on it (its teacher, or the admin).
async function ownSubject(env, user, subjectId) {
  const s = await env.DB.prepare("SELECT subject_id AS subjectId, name, class, optional, teacher_id AS teacherId FROM subjects WHERE subject_id = ?").bind(subjectId).first();
  if (!s) return null;
  if (user.role !== "admin" && s.teacherId !== user.id) return null;
  return s;
}
// Students who take the subject: everyone in the class, or only the enrolled ones for an optional paper.
async function roster(env, s) {
  const order = "ORDER BY CAST(st.roll_no AS INTEGER), st.roll_no";
  const q = s.optional
    ? env.DB.prepare(`SELECT st.student_id AS studentId, st.name, st.roll_no AS rollNo FROM subject_students e JOIN students st ON st.student_id = e.student_id WHERE e.subject_id = ? ${order}`).bind(s.subjectId)
    : env.DB.prepare(`SELECT st.student_id AS studentId, st.name, st.roll_no AS rollNo FROM students st WHERE st.class = ? ${order}`).bind(s.class);
  return (await q.all()).results;
}
const noSubject = () => fail(404, "That subject is not yours");

handlers["GET /api/teacher/subjects"] = async (request, env, user) => {
  const rows = await env.DB.prepare("SELECT subject_id AS subjectId, name, class, optional FROM subjects WHERE teacher_id = ? ORDER BY class, subject_id").bind(user.id).all();
  return json({ subjects: rows.results });
};

handlers["GET /api/teacher/roster"] = async (request, env, user) => {
  const s = await ownSubject(env, user, qs(request, "subjectId"));
  if (!s) return noSubject();
  return json({ subject: s, students: await roster(env, s) });
};

// The saved attendance for one class (date + subject + period), if any.
handlers["GET /api/teacher/attendance"] = async (request, env, user) => {
  const s = await ownSubject(env, user, qs(request, "subjectId"));
  if (!s) return noSubject();
  const date = qs(request, "date"), period = Number(qs(request, "period"));
  const sess = await env.DB.prepare("SELECT id FROM att_sessions WHERE date = ? AND subject_id = ? AND period = ?").bind(date, s.subjectId, period).first();
  if (!sess) return json({ exists: false, statuses: {} });
  const rows = await env.DB.prepare("SELECT student_id, present FROM att_marks WHERE session_id = ?").bind(sess.id).all();
  const statuses = {};
  rows.results.forEach((r) => { statuses[r.student_id] = r.present ? "present" : "absent"; });
  return json({ exists: true, statuses });
};

// Save (or correct) one class. Saving the same date + subject + period again replaces the earlier record.
handlers["POST /api/teacher/attendance"] = async (request, env, user) => {
  const body = await readBody(request);
  if (!body) return fail(400, "Bad request");
  const s = await ownSubject(env, user, String(body.subjectId || ""));
  if (!s) return noSubject();
  const date = String(body.date || ""), period = Number(body.period);
  if (!isDate(date)) return fail(400, "Pick a valid date");
  if (date > todayIST()) return fail(400, "You cannot mark attendance for a future date");
  if (![1, 2, 3, 4].includes(period)) return fail(400, "Pick a period from 1 to 4");
  const statuses = body.statuses && typeof body.statuses === "object" ? body.statuses : {};
  const ids = new Set((await roster(env, s)).map((r) => r.studentId));
  const marks = Object.entries(statuses).filter(([id, v]) => ids.has(id) && (v === "present" || v === "absent"));
  if (marks.length === 0) return fail(400, "Mark at least one student present or absent");

  const where = [date, s.subjectId, period];
  const sel = "SELECT id FROM att_sessions WHERE date = ? AND subject_id = ? AND period = ?";
  const stmts = [
    env.DB.prepare(`INSERT INTO att_sessions (date, subject_id, period, class, marked_by) VALUES (?,?,?,?,?)
                    ON CONFLICT(date, subject_id, period) DO UPDATE SET class = excluded.class, marked_by = excluded.marked_by`)
      .bind(date, s.subjectId, period, s.class, user.id),
    env.DB.prepare(`DELETE FROM att_marks WHERE session_id = (${sel})`).bind(...where),
    ...marks.map(([id, v]) => env.DB.prepare(`INSERT INTO att_marks (session_id, student_id, present) SELECT id, ?, ? FROM att_sessions WHERE date = ? AND subject_id = ? AND period = ?`)
      .bind(id, v === "present" ? 1 : 0, ...where)),
  ];
  await env.DB.batch(stmts);
  const absent = marks.filter(([, v]) => v === "absent").length;
  return json({ ok: true, present: marks.length - absent, absent });
};

// Recent classes for a subject (newest first), so a teacher can open one to correct it.
handlers["GET /api/teacher/attendance-history"] = async (request, env, user) => {
  const s = await ownSubject(env, user, qs(request, "subjectId"));
  if (!s) return noSubject();
  const rows = await env.DB.prepare(
    `SELECT a.date, a.period, COALESCE(SUM(m.present),0) AS present, COUNT(m.student_id) AS total
       FROM att_sessions a LEFT JOIN att_marks m ON m.session_id = a.id
      WHERE a.subject_id = ? GROUP BY a.id ORDER BY a.date DESC, a.period DESC LIMIT 60`
  ).bind(s.subjectId).all();
  return json({ classes: rows.results });
};

// Per-student totals for a subject.
handlers["GET /api/teacher/summary"] = async (request, env, user) => {
  const s = await ownSubject(env, user, qs(request, "subjectId"));
  if (!s) return noSubject();
  const [students, agg, held] = await Promise.all([
    roster(env, s),
    env.DB.prepare(`SELECT m.student_id AS id, SUM(m.present) AS present, COUNT(*) AS total
                      FROM att_marks m JOIN att_sessions a ON a.id = m.session_id WHERE a.subject_id = ? GROUP BY m.student_id`).bind(s.subjectId).all(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM att_sessions WHERE subject_id = ?").bind(s.subjectId).first(),
  ]);
  const by = {};
  agg.results.forEach((r) => { by[r.id] = r; });
  return json({
    classesHeld: held.n,
    students: students.map((st) => ({ ...st, present: (by[st.studentId] || {}).present || 0, total: (by[st.studentId] || {}).total || 0 })),
  });
};

// Everything needed to build the Excel register (the page builds the file).
handlers["GET /api/teacher/register"] = async (request, env, user) => {
  const s = await ownSubject(env, user, qs(request, "subjectId"));
  if (!s) return noSubject();
  const [students, sessions, marks] = await Promise.all([
    roster(env, s),
    env.DB.prepare("SELECT id, date, period FROM att_sessions WHERE subject_id = ? ORDER BY date, period").bind(s.subjectId).all(),
    env.DB.prepare(`SELECT m.session_id AS sid, m.student_id AS st, m.present AS p FROM att_marks m JOIN att_sessions a ON a.id = m.session_id WHERE a.subject_id = ?`).bind(s.subjectId).all(),
  ]);
  return json({ subject: s, students, sessions: sessions.results, marks: marks.results.map((m) => [m.sid, m.st, m.p]) });
};

// ----- marks: the teacher types the exam name and its full mark -----
handlers["GET /api/teacher/marks"] = async (request, env, user) => {
  const s = await ownSubject(env, user, qs(request, "subjectId"));
  if (!s) return noSubject();
  const exam = qs(request, "exam");
  if (!exam) {
    const rows = await env.DB.prepare(
      "SELECT exam_name AS exam, MAX(max_score) AS maxScore, COUNT(*) AS n FROM marks WHERE subject_id = ? GROUP BY exam_name ORDER BY MAX(date_graded) DESC, exam_name"
    ).bind(s.subjectId).all();
    return json({ exams: rows.results });
  }
  const rows = await env.DB.prepare("SELECT student_id AS id, score, max_score AS maxScore FROM marks WHERE subject_id = ? AND exam_name = ?").bind(s.subjectId, exam).all();
  const scores = {};
  rows.results.forEach((r) => { scores[r.id] = r.score; });
  return json({ maxScore: rows.results.length ? rows.results[0].maxScore : null, scores });
};

handlers["POST /api/teacher/marks"] = async (request, env, user) => {
  const body = await readBody(request);
  if (!body) return fail(400, "Bad request");
  const s = await ownSubject(env, user, String(body.subjectId || ""));
  if (!s) return noSubject();
  const exam = String(body.exam || "").trim();
  const max = Number(body.maxScore);
  if (!exam || exam.length > 60) return fail(400, "Enter an exam name (up to 60 characters)");
  if (!isFinite(max) || max <= 0 || max > 1000) return fail(400, "Enter the full mark (more than 0)");
  const scores = body.scores && typeof body.scores === "object" ? body.scores : {};
  const ids = new Set((await roster(env, s)).map((r) => r.studentId));
  const today = todayIST(), stmts = [];
  let saved = 0, cleared = 0;
  for (const [id, raw] of Object.entries(scores)) {
    if (!ids.has(id)) continue;
    if (raw === null || raw === "" || raw === undefined) {
      stmts.push(env.DB.prepare("DELETE FROM marks WHERE student_id = ? AND subject_id = ? AND exam_name = ?").bind(id, s.subjectId, exam)); cleared++; continue;
    }
    const v = Number(raw);
    if (!isFinite(v) || v < 0) return fail(400, `A score for ${id} is not a valid number`);
    if (v > max) return fail(400, `A score is higher than the full mark of ${max}`);
    stmts.push(env.DB.prepare(
      `INSERT INTO marks (student_id, subject_id, exam_name, score, max_score, graded_by, date_graded) VALUES (?,?,?,?,?,?,?)
       ON CONFLICT(student_id, subject_id, exam_name) DO UPDATE SET score = excluded.score, max_score = excluded.max_score, graded_by = excluded.graded_by, date_graded = excluded.date_graded`
    ).bind(id, s.subjectId, exam, v, max, user.id, today)); saved++;
  }
  // keep one full mark for the whole exam
  stmts.push(env.DB.prepare("UPDATE marks SET max_score = ? WHERE subject_id = ? AND exam_name = ?").bind(max, s.subjectId, exam));
  // lowering the full mark must not leave a saved score above it
  const existing = (await env.DB.prepare("SELECT student_id AS id, score FROM marks WHERE subject_id = ? AND exam_name = ?").bind(s.subjectId, exam).all()).results;
  if (existing.some((r) => !(r.id in scores) && r.score > max)) return fail(400, "Some saved scores are higher than this full mark. Re-enter those scores first.");
  await env.DB.batch(stmts);
  return json({ ok: true, saved, cleared });
};

handlers["POST /api/teacher/marks/delete-exam"] = async (request, env, user) => {
  const body = await readBody(request);
  const s = body && (await ownSubject(env, user, String(body.subjectId || "")));
  if (!s) return noSubject();
  await env.DB.prepare("DELETE FROM marks WHERE subject_id = ? AND exam_name = ?").bind(s.subjectId, String(body.exam || "")).run();
  return json({ ok: true });
};

// ----- optional papers: who takes the subject (admin, or the subject's own teacher) -----
handlers["GET /api/enrolment"] = async (request, env, user) => {
  const s = await ownSubject(env, user, qs(request, "subjectId"));
  if (!s) return noSubject();
  if (!s.optional) return fail(400, "This subject is not an optional paper");
  const [all, mine] = await Promise.all([
    env.DB.prepare("SELECT student_id AS studentId, name, roll_no AS rollNo FROM students WHERE class = ? ORDER BY CAST(roll_no AS INTEGER), roll_no").bind(s.class).all(),
    env.DB.prepare("SELECT student_id FROM subject_students WHERE subject_id = ?").bind(s.subjectId).all(),
  ]);
  return json({ subject: s, students: all.results, enrolled: mine.results.map((r) => r.student_id) });
};

handlers["POST /api/enrolment"] = async (request, env, user) => {
  const body = await readBody(request);
  const s = body && (await ownSubject(env, user, String(body.subjectId || "")));
  if (!s) return noSubject();
  if (!s.optional) return fail(400, "This subject is not an optional paper");
  const inClass = new Set((await env.DB.prepare("SELECT student_id FROM students WHERE class = ?").bind(s.class).all()).results.map((r) => r.student_id));
  const want = new Set((Array.isArray(body.studentIds) ? body.studentIds : []).map(String).filter((id) => inClass.has(id)));
  const have = new Set((await env.DB.prepare("SELECT student_id FROM subject_students WHERE subject_id = ?").bind(s.subjectId).all()).results.map((r) => r.student_id));
  const today = todayIST(), stmts = [];
  for (const id of have) if (!want.has(id)) stmts.push(env.DB.prepare("DELETE FROM subject_students WHERE subject_id = ? AND student_id = ?").bind(s.subjectId, id));
  for (const id of want) if (!have.has(id)) stmts.push(env.DB.prepare("INSERT INTO subject_students (subject_id, student_id, joined_on) VALUES (?,?,?)").bind(s.subjectId, id, today));
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true, enrolled: want.size });
};

// Timetable for one class, with the subject names (for teachers and students).
handlers["GET /api/timetable"] = async (request, env) => {
  const cls = qs(request, "class");
  const [tt, subs] = await Promise.all([
    env.DB.prepare("SELECT day, p1, p2, p3, p4 FROM timetable WHERE class = ?").bind(cls).all(),
    env.DB.prepare("SELECT subject_id AS subjectId, name FROM subjects WHERE class = ?").bind(cls).all(),
  ]);
  return json({ timetable: tt.results, subjects: subs.results });
};

// Who may call what. Anything not listed here needs no login (login, logout, setup).
const ADMIN_ONLY = [
  "GET /api/admin/students", "POST /api/admin/students/import", "POST /api/admin/students/delete", "POST /api/admin/students/delete-many", "POST /api/admin/users/delete",
  "GET /api/admin/subjects", "POST /api/admin/subjects", "POST /api/admin/subjects/assign", "POST /api/admin/subjects/update", "POST /api/admin/subjects/delete",
  "GET /api/admin/timetable", "POST /api/admin/timetable",
  "GET /api/admin/promote-preview", "POST /api/admin/promote", "POST /api/admin/clear-attendance",
  "POST /api/admin/past-results/import",
];
const ACCESS = {
  ...Object.fromEntries(ADMIN_ONLY.map((k) => [k, ["admin"]])),
  "GET /api/me": ROLES,
  ...Object.fromEntries([
    "GET /api/teacher/subjects", "GET /api/teacher/roster", "GET /api/teacher/attendance", "POST /api/teacher/attendance",
    "GET /api/teacher/attendance-history", "GET /api/teacher/summary", "GET /api/teacher/register",
    "GET /api/teacher/marks", "POST /api/teacher/marks", "POST /api/teacher/marks/delete-exam",
  ].map((k) => [k, ["teacher", "coordinator"]])),
  "GET /api/enrolment": ["admin", "teacher", "coordinator"],
  "POST /api/enrolment": ["admin", "teacher", "coordinator"],
  "GET /api/timetable": ROLES,
  "POST /api/change-password": ROLES,
  "GET /api/admin/teachers": ["admin"],
  "POST /api/admin/teachers": ["admin"],
  "POST /api/admin/reset-password": ["admin"],
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const key = `${request.method} ${url.pathname}`;
    const handler = handlers[key];
    if (!handler) return fail(404, "Not found");

    // Writes must come from our own pages (blocks cross-site form posts).
    if (request.method !== "GET") {
      const origin = request.headers.get("origin");
      if (origin && origin !== url.origin) return fail(403, "Cross-site request blocked");
    }

    try {
      const allowed = ACCESS[key];
      let user = null;
      if (allowed) {
        user = await currentUser(request, env);
        if (!user) return fail(401, "Please log in");
        if (!allowed.includes(user.role)) return fail(403, "You do not have permission for this");
        // A user still on a default password may only change it.
        if (user.must_change && key !== "POST /api/change-password" && key !== "GET /api/me") {
          return fail(403, "Please change your password first");
        }
      }
      return await handler(request, env, user);
    } catch (err) {
      console.error(err);
      return fail(500, "Server error");
    }
  },
};
