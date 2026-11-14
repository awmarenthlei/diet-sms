-- DIET Student Management System: database schema (Cloudflare D1 / SQLite)
-- Paste this whole file into the D1 console once. Safe to re-run.

CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  login       TEXT NOT NULL UNIQUE,             -- lowercase: student Login ID, or teacher e-mail, or "admin"
  name        TEXT NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('admin','teacher','coordinator','student')),
  pw          TEXT NOT NULL,                    -- pbkdf2$iterations$salt$hash
  must_change INTEGER NOT NULL DEFAULT 1,       -- 1 = still on the default password
  student_id  TEXT UNIQUE,                      -- only for role = student
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  INTEGER NOT NULL                  -- unix seconds
);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_fail (
  login        TEXT PRIMARY KEY,
  fails        INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
  student_id       TEXT PRIMARY KEY,            -- e.g. III_Sem_06 or 2027-2029_I_Sem_01
  name             TEXT NOT NULL,
  roll_no          TEXT NOT NULL,
  class            TEXT NOT NULL,               -- I Sem, II Sem, III Sem, IV Sem, Alumni
  semester         TEXT NOT NULL,
  batch            TEXT,
  last_promoted_on TEXT
);
CREATE INDEX IF NOT EXISTS idx_students_class ON students(class);

CREATE TABLE IF NOT EXISTS subjects (
  subject_id TEXT PRIMARY KEY,                  -- e.g. MAT101
  name       TEXT NOT NULL,
  class      TEXT NOT NULL,
  teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  optional   INTEGER NOT NULL DEFAULT 0          -- 1 = optional paper: only enrolled students take it
);
CREATE INDEX IF NOT EXISTS idx_subjects_teacher ON subjects(teacher_id);

-- Students enrolled in an optional subject (cleared when students are promoted).
CREATE TABLE IF NOT EXISTS subject_students (
  subject_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  joined_on  TEXT,
  PRIMARY KEY (subject_id, student_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_subject_students_student ON subject_students(student_id);

CREATE TABLE IF NOT EXISTS timetable (
  class TEXT NOT NULL,
  day   TEXT NOT NULL,
  p1 TEXT, p2 TEXT, p3 TEXT, p4 TEXT,           -- subject_id per period
  PRIMARY KEY (class, day)
);

-- One row per class session; one small row per student in att_marks.
CREATE TABLE IF NOT EXISTS att_sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  date       TEXT NOT NULL,                     -- YYYY-MM-DD
  subject_id TEXT NOT NULL,
  period     INTEGER NOT NULL,
  class      TEXT NOT NULL,
  marked_by  INTEGER REFERENCES users(id),
  UNIQUE (date, subject_id, period)
);
CREATE INDEX IF NOT EXISTS idx_att_sessions_subject ON att_sessions(subject_id, date);

CREATE TABLE IF NOT EXISTS att_marks (
  session_id INTEGER NOT NULL REFERENCES att_sessions(id) ON DELETE CASCADE,
  student_id TEXT NOT NULL,
  present    INTEGER NOT NULL,                  -- 1 present, 0 absent (exempt students have no row)
  PRIMARY KEY (session_id, student_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_att_marks_student ON att_marks(student_id, session_id);

CREATE TABLE IF NOT EXISTS marks (
  student_id  TEXT NOT NULL,
  subject_id  TEXT NOT NULL,
  exam_name   TEXT NOT NULL,
  score       REAL NOT NULL,
  max_score   REAL NOT NULL,
  graded_by   INTEGER REFERENCES users(id),
  date_graded TEXT,
  PRIMARY KEY (student_id, subject_id, exam_name)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS past_results (
  student_id        TEXT NOT NULL,
  past_semester     TEXT NOT NULL,
  subject_id        TEXT NOT NULL,
  subject_name      TEXT,
  internal_obtained REAL, internal_full REAL,
  external_obtained REAL, external_full REAL,
  status            TEXT,
  PRIMARY KEY (student_id, past_semester, subject_id)
) WITHOUT ROWID;
