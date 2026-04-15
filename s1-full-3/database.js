const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const path     = require('path');
const fs       = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 's1studios.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'user',
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
  );

  CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    type       TEXT NOT NULL,
    meta       TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_events_user  ON events(user_id);
  CREATE INDEX IF NOT EXISTS idx_events_type  ON events(type);
  CREATE INDEX IF NOT EXISTS idx_events_date  ON events(created_at);
`);

// ── Default admin ─────────────────────────────────────────────────────────────
if (!db.prepare('SELECT id FROM users WHERE role = ? LIMIT 1').get('admin')) {
  db.prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)').run(
    'admin', bcrypt.hashSync('admin123', 10), 'admin'
  );
  console.log('✅ Admin criado — usuário: admin  senha: admin123');
}

// ── Cached statements ─────────────────────────────────────────────────────────
const stmt = {
  findByUsername:  db.prepare('SELECT * FROM users WHERE username = ?'),
  findById:        db.prepare('SELECT * FROM users WHERE id = ?'),
  listUsers:       db.prepare('SELECT id,username,role,active,created_at,last_login FROM users ORDER BY id'),
  createUser:      db.prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)'),
  updateLastLogin: db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?"),
  setActive:       db.prepare('UPDATE users SET active = ? WHERE id = ?'),
  deleteUser:      db.prepare('DELETE FROM users WHERE id = ?'),
  updatePassword:  db.prepare('UPDATE users SET password = ? WHERE id = ?'),
  logEvent:        db.prepare('INSERT INTO events (user_id,type,meta) VALUES (?,?,?)'),
  eventsByUser:    db.prepare('SELECT * FROM events WHERE user_id = ? ORDER BY created_at DESC LIMIT 200'),
  // FIX #6: usar CASE WHEN em vez de SUM(col = val) — compatível com SQLite
  summary: db.prepare(`
    SELECT
      u.id, u.username, u.role, u.active, u.last_login, u.created_at,
      COUNT(e.id) AS total_events,
      SUM(CASE WHEN e.type='analysis'      THEN 1 ELSE 0 END) AS analyses,
      SUM(CASE WHEN e.type='download'      THEN 1 ELSE 0 END) AS downloads,
      SUM(CASE WHEN e.type='transcription' THEN 1 ELSE 0 END) AS transcriptions,
      SUM(CASE WHEN e.type='storyboard'    THEN 1 ELSE 0 END) AS storyboards,
      SUM(CASE WHEN e.type='api_call'      THEN 1 ELSE 0 END) AS api_calls,
      SUM(CASE WHEN e.type='protection'    THEN 1 ELSE 0 END) AS protections,
      MAX(e.created_at) AS last_activity
    FROM users u
    LEFT JOIN events e ON e.user_id = u.id
    GROUP BY u.id
    ORDER BY total_events DESC
  `),
  // FIX #6: CASE WHEN aqui também
  daily: db.prepare(`
    SELECT
      date(created_at) AS day,
      COUNT(*) AS total,
      SUM(CASE WHEN type='analysis' THEN 1 ELSE 0 END) AS analyses,
      SUM(CASE WHEN type='download' THEN 1 ELSE 0 END) AS downloads
    FROM events
    WHERE created_at >= date('now','-30 days')
    GROUP BY day
    ORDER BY day
  `),
  recent: db.prepare(`
    SELECT e.id, e.user_id, e.type, e.meta, e.created_at, u.username
    FROM events e
    JOIN users u ON u.id = e.user_id
    ORDER BY e.created_at DESC
    LIMIT ?
  `),
};

const Users = {
  findByUsername:  (u)       => stmt.findByUsername.get(u),
  findById:        (id)      => stmt.findById.get(id),
  list:            ()        => stmt.listUsers.all(),
  create:          (u,h,r)   => stmt.createUser.run(u,h,r),
  updateLastLogin: (id)      => stmt.updateLastLogin.run(id),
  setActive:       (id,v)    => stmt.setActive.run(v,id),
  delete:          (id)      => stmt.deleteUser.run(id),
  updatePassword:  (id,h)    => stmt.updatePassword.run(h,id),
};

const Events = {
  log:     (userId, type, meta=null) => stmt.logEvent.run(userId, type, meta ? JSON.stringify(meta) : null),
  byUser:  (userId)                  => stmt.eventsByUser.all(userId),
  summary: ()                        => stmt.summary.all(),
  daily:   ()                        => stmt.daily.all(),
  recent:  (limit=50)                => stmt.recent.all(limit),
};

module.exports = { db, Users, Events };
