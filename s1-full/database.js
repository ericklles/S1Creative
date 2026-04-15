const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 's1studios.db'));

// Performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Tabelas ──────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user',
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_login  TEXT
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    token       TEXT UNIQUE NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    type        TEXT NOT NULL,
    meta        TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── Cria admin padrão se não existir ─────────────────────────────────────────
const bcrypt = require('bcryptjs');
const adminExists = db.prepare('SELECT id FROM users WHERE role = ? LIMIT 1').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`).run('admin', hash, 'admin');
  console.log('✅ Admin criado — usuário: admin  senha: admin123');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const Users = {
  findByUsername: (username) => db.prepare('SELECT * FROM users WHERE username = ?').get(username),
  findById:       (id)       => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
  list:           ()         => db.prepare('SELECT id,username,role,active,created_at,last_login FROM users ORDER BY id').all(),
  create:         (username, hash, role) =>
    db.prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)').run(username, hash, role),
  updateLastLogin:(id)       => db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(id),
  setActive:      (id, val)  => db.prepare('UPDATE users SET active = ? WHERE id = ?').run(val, id),
  delete:         (id)       => db.prepare('DELETE FROM users WHERE id = ?').run(id),
  updatePassword: (id, hash) => db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, id),
};

const Events = {
  log: (userId, type, meta = null) =>
    db.prepare('INSERT INTO events (user_id,type,meta) VALUES (?,?,?)').run(userId, type, meta ? JSON.stringify(meta) : null),

  byUser: (userId) =>
    db.prepare('SELECT * FROM events WHERE user_id = ? ORDER BY created_at DESC LIMIT 200').all(userId),

  countByType: (userId, type) =>
    db.prepare('SELECT COUNT(*) as n FROM events WHERE user_id = ? AND type = ?').get(userId, type)?.n || 0,

  // Métricas globais por usuário
  summary: () => db.prepare(`
    SELECT
      u.id, u.username, u.role, u.active, u.last_login, u.created_at,
      COUNT(e.id)                                             AS total_events,
      SUM(e.type = 'analysis')                               AS analyses,
      SUM(e.type = 'download')                               AS downloads,
      SUM(e.type = 'transcription')                          AS transcriptions,
      SUM(e.type = 'storyboard')                             AS storyboards,
      SUM(e.type = 'api_call')                               AS api_calls,
      MAX(e.created_at)                                      AS last_activity
    FROM users u
    LEFT JOIN events e ON e.user_id = u.id
    GROUP BY u.id
    ORDER BY total_events DESC
  `).all(),

  // Atividade diária (últimos 30 dias)
  daily: () => db.prepare(`
    SELECT
      date(created_at) AS day,
      COUNT(*) AS total,
      SUM(type='analysis') AS analyses,
      SUM(type='download') AS downloads
    FROM events
    WHERE created_at >= date('now','-30 days')
    GROUP BY day
    ORDER BY day
  `).all(),

  // Top eventos recentes
  recent: (limit = 50) => db.prepare(`
    SELECT e.*, u.username
    FROM events e
    JOIN users u ON u.id = e.user_id
    ORDER BY e.created_at DESC
    LIMIT ?
  `).all(limit),
};

module.exports = { db, Users, Events };
