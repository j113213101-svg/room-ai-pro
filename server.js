const express = require('express');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'room-ai-pro-secret-key-change-me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'app.db');

// --- Middleware ---
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// --- Database (sql.js — pure JS, no native compilation) ---
let db = null;

function saveDatabase() {
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  } catch (e) {
    console.error('DB save error:', e.message);
  }
}

// Auto-save every 30 seconds
setInterval(() => { if (db) saveDatabase(); }, 30000);

async function initDatabase() {
  const dataDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

  const SQL = await initSqlJs();

  // Load existing DB or create new
  if (fs.existsSync(DB_PATH)) {
    try {
      const fileBuffer = fs.readFileSync(DB_PATH);
      db = new SQL.Database(fileBuffer);
      console.log('Loaded existing database from', DB_PATH);
    } catch (e) {
      console.error('Failed to load DB, creating new:', e.message);
      db = new SQL.Database();
    }
  } else {
    db = new SQL.Database();
    console.log('Created new database');
  }

  db.run('PRAGMA foreign_keys = ON');

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    points INTEGER DEFAULT 0,
    sub_type TEXT DEFAULT 'none',
    sub_expires TEXT,
    is_admin INTEGER DEFAULT 0,
    is_banned INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    last_login TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    points_used INTEGER DEFAULT 0,
    detail TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  // Default settings
  const defaultSettings = {
    gemini_api_key: '',
    gemini_model: 'gemini-2.0-flash-preview-image-generation',
    points_per_gen: '1',
    default_points: '3',
    site_name: '界象策畫所 Pro',
    allow_register: 'true'
  };
  for (const [k, v] of Object.entries(defaultSettings)) {
    db.run('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', [k, v]);
  }

  // Create default admin if not exists
  const adminRow = db.exec('SELECT id FROM users WHERE is_admin = 1');
  if (!adminRow.length || !adminRow[0].values.length) {
    const hash = bcrypt.hashSync('admin123', 10);
    db.run('INSERT INTO users (username, password, display_name, points, is_admin) VALUES (?, ?, ?, ?, ?)',
      ['admin', hash, '系統管理員', 9999, 1]);
    console.log('Default admin created: admin / admin123');
  }

  saveDatabase();
  console.log('Database initialized successfully');
}

// --- sql.js Helpers ---
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  let result = null;
  if (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    result = {};
    cols.forEach((c, i) => result[c] = vals[i]);
  }
  stmt.free();
  return result;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    const row = {};
    cols.forEach((c, i) => row[c] = vals[i]);
    results.push(row);
  }
  stmt.free();
  return results;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  const changes = db.getRowsModified();
  // For INSERT, get last insert rowid
  const lastId = dbGet('SELECT last_insert_rowid() as id');
  return { changes, lastInsertRowid: lastId ? lastId.id : 0 };
}

function getSetting(key) {
  const row = dbGet('SELECT value FROM settings WHERE key = ?', [key]);
  return row ? row.value : null;
}

// --- Auth Middleware ---
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '請先登入' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = dbGet('SELECT id, username, display_name, points, sub_type, sub_expires, is_admin, is_banned FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(401).json({ error: '用戶不存在' });
    if (user.is_banned) return res.status(403).json({ error: '帳號已被停權' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: '登入已過期，請重新登入' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: '需要管理員權限' });
  next();
}

function hasActiveSubscription(user) {
  if (user.sub_type === 'none' || !user.sub_type) return false;
  if (!user.sub_expires) return false;
  return new Date(user.sub_expires) > new Date();
}

// =================== AUTH ROUTES ===================
app.post('/api/auth/register', (req, res) => {
  try {
    const { username, password, display_name } = req.body;
    if (getSetting('allow_register') !== 'true') return res.status(403).json({ error: '目前不開放註冊' });
    if (!username || !password) return res.status(400).json({ error: '請填寫帳號和密碼' });
    if (username.length < 3) return res.status(400).json({ error: '帳號至少 3 個字元' });
    if (password.length < 6) return res.status(400).json({ error: '密碼至少 6 個字元' });

    const existing = dbGet('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return res.status(400).json({ error: '帳號已被使用' });

    const hash = bcrypt.hashSync(password, 10);
    const defaultPts = parseInt(getSetting('default_points')) || 0;
    const result = dbRun('INSERT INTO users (username, password, display_name, points) VALUES (?, ?, ?, ?)',
      [username, hash, display_name || username, defaultPts]);

    if (defaultPts > 0) {
      dbRun('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)',
        [result.lastInsertRowid, 'register_bonus', 0, `註冊贈送 ${defaultPts} 點`]);
    }

    saveDatabase();
    const token = jwt.sign({ id: result.lastInsertRowid }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: result.lastInsertRowid, username, display_name: display_name || username, points: defaultPts, sub_type: 'none', is_admin: 0 } });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: '註冊失敗: ' + e.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '請填寫帳號和密碼' });

    const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(401).json({ error: '帳號或密碼錯誤' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: '帳號或密碼錯誤' });
    if (user.is_banned) return res.status(403).json({ error: '帳號已被停權' });

    dbRun('UPDATE users SET last_login = datetime("now","localtime") WHERE id = ?', [user.id]);
    saveDatabase();

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: { id: user.id, username: user.username, display_name: user.display_name, points: user.points, sub_type: user.sub_type, sub_expires: user.sub_expires, is_admin: user.is_admin }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: '登入失敗: ' + e.message });
  }
});

// =================== USER ROUTES ===================
app.get('/api/user/profile', authMiddleware, (req, res) => {
  const u = req.user;
  res.json({
    id: u.id, username: u.username, display_name: u.display_name,
    points: u.points, sub_type: u.sub_type, sub_expires: u.sub_expires,
    is_admin: u.is_admin, has_subscription: hasActiveSubscription(u)
  });
});

// =================== AI GENERATE PROXY ===================
app.post('/api/generate', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    const cost = parseInt(getSetting('points_per_gen')) || 1;
    const hasSub = hasActiveSubscription(user);

    if (!hasSub && user.points < cost) {
      return res.status(402).json({ error: `點數不足，需要 ${cost} 點，目前剩餘 ${user.points} 點` });
    }

    const apiKey = getSetting('gemini_api_key');
    if (!apiKey) return res.status(500).json({ error: '系統 API Key 未設定，請聯繫管理員' });

    const model = getSetting('gemini_model') || 'gemini-2.0-flash-preview-image-generation';
    const { contents } = req.body;
    if (!contents) return res.status(400).json({ error: '缺少生成內容' });

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents,
        generationConfig: { responseModalities: ['TEXT', 'IMAGE'] }
      })
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ error: data.error?.message || 'AI 生成失敗' });
    }

    // Deduct points (skip for subscribers)
    if (!hasSub) {
      dbRun('UPDATE users SET points = points - ? WHERE id = ?', [cost, user.id]);
    }
    dbRun('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)',
      [user.id, 'generate', hasSub ? 0 : cost, hasSub ? '訂閱用戶免扣點' : `扣除 ${cost} 點`]);
    saveDatabase();

    const updated = dbGet('SELECT points FROM users WHERE id = ?', [user.id]);
    res.json({ ...data, remaining_points: updated.points, subscription_active: hasSub });
  } catch (e) {
    console.error('Gemini API Error:', e);
    res.status(500).json({ error: 'AI 服務連線失敗: ' + e.message });
  }
});

// =================== ADMIN ROUTES ===================
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const totalUsers = dbGet('SELECT COUNT(*) as c FROM users WHERE is_admin = 0').c;
    const activeSubUsers = dbGet("SELECT COUNT(*) as c FROM users WHERE sub_type != 'none' AND sub_expires > datetime('now','localtime')").c;
    const todayGens = dbGet("SELECT COUNT(*) as c FROM usage_log WHERE action = 'generate' AND date(created_at) = date('now','localtime')").c;
    const totalGens = dbGet("SELECT COUNT(*) as c FROM usage_log WHERE action = 'generate'").c;
    const totalPointsUsed = dbGet("SELECT COALESCE(SUM(points_used),0) as c FROM usage_log WHERE action = 'generate'").c;
    res.json({ totalUsers, activeSubUsers, todayGens, totalGens, totalPointsUsed });
  } catch (e) {
    console.error('Dashboard error:', e);
    res.status(500).json({ error: '取得儀表板資料失敗' });
  }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const users = dbAll('SELECT id, username, display_name, points, sub_type, sub_expires, is_admin, is_banned, created_at, last_login FROM users ORDER BY id DESC');
    res.json(users);
  } catch (e) {
    console.error('Get users error:', e);
    res.status(500).json({ error: '取得用戶列表失敗' });
  }
});

app.put('/api/admin/users/:id/points', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const { amount, action } = req.body;
    const userId = parseInt(req.params.id);
    const user = dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) return res.status(404).json({ error: '用戶不存在' });

    if (action === 'set') {
      dbRun('UPDATE users SET points = ? WHERE id = ?', [amount, userId]);
    } else {
      dbRun('UPDATE users SET points = points + ? WHERE id = ?', [amount, userId]);
    }
    dbRun('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)',
      [userId, 'admin_points', 0, `管理員${action === 'set' ? '設定' : '加'}點數: ${amount}`]);
    saveDatabase();

    const updated = dbGet('SELECT points FROM users WHERE id = ?', [userId]);
    res.json({ success: true, points: updated.points });
  } catch (e) {
    console.error('Update points error:', e);
    res.status(500).json({ error: '更新點數失敗' });
  }
});

app.put('/api/admin/users/:id/subscription', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const { sub_type, days } = req.body;
    const userId = parseInt(req.params.id);
    const user = dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) return res.status(404).json({ error: '用戶不存在' });

    let expires = null;
    if (sub_type !== 'none' && days) {
      const d = new Date();
      d.setDate(d.getDate() + parseInt(days));
      expires = d.toISOString().slice(0, 19).replace('T', ' ');
    }

    dbRun('UPDATE users SET sub_type = ?, sub_expires = ? WHERE id = ?', [sub_type, expires, userId]);
    dbRun('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)',
      [userId, 'admin_sub', 0, `管理員設定訂閱: ${sub_type}, ${days || 0} 天`]);
    saveDatabase();

    res.json({ success: true, sub_type, sub_expires: expires });
  } catch (e) {
    console.error('Update subscription error:', e);
    res.status(500).json({ error: '更新訂閱失敗' });
  }
});

app.put('/api/admin/users/:id/ban', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const { is_banned } = req.body;
    const userId = parseInt(req.params.id);
    if (userId === req.user.id) return res.status(400).json({ error: '不能停權自己' });
    dbRun('UPDATE users SET is_banned = ? WHERE id = ?', [is_banned ? 1 : 0, userId]);
    saveDatabase();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '操作失敗' });
  }
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (userId === req.user.id) return res.status(400).json({ error: '不能刪除自己' });
    dbRun('DELETE FROM usage_log WHERE user_id = ?', [userId]);
    dbRun('DELETE FROM users WHERE id = ?', [userId]);
    saveDatabase();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '刪除用戶失敗' });
  }
});

app.get('/api/admin/logs', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const logs = dbAll(`
      SELECT l.*, u.username, u.display_name
      FROM usage_log l LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.id DESC LIMIT ?
    `, [limit]);
    res.json(logs);
  } catch (e) {
    res.status(500).json({ error: '取得日誌失敗' });
  }
});

app.get('/api/admin/settings', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const rows = dbAll('SELECT * FROM settings');
    const obj = {};
    rows.forEach(r => obj[r.key] = r.value);
    res.json(obj);
  } catch (e) {
    res.status(500).json({ error: '取得設定失敗' });
  }
});

app.put('/api/admin/settings', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const updates = req.body;
    for (const [k, v] of Object.entries(updates)) {
      dbRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', [k, String(v)]);
    }
    saveDatabase();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '更新設定失敗' });
  }
});

app.put('/api/admin/users/:id/password', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const { password } = req.body;
    const userId = parseInt(req.params.id);
    if (!password || password.length < 6) return res.status(400).json({ error: '密碼至少 6 個字元' });
    const hash = bcrypt.hashSync(password, 10);
    dbRun('UPDATE users SET password = ? WHERE id = ?', [hash, userId]);
    saveDatabase();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '重設密碼失敗' });
  }
});

// =================== STATIC FILES ===================
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// =================== START SERVER ===================
initDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`界象策畫所 Pro running on port ${PORT}`);
    console.log(`管理後台: http://localhost:${PORT}/admin`);
    console.log(`預設管理員: admin / admin123`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
