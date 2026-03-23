const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'room-ai-pro-secret-key-change-me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'app.db');

// --- Middleware ---
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// --- Database Setup ---
const fs = require('fs');
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
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
  );
  CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    points_used INTEGER DEFAULT 0,
    detail TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Default settings
const defaultSettings = {
  gemini_api_key: '',
  gemini_model: 'gemini-2.0-flash-preview-image-generation',
  points_per_gen: '1',
  default_points: '3',
  site_name: '界象策畫所 Pro',
  allow_register: 'true'
};
const upsertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
for (const [k, v] of Object.entries(defaultSettings)) upsertSetting.run(k, v);

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE is_admin = 1').get();
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password, display_name, points, is_admin) VALUES (?, ?, ?, ?, ?)')
    .run('admin', hash, '系統管理員', 9999, 1);
  console.log('✅ Default admin created: admin / admin123');
}

// --- Helpers ---
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '請先登入' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, username, display_name, points, sub_type, sub_expires, is_admin, is_banned FROM users WHERE id = ?').get(decoded.id);
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
  const { username, password, display_name } = req.body;
  if (getSetting('allow_register') !== 'true') return res.status(403).json({ error: '目前不開放註冊' });
  if (!username || !password) return res.status(400).json({ error: '請填寫帳號和密碼' });
  if (username.length < 3) return res.status(400).json({ error: '帳號至少 3 個字元' });
  if (password.length < 6) return res.status(400).json({ error: '密碼至少 6 個字元' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: '帳號已被使用' });

  const hash = bcrypt.hashSync(password, 10);
  const defaultPts = parseInt(getSetting('default_points')) || 0;
  const result = db.prepare('INSERT INTO users (username, password, display_name, points) VALUES (?, ?, ?, ?)')
    .run(username, hash, display_name || username, defaultPts);

  if (defaultPts > 0) {
    db.prepare('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)')
      .run(result.lastInsertRowid, 'register_bonus', 0, `註冊贈送 ${defaultPts} 點`);
  }

  const token = jwt.sign({ id: result.lastInsertRowid }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: result.lastInsertRowid, username, display_name: display_name || username, points: defaultPts, sub_type: 'none', is_admin: 0 } });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '請填寫帳號和密碼' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: '帳號或密碼錯誤' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: '帳號或密碼錯誤' });
  if (user.is_banned) return res.status(403).json({ error: '帳號已被停權' });

  db.prepare('UPDATE users SET last_login = datetime("now","localtime") WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({
    token,
    user: { id: user.id, username: user.username, display_name: user.display_name, points: user.points, sub_type: user.sub_type, sub_expires: user.sub_expires, is_admin: user.is_admin }
  });
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

  try {
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
      db.prepare('UPDATE users SET points = points - ? WHERE id = ?').run(cost, user.id);
    }
    db.prepare('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)')
      .run(user.id, 'generate', hasSub ? 0 : cost, hasSub ? '訂閱用戶免扣點' : `扣除 ${cost} 點`);

    const updated = db.prepare('SELECT points FROM users WHERE id = ?').get(user.id);
    res.json({ ...data, remaining_points: updated.points, subscription_active: hasSub });
  } catch (e) {
    console.error('Gemini API Error:', e);
    res.status(500).json({ error: 'AI 服務連線失敗: ' + e.message });
  }
});

// =================== ADMIN ROUTES ===================
app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_admin = 0').get().c;
  const activeSubUsers = db.prepare("SELECT COUNT(*) as c FROM users WHERE sub_type != 'none' AND sub_expires > datetime('now','localtime')").get().c;
  const todayGens = db.prepare("SELECT COUNT(*) as c FROM usage_log WHERE action = 'generate' AND date(created_at) = date('now','localtime')").get().c;
  const totalGens = db.prepare("SELECT COUNT(*) as c FROM usage_log WHERE action = 'generate'").get().c;
  const totalPointsUsed = db.prepare("SELECT COALESCE(SUM(points_used),0) as c FROM usage_log WHERE action = 'generate'").get().c;
  res.json({ totalUsers, activeSubUsers, todayGens, totalGens, totalPointsUsed });
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const users = db.prepare('SELECT id, username, display_name, points, sub_type, sub_expires, is_admin, is_banned, created_at, last_login FROM users ORDER BY id DESC').all();
  res.json(users);
});

app.put('/api/admin/users/:id/points', authMiddleware, adminMiddleware, (req, res) => {
  const { amount, action } = req.body; // action: 'add' | 'set'
  const userId = parseInt(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: '用戶不存在' });

  if (action === 'set') {
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(amount, userId);
  } else {
    db.prepare('UPDATE users SET points = points + ? WHERE id = ?').run(amount, userId);
  }
  db.prepare('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)')
    .run(userId, 'admin_points', 0, `管理員${action === 'set' ? '設定' : '加'}點數: ${amount}`);

  const updated = db.prepare('SELECT points FROM users WHERE id = ?').get(userId);
  res.json({ success: true, points: updated.points });
});

app.put('/api/admin/users/:id/subscription', authMiddleware, adminMiddleware, (req, res) => {
  const { sub_type, days } = req.body;
  const userId = parseInt(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: '用戶不存在' });

  let expires = null;
  if (sub_type !== 'none' && days) {
    const d = new Date();
    d.setDate(d.getDate() + parseInt(days));
    expires = d.toISOString().slice(0, 19).replace('T', ' ');
  }

  db.prepare('UPDATE users SET sub_type = ?, sub_expires = ? WHERE id = ?').run(sub_type, expires, userId);
  db.prepare('INSERT INTO usage_log (user_id, action, points_used, detail) VALUES (?, ?, ?, ?)')
    .run(userId, 'admin_sub', 0, `管理員設定訂閱: ${sub_type}, ${days || 0} 天`);

  res.json({ success: true, sub_type, sub_expires: expires });
});

app.put('/api/admin/users/:id/ban', authMiddleware, adminMiddleware, (req, res) => {
  const { is_banned } = req.body;
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) return res.status(400).json({ error: '不能停權自己' });
  db.prepare('UPDATE users SET is_banned = ? WHERE id = ?').run(is_banned ? 1 : 0, userId);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) return res.status(400).json({ error: '不能刪除自己' });
  db.prepare('DELETE FROM usage_log WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  res.json({ success: true });
});

app.get('/api/admin/logs', authMiddleware, adminMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const logs = db.prepare(`
    SELECT l.*, u.username, u.display_name
    FROM usage_log l LEFT JOIN users u ON l.user_id = u.id
    ORDER BY l.id DESC LIMIT ?
  `).all(limit);
  res.json(logs);
});

app.get('/api/admin/settings', authMiddleware, adminMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM settings').all();
  const obj = {};
  rows.forEach(r => obj[r.key] = r.value);
  res.json(obj);
});

app.put('/api/admin/settings', authMiddleware, adminMiddleware, (req, res) => {
  const updates = req.body;
  const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  for (const [k, v] of Object.entries(updates)) stmt.run(k, String(v));
  res.json({ success: true });
});

app.put('/api/admin/users/:id/password', authMiddleware, adminMiddleware, (req, res) => {
  const { password } = req.body;
  const userId = parseInt(req.params.id);
  if (!password || password.length < 6) return res.status(400).json({ error: '密碼至少 6 個字元' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, userId);
  res.json({ success: true });
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🏠 界象策畫所 Pro running on port ${PORT}`);
  console.log(`   管理後台: http://localhost:${PORT}/admin`);
  console.log(`   預設管理員: admin / admin123`);
});
