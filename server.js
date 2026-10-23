/**
 * SpotSim Backend — zero npm dependencies (Node built-ins only)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3847;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

const dataDir = path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'db.json');
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

function loadDb() {
  try { return JSON.parse(fs.readFileSync(dbPath, 'utf8')); }
  catch {
    return { settings: { default_starting_balance: 10000 }, users: [], nextId: 1, tokens: {}, requests: [], nextRequestId: 1 };
  }
}
function saveDb() {
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
}

let db = loadDb();
if (!db.tokens) db.tokens = {};
if (!db.requests) db.requests = [];
if (!db.nextRequestId) db.nextRequestId = 1;

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 32).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const h = crypto.scryptSync(password, salt, 32).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
}
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Seed admin
// Ensure admin exists with email
(function ensureAdmin() {
  let admin = db.users.find((u) => u.role === 'admin' || u.username.toLowerCase() === ADMIN_USER.toLowerCase());
  if (!admin) {
    const start = db.settings.default_starting_balance || 10000;
    const { salt, hash } = hashPassword(ADMIN_PASS);
    admin = {
      id: db.nextId++,
      username: ADMIN_USER,
      email: 'admin@spotsim.local',
      first_name: 'Admin',
      last_name: 'User',
      salt, password_hash: hash,
      role: 'admin',
      starting_balance: start,
      usdt: start,
      holdings: {},
      history: [],
      created_at: new Date().toISOString(),
      last_login: null,
    };
    db.users.push(admin);
    saveDb();
    console.log(`Admin: admin@spotsim.local / ${ADMIN_PASS}`);
  } else {
    if (!admin.email) { admin.email = 'admin@spotsim.local'; saveDb(); }
    if (!admin.first_name) { admin.first_name = 'Admin'; admin.last_name = 'User'; saveDb(); }
    console.log(`Admin login email: ${admin.email}`);
  }
})();

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    email: u.email || '',
    first_name: u.first_name || '',
    last_name: u.last_name || '',
    role: u.role,
    display_name: u.display_name || [u.first_name, u.last_name].filter(Boolean).join(' ') || u.username,
    starting_balance: u.starting_balance, usdt: u.usdt,
    holdings: u.holdings || {}, history: u.history || [],
    created_at: u.created_at, last_login: u.last_login,
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e6) reject(new Error('too large')); });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch { reject(new Error('Invalid JSON')); }
    });
  });
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  });
  res.end(body);
}

function getUserFromReq(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token || !db.tokens[token]) return null;
  const user = db.users.find((u) => u.id === db.tokens[token]);
  return user || null;
}

const mime = {
  '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css',
  '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml',
};

async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    });
    return res.end();
  }

  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;

  try {
    // ----- API -----
    if (p === '/api/register' && req.method === 'POST') {
      const body = await readBody(req);
      const first_name = String(body.first_name || '').trim();
      const last_name = String(body.last_name || '').trim();
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const confirm = String(body.confirm_password || body.confirmPassword || '');
      if (!first_name || first_name.length < 1 || first_name.length > 40)
        return send(res, 400, { error: 'First name is required' });
      if (!last_name || last_name.length < 1 || last_name.length > 40)
        return send(res, 400, { error: 'Last name is required' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return send(res, 400, { error: 'Valid email is required' });
      if (password.length < 6)
        return send(res, 400, { error: 'Password must be at least 6 characters' });
      if (password !== confirm)
        return send(res, 400, { error: 'Passwords do not match' });
      if (db.users.some((u) => (u.email || '').toLowerCase() === email))
        return send(res, 409, { error: 'Email already registered' });
      const start = Number(db.settings.default_starting_balance) || 10000;
      const { salt, hash } = hashPassword(password);
      const username = email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '').slice(0, 20) || 'user';
      let base = username, n = 1;
      while (db.users.some((u) => u.username.toLowerCase() === base.toLowerCase())) {
        base = username.slice(0, 16) + n;
        n++;
      }
      const user = {
        id: db.nextId++,
        username: base,
        email, first_name, last_name,
        display_name: first_name + ' ' + last_name,
        salt, password_hash: hash, role: 'user',
        starting_balance: start, usdt: start, holdings: {}, history: [],
        reset_token: null, reset_expires: null,
        created_at: new Date().toISOString(), last_login: null,
      };
      db.users.push(user);
      saveDb();
      const token = makeToken();
      db.tokens[token] = user.id;
      return send(res, 201, { token, user: publicUser(user) });
    }

    if (p === '/api/login' && req.method === 'POST') {
      const body = await readBody(req);
      const email = String(body.email || body.username || '').trim().toLowerCase();
      const password = String(body.password || '');
      const user = db.users.find((u) =>
        (u.email || '').toLowerCase() === email ||
        (u.username || '').toLowerCase() === email
      );
      if (!user || !verifyPassword(password, user.salt, user.password_hash))
        return send(res, 401, { error: 'Invalid email or password' });
      user.last_login = new Date().toISOString();
      saveDb();
      const token = makeToken();
      db.tokens[token] = user.id;
      return send(res, 200, { token, user: publicUser(user) });
    }

    if (p === '/api/me' && req.method === 'GET') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      return send(res, 200, { user: publicUser(user) });
    }

    if (p === '/api/portfolio' && req.method === 'GET') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      return send(res, 200, {
        usdt: user.usdt, holdings: user.holdings || {}, history: user.history || [],
        starting_balance: user.starting_balance,
      });
    }

    if (p === '/api/portfolio' && req.method === 'PUT') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      const body = await readBody(req);
      if (typeof body.usdt !== 'number' || body.usdt < 0)
        return send(res, 400, { error: 'Invalid usdt' });
      if (typeof body.holdings !== 'object' || !body.holdings)
        return send(res, 400, { error: 'Invalid holdings' });
      if (!Array.isArray(body.history))
        return send(res, 400, { error: 'Invalid history' });
      user.usdt = body.usdt;
      user.holdings = body.holdings;
      user.history = body.history.slice(0, 200);
      saveDb();
      return send(res, 200, { ok: true });
    }

    if (p === '/api/portfolio/reset' && req.method === 'POST') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      user.usdt = user.starting_balance;
      user.holdings = {};
      user.history = [];
      saveDb();
      return send(res, 200, { user: publicUser(user) });
    }

    if (p === '/api/admin/settings' && req.method === 'GET') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      if (user.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      return send(res, 200, { default_starting_balance: Number(db.settings.default_starting_balance) || 10000 });
    }

    if (p === '/api/admin/settings' && req.method === 'PUT') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      if (user.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      const body = await readBody(req);
      const bal = parseFloat(body.default_starting_balance);
      if (!Number.isFinite(bal) || bal < 0 || bal > 1e9)
        return send(res, 400, { error: 'Invalid starting balance' });
      db.settings.default_starting_balance = bal;
      saveDb();
      return send(res, 200, { default_starting_balance: bal });
    }

    if (p === '/api/admin/users' && req.method === 'GET') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      if (user.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      return send(res, 200, {
        users: db.users.map((u) => ({
          id: u.id, username: u.username, email: u.email || '',
          first_name: u.first_name || '', last_name: u.last_name || '',
          role: u.role,
          starting_balance: u.starting_balance, usdt: u.usdt,
          holdings_count: Object.keys(u.holdings || {}).length,
          trades: (u.history || []).length,
          created_at: u.created_at, last_login: u.last_login,
        })),
      });
    }

    const balMatch = p.match(/^\/api\/admin\/users\/(\d+)\/balance$/);
    if (balMatch && req.method === 'PUT') {
      const admin = getUserFromReq(req);
      if (!admin) return send(res, 401, { error: 'Not authenticated' });
      if (admin.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      const id = parseInt(balMatch[1], 10);
      const body = await readBody(req);
      const starting = parseFloat(body.starting_balance);
      if (!Number.isFinite(starting) || starting < 0)
        return send(res, 400, { error: 'Invalid starting_balance' });
      const target = db.users.find((u) => u.id === id);
      if (!target) return send(res, 404, { error: 'User not found' });
      target.starting_balance = starting;
      if (body.reset_now) {
        target.usdt = starting;
        target.holdings = {};
        target.history = [];
      }
      saveDb();
      return send(res, 200, { user: publicUser(target) });
    }

    const delMatch = p.match(/^\/api\/admin\/users\/(\d+)$/);
    if (delMatch && req.method === 'DELETE') {
      const admin = getUserFromReq(req);
      if (!admin) return send(res, 401, { error: 'Not authenticated' });
      if (admin.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      const id = parseInt(delMatch[1], 10);
      if (id === admin.id) return send(res, 400, { error: 'Cannot delete yourself' });
      const target = db.users.find((u) => u.id === id);
      if (!target) return send(res, 404, { error: 'User not found' });
      if (target.role === 'admin') return send(res, 400, { error: 'Cannot delete admin' });
      db.users = db.users.filter((u) => u.id !== id);
      saveDb();
      return send(res, 200, { ok: true });
    }


    if (p === '/api/me/password' && req.method === 'PUT') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      const body = await readBody(req);
      const current = String(body.current_password || '');
      const next = String(body.new_password || '');
      if (!verifyPassword(current, user.salt, user.password_hash)) {
        return send(res, 400, { error: 'Current password is incorrect' });
      }
      if (next.length < 6) {
        return send(res, 400, { error: 'New password must be at least 6 characters' });
      }
      const { salt, hash } = hashPassword(next);
      user.salt = salt;
      user.password_hash = hash;
      saveDb();
      return send(res, 200, { ok: true });
    }

    if (p === '/api/me/profile' && req.method === 'PUT') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      const body = await readBody(req);
      // optional display name
      if (body.display_name != null) {
        const dn = String(body.display_name).trim().slice(0, 40);
        user.display_name = dn;
      }
      saveDb();
      return send(res, 200, { user: publicUser(user) });
    }


    // ----- Money requests (deposit / withdraw need admin approval) -----
    if (p === '/api/money/request' && req.method === 'POST') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      const body = await readBody(req);
      const type = body.type === 'withdraw' ? 'withdraw' : 'deposit';
      const amount = parseFloat(body.amount);
      if (!Number.isFinite(amount) || amount <= 0) {
        return send(res, 400, { error: 'Invalid amount' });
      }
      if (type === 'withdraw' && amount > user.usdt + 1e-8) {
        return send(res, 400, { error: 'Insufficient USDT balance' });
      }
      const request = {
        id: db.nextRequestId++,
        user_id: user.id,
        username: user.username,
        type,
        amount,
        status: 'pending',
        created_at: new Date().toISOString(),
        resolved_at: null,
        resolved_by: null,
      };
      db.requests.unshift(request);
      saveDb();
      return send(res, 201, { request });
    }

    if (p === '/api/money/requests' && req.method === 'GET') {
      const user = getUserFromReq(req);
      if (!user) return send(res, 401, { error: 'Not authenticated' });
      const mine = db.requests.filter((r) => r.user_id === user.id).slice(0, 100);
      return send(res, 200, { requests: mine });
    }

    if (p === '/api/admin/money/requests' && req.method === 'GET') {
      const admin = getUserFromReq(req);
      if (!admin) return send(res, 401, { error: 'Not authenticated' });
      if (admin.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      const status = new URL(req.url, 'http://localhost').searchParams.get('status') || 'pending';
      let list = db.requests;
      if (status !== 'all') list = list.filter((r) => r.status === status);
      return send(res, 200, { requests: list.slice(0, 200) });
    }

    if (p.match(/^\/api\/admin\/money\/requests\/\d+$/) && req.method === 'POST') {
      const admin = getUserFromReq(req);
      if (!admin) return send(res, 401, { error: 'Not authenticated' });
      if (admin.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      const id = parseInt(p.split('/').pop(), 10);
      const body = await readBody(req);
      const action = body.action === 'reject' ? 'reject' : 'approve';
      const request = db.requests.find((r) => r.id === id);
      if (!request) return send(res, 404, { error: 'Request not found' });
      if (request.status !== 'pending') return send(res, 400, { error: 'Request already resolved' });
      const target = db.users.find((u) => u.id === request.user_id);
      if (!target) return send(res, 404, { error: 'User not found' });

      if (action === 'approve') {
        if (request.type === 'deposit') {
          target.usdt = (target.usdt || 0) + request.amount;
          if (!target.history) target.history = [];
          target.history.unshift({
            side: 'deposit', base: 'USDT', amount: request.amount, price: 1,
            total: request.amount, time: Date.now(), note: 'Deposit approved',
          });
        } else {
          if (request.amount > target.usdt + 1e-8) {
            return send(res, 400, { error: 'User has insufficient balance for this withdrawal' });
          }
          target.usdt -= request.amount;
          if (!target.history) target.history = [];
          target.history.unshift({
            side: 'withdraw', base: 'USDT', amount: request.amount, price: 1,
            total: request.amount, time: Date.now(), note: 'Withdraw approved',
          });
        }
        request.status = 'approved';
      } else {
        request.status = 'rejected';
      }
      request.resolved_at = new Date().toISOString();
      request.resolved_by = admin.username;
      saveDb();
      return send(res, 200, { request, user: publicUser(target) });
    }


    if (p === '/api/forgot-password' && req.method === 'POST') {
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const user = db.users.find((u) => (u.email || '').toLowerCase() === email);
      // Always same message (don't reveal if email exists)
      if (!user) {
        return send(res, 200, { ok: true, message: 'If that email is registered, a reset code was created.' });
      }
      const token = crypto.randomBytes(4).toString('hex'); // 8-char code
      user.reset_token = token;
      user.reset_expires = Date.now() + 60 * 60 * 1000; // 1 hour
      saveDb();
      // No email server: return code for demo / admin can also reset
      return send(res, 200, {
        ok: true,
        message: 'Reset code generated. Use it with your email to set a new password.',
        reset_code: token, // shown because no SMTP in this demo
      });
    }

    if (p === '/api/reset-password' && req.method === 'POST') {
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const code = String(body.reset_code || body.token || '').trim();
      const password = String(body.new_password || body.password || '');
      const confirm = String(body.confirm_password || '');
      if (password.length < 6)
        return send(res, 400, { error: 'Password must be at least 6 characters' });
      if (confirm && password !== confirm)
        return send(res, 400, { error: 'Passwords do not match' });
      const user = db.users.find((u) => (u.email || '').toLowerCase() === email);
      if (!user || !user.reset_token || user.reset_token !== code)
        return send(res, 400, { error: 'Invalid email or reset code' });
      if (!user.reset_expires || Date.now() > user.reset_expires)
        return send(res, 400, { error: 'Reset code expired. Request a new one.' });
      const { salt, hash } = hashPassword(password);
      user.salt = salt;
      user.password_hash = hash;
      user.reset_token = null;
      user.reset_expires = null;
      saveDb();
      return send(res, 200, { ok: true, message: 'Password updated. You can log in now.' });
    }

    if (p.match(/^\/api\/admin\/users\/\d+\/reset-password$/) && req.method === 'POST') {
      const admin = getUserFromReq(req);
      if (!admin) return send(res, 401, { error: 'Not authenticated' });
      if (admin.role !== 'admin') return send(res, 403, { error: 'Admin only' });
      const id = parseInt(p.split('/')[4], 10);
      const body = await readBody(req);
      const password = String(body.new_password || body.password || '');
      if (password.length < 6)
        return send(res, 400, { error: 'Password must be at least 6 characters' });
      const target = db.users.find((u) => u.id === id);
      if (!target) return send(res, 404, { error: 'User not found' });
      const { salt, hash } = hashPassword(password);
      target.salt = salt;
      target.password_hash = hash;
      target.reset_token = null;
      target.reset_expires = null;
      saveDb();
      return send(res, 200, { ok: true, user: publicUser(target) });
    }

    // ----- Static files -----
    let filePath = path.join(publicDir, p === '/' ? 'index.html' : p);
    if (!filePath.startsWith(publicDir)) return send(res, 403, { error: 'Forbidden' });
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(publicDir, 'index.html');
    }
    if (!fs.existsSync(filePath)) return send(res, 404, { error: 'Not found' });
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  } catch (e) {
    console.error(e);
    send(res, 500, { error: e.message || 'Server error' });
  }
}

http.createServer(handler).listen(PORT, () => {
  console.log(`\n  SpotSim → http://localhost:${PORT}`);
  console.log(`  Admin: ${ADMIN_USER} / ${ADMIN_PASS}`);
  console.log(`  Default start balance: ${db.settings.default_starting_balance}\n`);
});
