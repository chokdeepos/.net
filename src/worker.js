// Chokdee POS — Cloudflare Worker: ไฟล์สถิต + API + D1 + proxy ไป Xtra Payment Gateway
const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
const bad = (status, detail) => json({ title: status === 401 ? 'Unauthorized' : 'Error', status, detail }, status);

const ADMIN_KEYS = new Set(['menu', 'cats', 'groups', 'stock', 'scats', 'slog', 'alog', 'S', 'cfg', 'qrpend']);
const POS_KEYS = new Set(['alog', 'qrpend']);
const GATEWAY_ALLOWED = new Set(['/payment-gateway/api/v1/qr-payments/generate', '/payment-gateway/api/v1/qr-payments/payment-status']);
const ADMIN_TTL = 12 * 3600, POS_TTL = 30 * 24 * 3600;

/* ---------- โทเคนล็อกอิน (HMAC-SHA256) ---------- */
const hmacKey = secret => crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
async function sign(env, payload) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  return body + '.' + b64u(await crypto.subtle.sign('HMAC', await hmacKey(env.SESSION_SECRET), enc.encode(body)));
}
async function verify(env, tok) {
  try {
    const [body, sig] = (tok || '').split('.'); if (!body || !sig) return null;
    if (!await crypto.subtle.verify('HMAC', await hmacKey(env.SESSION_SECRET), unb64u(sig), enc.encode(body))) return null;
    const p = JSON.parse(dec.decode(unb64u(body)));
    return p.e > Date.now() / 1000 ? p : null;
  } catch { return null; }
}
async function auth(req, env) {
  const m = /^Bearer (.+)$/.exec(req.headers.get('Authorization') || '');
  return m ? verify(env, m[1]) : null;
}

/* ---------- รหัสผ่าน (PBKDF2-SHA256) ---------- */
async function hashPw(pw, salt, iter = 100000) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64u(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}
// เก็บจำนวนรอบไว้ในค่าแฮช (รูปแบบ "รอบ$แฮช") — แพ็กเกจฟรีของ Workers จำกัด CPU 10 มิลลิวินาที ถ้า login ล้ม (error 1102) ให้อัปเกรดเป็น Workers Paid หรือตั้ง PBKDF2_ITER ให้ต่ำลง (ขั้นต่ำ 1000) ก่อนสมัครบัญชีแรก
const iterOf = env => Math.max(1000, Math.min(100000, parseInt(env.PBKDF2_ITER) || 100000));
const mkHash = async (env, pw, salt) => { const it = iterOf(env); return it + '$' + await hashPw(pw, salt, it); };
const chkHash = async (pw, salt, stored) => { const [it, h] = stored.includes('$') ? stored.split('$') : ['100000', stored]; return same(await hashPw(pw, salt, +it), h); };
const same = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };

/* ---------- จำกัดการเดารหัส ---------- */
const ip = req => req.headers.get('CF-Connecting-IP') || 'local';
async function limited(env, k, max = 10, win = 600000) { const r = await env.DB.prepare('SELECT COUNT(*) n FROM fails WHERE k=?1 AND ts>?2').bind(k, Date.now() - win).first(); return r.n >= max; }
async function fail(env, k) {
  await env.DB.prepare('INSERT INTO fails(k,ts) VALUES(?1,?2)').bind(k, Date.now()).run();
  await env.DB.prepare('DELETE FROM fails WHERE ts<?1').bind(Date.now() - 3600000).run();
}

const readJson = async req => { try { const t = await req.text(); if (t.length > 1_000_000) return null; return JSON.parse(t || '{}'); } catch { return null; } };
const kvGet = async (env, store, k) => { const r = await env.DB.prepare('SELECT v FROM kv WHERE store=?1 AND k=?2').bind(store, k).first(); return r ? JSON.parse(r.v) : null; };

/* ---------- เส้นทาง ---------- */
async function handleApi(req, env, url) {
  const path = url.pathname, method = req.method;
  if (path === '/api/ping') return json({ ok: true, cloud: true });
  const mi = /^\/api\/img\/([A-Za-z0-9_-]{8,40})$/.exec(path); // รูปเมนูเปิดอ่านได้ (รหัสสุ่มเดาไม่ได้) เพราะ <img> ส่งโทเคนไม่ได้
  if (method === 'GET' && mi) {
    const r = await env.DB.prepare('SELECT mime,data FROM images WHERE id=?1').bind(mi[1]).first();
    if (!r) return bad(404, 'Not Found');
    return new Response(Uint8Array.from(atob(r.data), c => c.charCodeAt(0)), { headers: { 'Content-Type': r.mime, 'Cache-Control': 'public, max-age=31536000, immutable', 'X-Content-Type-Options': 'nosniff' } });
  }
  if (!env.SESSION_SECRET) return bad(500, 'ยังไม่ได้ตั้งค่า SESSION_SECRET บนเซิร์ฟเวอร์');

  if (method === 'POST' && path === '/api/signup') {
    const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้อง');
    const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    if (!/^\S+@\S+\.\S+$/.test(email)) return bad(400, 'กรอกอีเมลให้ถูกต้อง');
    if (pw.length < 6) return bad(400, 'รหัสผ่านต้องมีอย่างน้อย 6 ตัว');
    const k = ip(req) + '|signup'; if (await limited(env, k)) return bad(429, 'สมัครถี่เกินไป ลองใหม่ภายหลัง');
    await fail(env, k);
    if (await env.DB.prepare('SELECT 1 FROM accounts WHERE email=?1').bind(email).first()) return bad(409, 'อีเมลนี้สมัครแล้ว ให้เข้าสู่ระบบแทน');
    let code = '';
    for (let i = 0; i < 20; i++) { const c = 'CK' + (1000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 9000)); if (!await env.DB.prepare('SELECT 1 FROM accounts WHERE code=?1').bind(c).first()) { code = c; break; } }
    if (!code) return bad(500, 'สร้างรหัสร้านไม่สำเร็จ ลองใหม่');
    const salt = crypto.getRandomValues(new Uint8Array(16)), name = email.split('@')[0];
    await env.DB.prepare('INSERT INTO accounts(code,email,name,salt,hash,created_at) VALUES(?1,?2,?3,?4,?5,?6)').bind(code, email, name, b64u(salt), await mkHash(env, pw, salt), Date.now()).run();
    return json({ token: await sign(env, { c: code, r: 'admin', e: Math.floor(Date.now() / 1000) + ADMIN_TTL }), role: 'admin', code, name, email });
  }

  if (method === 'POST' && path === '/api/login') {
    const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้อง');
    const id = String(b.id || '').trim(), k = ip(req) + '|login';
    if (await limited(env, k)) return bad(429, 'ลองผิดหลายครั้ง กรุณารอ 10 นาที');
    const a = await env.DB.prepare('SELECT * FROM accounts WHERE email=?1 OR code=?2').bind(id.toLowerCase(), id.toUpperCase()).first();
    if (!a || !await chkHash(String(b.password || ''), unb64u(a.salt), a.hash)) { await fail(env, k); return bad(401, 'อีเมลหรือรหัสผ่านไม่ถูกต้อง'); }
    const sys = a.role === 'sysadmin' ? 1 : 0; // s=1 คือผู้จัดการระบบ (สิทธิ์ผู้จัดการ + เห็นภาพรวมทุกร้าน)
    return json({ token: await sign(env, { c: a.code, r: 'admin', s: sys, e: Math.floor(Date.now() / 1000) + ADMIN_TTL }), role: 'admin', sys: !!sys, code: a.code, name: a.name, email: a.email });
  }

  // รายชื่อพนักงานของร้าน (ชื่อเท่านั้น) ให้หน้าเข้าสู่ระบบแสดงให้เลือก
  if (method === 'POST' && path === '/api/staff-list') {
    const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้อง');
    const code = String(b.code || '').trim().toUpperCase(), k = ip(req) + '|stafflist';
    if (await limited(env, k, 30)) return bad(429, 'ลองถี่เกินไป กรุณารอ 10 นาที');
    const a = await env.DB.prepare('SELECT code,name FROM accounts WHERE code=?1').bind(code).first();
    if (!a) { await fail(env, k); return bad(401, 'ไม่พบรหัสร้านนี้'); }
    const staff = (await env.DB.prepare('SELECT id,name FROM users WHERE store=?1 AND active=1 ORDER BY name').bind(code).all()).results;
    return json({ store: a.name, staff });
  }

  if (method === 'POST' && path === '/api/pos-login') {
    const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้อง');
    const code = String(b.code || '').trim().toUpperCase(), k = ip(req) + '|pos';
    if (await limited(env, k)) return bad(429, 'ลองผิดหลายครั้ง กรุณารอ 10 นาที');
    const a = await env.DB.prepare('SELECT code,name FROM accounts WHERE code=?1').bind(code).first();
    if (!a) { await fail(env, k); return bad(401, 'ไม่พบรหัสร้านนี้'); }
    const exp = Math.floor(Date.now() / 1000) + POS_TTL;
    if (b.userId) { // พนักงานเข้าด้วยชื่อ + PIN
      const uk = 'u|' + String(b.userId);
      if (await limited(env, uk, 5, 300000)) return bad(429, 'ใส่ PIN ผิดหลายครั้ง ล็อกชื่อนี้ 5 นาที ให้ผู้จัดการรีเซ็ต PIN หรือรอสักครู่');
      const u = await env.DB.prepare('SELECT * FROM users WHERE id=?1 AND store=?2 AND active=1').bind(String(b.userId), code).first();
      if (!u || !await chkHash(String(b.pin || ''), unb64u(u.salt), u.hash)) { await fail(env, k); await fail(env, uk); return bad(401, 'PIN ไม่ถูกต้อง'); }
      return json({ token: await sign(env, { c: a.code, r: 'pos', u: u.id, n: u.name, e: exp }), role: 'pos', code: a.code, name: a.name, staff: u.name });
    }
    // ร้านที่ตั้งพนักงานไว้แล้วต้องใช้ PIN เท่านั้น ร้านที่ยังไม่มีพนักงานเข้าด้วยรหัสร้านได้เหมือนเดิม
    const has = await env.DB.prepare('SELECT 1 FROM users WHERE store=?1 AND active=1').bind(code).first();
    if (has) return bad(403, 'ร้านนี้ใช้ PIN พนักงาน กรุณาเลือกชื่อและใส่ PIN');
    return json({ token: await sign(env, { c: a.code, r: 'pos', e: exp }), role: 'pos', code: a.code, name: a.name });
  }

  const me = await auth(req, env); if (!me) return bad(401, 'กรุณาเข้าสู่ระบบใหม่');
  const store = me.c;
  const me_ok = async () => { const r = me.u ? await env.DB.prepare('SELECT 1 FROM users WHERE id=?1 AND active=1').bind(me.u).first() : true; return !!r; };
  if (me.u && !await me_ok()) return bad(401, 'บัญชีพนักงานนี้ถูกปิดใช้งาน กรุณาเข้าสู่ระบบใหม่'); // พนักงานที่ถูกปิดสิทธิ์ใช้ต่อไม่ได้แม้โทเคนยังไม่หมดอายุ

  if (method === 'POST' && path === '/api/img') {
    if (me.r !== 'admin') return bad(403, 'ต้องเป็น Admin');
    const b = await readJson(req) || {}, m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(b.data || ''));
    if (!m) return bad(400, 'รองรับเฉพาะรูป JPEG / PNG / WebP');
    if (m[2].length > 400000) return bad(413, 'รูปใหญ่เกินไป (ไม่เกินประมาณ 300 KB)');
    const n = await env.DB.prepare('SELECT COUNT(*) n FROM images WHERE store=?1').bind(store).first();
    if (n.n >= 500) return bad(400, 'จำนวนรูปเต็มแล้ว (500 รูปต่อร้าน)');
    const id = b64u(crypto.getRandomValues(new Uint8Array(12)));
    await env.DB.prepare('INSERT INTO images(id,store,mime,data,ts) VALUES(?1,?2,?3,?4,?5)').bind(id, store, m[1], m[2], Date.now()).run();
    return json({ id });
  }

  if (method === 'GET' && path === '/api/state') {
    const kv = {}; for (const r of (await env.DB.prepare('SELECT k,v,ts FROM kv WHERE store=?1').bind(store).all()).results) kv[r.k] = { v: r.v, ts: r.ts };
    const since = new Date(Date.now() - 90 * 864e5).toISOString().slice(0, 10);
    const orders = (await env.DB.prepare('SELECT json FROM orders WHERE store=?1 AND day>=?2 ORDER BY id').bind(store, since).all()).results.map(r => JSON.parse(r.json));
    const a = await env.DB.prepare('SELECT name,email FROM accounts WHERE code=?1').bind(store).first();
    return json({ kv, orders, role: me.r, code: store, name: a?.name, email: a?.email, now: Date.now() });
  }

  if (method === 'POST' && path === '/api/push') {
    const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้องหรือใหญ่เกินไป');
    const allowed = me.r === 'admin' ? ADMIN_KEYS : POS_KEYS, now = Date.now(), ignored = [], rejected = [], stmts = [];
    for (const [k, v] of Object.entries(b.kv || {})) {
      if (!allowed.has(k)) { ignored.push(k); continue; }
      stmts.push(env.DB.prepare('INSERT INTO kv(store,k,v,ts) VALUES(?1,?2,?3,?4) ON CONFLICT(store,k) DO UPDATE SET v=excluded.v, ts=excluded.ts').bind(store, k, JSON.stringify(v), now));
    }
    if (stmts.length) await env.DB.batch(stmts);
    for (const o of Array.isArray(b.orders) ? b.orders : []) {
      if (!o || typeof o.time !== 'string' || !Array.isArray(o.items) || !isFinite(+o.total)) { rejected.push({ id: o && o.time, why: 'invalid' }); continue; }
      const old = await env.DB.prepare('SELECT 1 FROM orders WHERE store=?1 AND id=?2').bind(store, o.time).first();
      if (me.r !== 'admin' && (old || o.cancelled)) { rejected.push({ id: o.time, why: old ? 'exists' : 'forbidden' }); continue; } // หน้าร้านเพิ่มบิลใหม่ได้อย่างเดียว ยกเลิก/แก้ไขเป็นสิทธิ์ Admin
      try {
        await env.DB.prepare('INSERT INTO orders(store,id,day,total,cancelled,ref,json,ts,staff) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(store,id) DO UPDATE SET total=excluded.total, cancelled=excluded.cancelled, json=excluded.json, ts=excluded.ts')
          .bind(store, o.time, o.time.slice(0, 10), +o.total, o.cancelled ? 1 : 0, o.ref || null, JSON.stringify(o), now, me.n || null).run();
      } catch (e) { rejected.push({ id: o.time, why: /UNIQUE/i.test(String(e)) ? 'dup_ref' : 'error' }); }
    }
    return json({ ok: true, ignored, rejected });
  }

  /* ---------- จัดการพนักงาน (ผู้จัดการ) ---------- */
  if (path.startsWith('/api/users')) {
    if (me.r !== 'admin') return bad(403, 'ต้องเป็นผู้จัดการ');
    if (method === 'GET' && path === '/api/users') return json({ users: (await env.DB.prepare('SELECT id,name,active,created_at FROM users WHERE store=?1 ORDER BY name').bind(store).all()).results });
    const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้อง');
    const pinOk = p => /^\d{4}$/.test(String(p || ''));
    if (method === 'POST' && path === '/api/users') {
      const name = String(b.name || '').trim().slice(0, 40);
      if (!name) return bad(400, 'กรอกชื่อพนักงาน');
      if (!pinOk(b.pin)) return bad(400, 'PIN ต้องเป็นตัวเลข 4 หลัก');
      const n = await env.DB.prepare('SELECT COUNT(*) n FROM users WHERE store=?1').bind(store).first();
      if (n.n >= 30) return bad(400, 'จำนวนพนักงานเต็มแล้ว (30 คนต่อร้าน)');
      if (await env.DB.prepare('SELECT 1 FROM users WHERE store=?1 AND name=?2').bind(store, name).first()) return bad(409, 'มีชื่อนี้ในร้านแล้ว');
      const id = b64u(crypto.getRandomValues(new Uint8Array(9))), salt = crypto.getRandomValues(new Uint8Array(16));
      await env.DB.prepare('INSERT INTO users(id,store,name,salt,hash,active,created_at) VALUES(?1,?2,?3,?4,?5,1,?6)').bind(id, store, name, b64u(salt), await mkHash(env, String(b.pin), salt), Date.now()).run();
      return json({ ok: true, id });
    }
    if (method === 'POST' && path === '/api/users/pin') {
      if (!pinOk(b.pin)) return bad(400, 'PIN ต้องเป็นตัวเลข 4 หลัก');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const r = await env.DB.prepare('UPDATE users SET salt=?1, hash=?2 WHERE id=?3 AND store=?4').bind(b64u(salt), await mkHash(env, String(b.pin), salt), String(b.id || ''), store).run();
      if (!r.meta.changes) return bad(404, 'ไม่พบพนักงาน');
      await env.DB.prepare('DELETE FROM fails WHERE k=?1').bind('u|' + String(b.id)).run(); // ปลดล็อกชื่อนี้
      return json({ ok: true });
    }
    if (method === 'POST' && path === '/api/users/active') {
      const r = await env.DB.prepare('UPDATE users SET active=?1 WHERE id=?2 AND store=?3').bind(b.active ? 1 : 0, String(b.id || ''), store).run();
      if (!r.meta.changes) return bad(404, 'ไม่พบพนักงาน');
      return json({ ok: true });
    }
    return bad(404, 'Not Found');
  }

  /* ---------- ภาพรวมทุกร้านและ GP (ผู้จัดการระบบ) ---------- */
  if (path.startsWith('/api/hq')) {
    if (!me.s) return bad(403, 'ต้องเป็นผู้จัดการระบบ');
    if (method === 'GET' && path === '/api/hq') {
      const today = new Date(Date.now() + 7 * 3600e3).toISOString().slice(0, 10); // วันตามเวลาไทย
      const ok = d => /^\d{4}-\d{2}-\d{2}$/.test(d || '');
      const from = ok(url.searchParams.get('from')) ? url.searchParams.get('from') : today, to = ok(url.searchParams.get('to')) ? url.searchParams.get('to') : from;
      const agg = (await env.DB.prepare('SELECT store, COUNT(*) bills, COALESCE(SUM(total),0) sales FROM orders WHERE day>=?1 AND day<=?2 AND cancelled=0 GROUP BY store').bind(from, to).all()).results;
      const by = Object.fromEntries(agg.map(r => [r.store, r]));
      const stores = (await env.DB.prepare('SELECT code,name,email,role,kind,gp_rate FROM accounts ORDER BY code').all()).results.map(a => {
        const g = by[a.code] || { bills: 0, sales: 0 };
        return { code: a.code, name: a.name, email: a.email, role: a.role, kind: a.kind, gpRate: a.gp_rate, bills: g.bills, sales: g.sales, gp: Math.round(g.sales * a.gp_rate) / 100 };
      });
      return json({ from, to, stores });
    }
    if (method === 'POST' && path === '/api/hq/store') {
      const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้อง');
      const gp = Number(b.gpRate), kind = b.kind === 'out' ? 'out' : 'in';
      if (!isFinite(gp) || gp < 0 || gp > 100) return bad(400, 'GP ต้องอยู่ระหว่าง 0-100');
      const r = await env.DB.prepare('UPDATE accounts SET gp_rate=?1, kind=?2 WHERE code=?3').bind(gp, kind, String(b.code || '').toUpperCase()).run();
      if (!r.meta.changes) return bad(404, 'ไม่พบร้านนี้');
      return json({ ok: true });
    }
    return bad(404, 'Not Found');
  }

  if (method === 'POST' && path === '/api/password') {
    if (me.r !== 'admin') return bad(403, 'ต้องเป็น Admin');
    const b = await readJson(req) || {}, a = await env.DB.prepare('SELECT * FROM accounts WHERE code=?1').bind(store).first();
    if (String(b.new || '').length < 6) return bad(400, 'รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัว');
    if (!a || !await chkHash(String(b.old || ''), unb64u(a.salt), a.hash)) return bad(401, 'รหัสผ่านเดิมไม่ถูกต้อง');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    await env.DB.prepare('UPDATE accounts SET salt=?1, hash=?2 WHERE code=?3').bind(b64u(salt), await mkHash(env, String(b.new), salt), store).run();
    return json({ ok: true });
  }
  return bad(404, 'Not Found');
}

/* ---------- proxy ไป Xtra Payment Gateway (API-01 / API-03) ---------- */
async function handleGateway(req, env, url) {
  if (req.method !== 'POST' || !GATEWAY_ALLOWED.has(url.pathname)) return bad(404, 'Not Found');
  if (!env.SESSION_SECRET) return bad(500, 'ยังไม่ได้ตั้งค่า SESSION_SECRET บนเซิร์ฟเวอร์');
  const me = await auth(req, env); if (!me) return bad(401, 'กรุณาเข้าสู่ระบบใหม่');
  if (!env.GATEWAY_BASE || !env.GATEWAY_TOKEN) return bad(503, 'ยังไม่ได้ตั้งค่า Gateway บนเซิร์ฟเวอร์ (GATEWAY_BASE / GATEWAY_TOKEN)');
  const b = await readJson(req); if (!b) return bad(400, 'ข้อมูลไม่ถูกต้อง');
  const cfg = await kvGet(env, me.c, 'cfg') || {}; // ค่า service code ฯลฯ ใช้จากที่ Admin ตั้งไว้ ไม่เชื่อค่าจากหน้าเว็บ
  if (cfg.serviceCode) b.serviceCode = cfg.serviceCode;
  if (url.pathname.endsWith('/generate')) { if (cfg.payFor) b.paymentForCode = cfg.payFor; if (cfg.payType) b.paymentType = cfg.payType; }
  try {
    const r = await fetch(env.GATEWAY_BASE.replace(/\/$/, '') + url.pathname, {
      method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-8', Authorization: 'Bearer ' + env.GATEWAY_TOKEN },
      body: JSON.stringify(b), signal: AbortSignal.timeout(15000),
    });
    console.log(`${url.pathname} store=${me.c} -> ${r.status}`); // ไม่บันทึก body หรือโทเคน
    return new Response(await r.text(), { status: r.status, headers: { 'Content-Type': r.headers.get('content-type') || 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
  } catch (e) {
    console.log(`${url.pathname} store=${me.c} -> gateway error ${e.name}`);
    return bad(502, 'ติดต่อ Payment Gateway ไม่ได้');
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (url.pathname.startsWith('/api/')) return await handleApi(req, env, url);
      if (url.pathname.startsWith('/payment-gateway/')) return await handleGateway(req, env, url);
    } catch (e) { console.log('error', String(e)); return bad(500, 'เกิดข้อผิดพลาดบนเซิร์ฟเวอร์'); }
    return env.ASSETS.fetch(req);
  },
};
