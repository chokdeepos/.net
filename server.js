// Chokdee POS — เซิร์ฟเวอร์เล็กๆ สำหรับ (1) เสิร์ฟหน้า POS และ (2) proxy ไป Xtra Payment Gateway
// เก็บ Bearer token ของ Gateway ไว้ฝั่งเซิร์ฟเวอร์ ไม่ส่งลงเบราว์เซอร์ (ตามข้อ 8.2 ของสเปก)
// ต้องใช้ Node.js 20.6 ขึ้นไป  ·  รัน: node --env-file=.env server.js
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { GATEWAY_BASE, GATEWAY_TOKEN, POS_KEY = '', ALLOW_ORIGIN = '', PORT = 8080 } = process.env;
if (!GATEWAY_BASE || !GATEWAY_TOKEN) {
  console.error('ต้องตั้งค่า GATEWAY_BASE และ GATEWAY_TOKEN (ดู .env.example)');
  process.exit(1);
}

// อนุญาตเฉพาะ API-01 และ API-03 เท่านั้น
const ALLOWED = new Set([
  'POST /payment-gateway/api/v1/qr-payments/generate',
  'POST /payment-gateway/api/v1/qr-payments/payment-status',
]);

const send = (res, status, body, type = 'application/json; charset=utf-8', extra = {}) => {
  res.writeHead(status, { 'Content-Type': type, ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const cors = () => (ALLOW_ORIGIN
  ? { 'Access-Control-Allow-Origin': ALLOW_ORIGIN, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'POST, OPTIONS', Vary: 'Origin' }
  : {});

async function readBody(req, limit = 10_000) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > limit) throw new Error('too large'); chunks.push(c); }
  return Buffer.concat(chunks);
}

async function proxy(req, res) {
  const route = `${req.method} ${req.url.split('?')[0]}`;
  if (req.method === 'OPTIONS') return send(res, 204, '', 'text/plain', cors());
  if (!ALLOWED.has(route)) return send(res, 404, { title: 'Not Found', status: 404 }, undefined, cors());
  // ถ้าตั้ง POS_KEY: เบราว์เซอร์ต้องส่ง Authorization: Bearer {POS_KEY} (ใส่ในช่อง token ของหน้าตั้งค่า)
  if (POS_KEY && req.headers.authorization !== `Bearer ${POS_KEY}`) {
    return send(res, 401, { title: 'Unauthorized', status: 401, detail: 'POS key ไม่ถูกต้อง' }, undefined, cors());
  }
  let body;
  try { body = await readBody(req); } catch { return send(res, 413, { title: 'Payload Too Large', status: 413 }, undefined, cors()); }
  try {
    const r = await fetch(GATEWAY_BASE.replace(/\/$/, '') + req.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8', Authorization: `Bearer ${GATEWAY_TOKEN}` },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    const text = await r.text();
    console.log(`${new Date().toISOString()} ${route} -> ${r.status}`); // ไม่บันทึก body หรือ token
    return send(res, r.status, text, r.headers.get('content-type') || 'application/json; charset=utf-8', cors());
  } catch (e) {
    console.log(`${new Date().toISOString()} ${route} -> gateway error (${e.name})`);
    return send(res, 502, { title: 'Bad Gateway', status: 502, detail: 'ติดต่อ Payment Gateway ไม่ได้' }, undefined, cors());
  }
}

function serveStatic(req, res) {
  const file = path.join(here, 'public', req.url === '/' ? 'index.html' : path.normalize(req.url.split('?')[0]));
  if (!file.startsWith(path.join(here, 'public'))) return send(res, 403, 'Forbidden', 'text/plain');
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'Not Found', 'text/plain');
    send(res, 200, data, file.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/octet-stream');
  });
}

http.createServer((req, res) => {
  if (req.url.startsWith('/payment-gateway/')) return void proxy(req, res);
  serveStatic(req, res);
}).listen(PORT, () => console.log(`Chokdee POS พร้อมที่ http://localhost:${PORT}`));
