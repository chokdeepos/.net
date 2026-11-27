// Xtra Payment Gateway จำลอง (ตามสเปก XII-PG-API-001-S v1.2) สำหรับซ้อมทดสอบก่อนต่อ UAT จริง
// รัน: MOCK_TOKEN=test-token node tools/mock-gateway.js   (ค่าเริ่มต้นพอร์ต 9000)
// ใช้กับ proxy:  GATEWAY_BASE=http://localhost:9000  GATEWAY_TOKEN=test-token
//
// ปลายทางจริง (ต้องมี Bearer): POST /payment-gateway/api/v1/qr-payments/generate · /payment-status
// ปลายทางสำหรับซ้อม (ไม่ต้องมี token ห้ามเปิดนอกเครื่อง):
//   POST /__bank/pay   {qrPaymentId, amount?}  จำลองธนาคาร verify+notify (ตอบ responseCode ตามข้อ 7)
//   POST /__bank/age   {qrPaymentId}           ทำให้ QR "ข้ามวัน" (EXPIRED)
//   POST /__fail       {count, status}         ให้คำขอถัดไป N ครั้งล้มเหลวด้วยสถานะนั้น (เช่น 503)
//   GET  /__state                              ดูรายการทั้งหมด
import http from 'node:http';

const { PORT = 9000, MOCK_TOKEN = 'test-token', SERVICES = 'SVCPARK1,CHOKDEE1', PAYFOR = '01,02', TAX = '0105558012345000' } = process.env;
const services = new Set(SERVICES.split(',')), payFors = new Set(PAYFOR.split(','));
const db = new Map(); let failLeft = 0, failStatus = 503;

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ulid = () => { let t = Date.now(), s = ''; for (let i = 0; i < 10; i++) { s = B32[t % 32] + s; t = Math.floor(t / 32); } for (let i = 0; i < 16; i++) s += B32[Math.random() * 32 | 0]; return s; };
const ymd = d => d.toISOString().slice(0, 10).replace(/-/g, '');
const problem = (res, status, detail) => { res.writeHead(status, { 'Content-Type': 'application/problem+json' }); res.end(JSON.stringify({ type: 'about:blank', title: http.STATUS_CODES[status], status, detail })); };
const json = (res, obj, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };
const readJson = async req => { let b = ''; for await (const c of req) b += c; try { return JSON.parse(b || '{}'); } catch { return null; } };
const isPaid = q => q.paidCompleted;
const view = q => ({ id: q.id, amount: q.amount, channel: q.channel, generatedAt: q.generatedAt, paidCompleted: q.paidCompleted, qrCode: q.qrCode, referenceCode1: q.referenceCode1, referenceCode2: q.referenceCode2, requestedById: 'MOCKUSER', requestedByName: 'mock.supplier', serviceCode: q.serviceCode, paidAt: q.paidAt, qrCodeFileName: q.id + '.svg', remark: q.remark, paymentForId: 'MOCKPAYFOR', bblNotifyId: q.bblNotifyId });

function validate(b) {
  const e = [], s = (v, min, max) => typeof v === 'string' && v.trim().length >= min && v.length <= max;
  if (!s(b.serviceCode, 8, 8)) e.push("'serviceCode' must be exactly 8 characters");
  if (!s(b.referenceCode1, 1, 30)) e.push("'referenceCode1' must be 1-30 characters");
  if (!s(b.referenceCode2, 1, 30)) e.push("'referenceCode2' must be 1-30 characters");
  if (!s(b.paymentType, 1, 4)) e.push("'paymentType' must be 1-4 characters");
  if (!s(b.paymentForCode, 1, 3)) e.push("'paymentForCode' must be 1-3 characters");
  if (typeof b.amount !== 'number' || b.amount < 0 || Math.round(b.amount * 100) !== b.amount * 100) e.push("'amount' must be a number >= 0 with at most 2 decimals");
  if (b.remark != null && String(b.remark).length > 255) e.push("'remark' must be at most 255 characters");
  return e;
}

function generate(b, res) {
  const e = validate(b); if (e.length) return problem(res, 400, e.join('; '));
  if (!services.has(b.serviceCode)) return problem(res, 404, `The SERVICE CODE '${b.serviceCode}' was not found.`);
  if (!payFors.has(b.paymentForCode)) return problem(res, 404, `The PAYMENT FOR CODE '${b.paymentForCode}' was not found.`);
  const now = new Date();
  const r1 = `${b.referenceCode1.trim()}D${ymd(now)}D${b.paymentForCode}`;                         // ข้อ 4.6
  const r2 = `${b.paymentType.trim()}D${b.referenceCode2}`.replace(/-/g, 'D');
  const amt = b.amount.toFixed(2).replace('.', '');
  const q = { id: ulid(), serviceCode: b.serviceCode, amount: b.amount, channel: 'QR', generatedAt: now.toISOString(), paidCompleted: b.amount === 0, paidAt: b.amount === 0 ? now.toISOString() : null,
    qrCode: `|${TAX}\r${r1}\r${r2}\r${amt}\r`, referenceCode1: r1, referenceCode2: r2, remark: b.remark ?? null, bblNotifyId: null, bank: null };
  db.set(q.id, q); json(res, view(q));
}

function status(b, res) {
  let q;
  if (b.qrPaymentId) q = db.get(b.qrPaymentId);
  else if (b.referenceCode1 && b.referenceCode2) q = [...db.values()].filter(x => x.referenceCode1 === b.referenceCode1 && x.referenceCode2 === b.referenceCode2 && (!b.serviceCode || x.serviceCode === b.serviceCode)).sort((a, c) => c.generatedAt.localeCompare(a.generatedAt))[0];
  else return problem(res, 400, "Either 'qrPaymentId' or both 'referenceCode1' and 'referenceCode2' must be supplied.");
  if (!q) return problem(res, 404, `The QR payment with Reference1 '${b.referenceCode1 ?? ''}' and Reference2 '${b.referenceCode2 ?? ''}' was not found.`);
  const st = q.paidCompleted ? 'PAID' : ymd(new Date(q.generatedAt)) !== ymd(new Date()) ? 'EXPIRED' : 'NOT_PAID'; // ข้อ 6.4
  json(res, { qrPaymentId: q.id, serviceCode: q.serviceCode, referenceCode1: q.referenceCode1, referenceCode2: q.referenceCode2, amount: q.amount, paymentStatus: st, paidCompleted: q.paidCompleted, paidAt: q.paidAt, channel: q.channel, generatedAt: q.generatedAt, bank: q.bank });
}

function bankPay(b, res) { // ธนาคาร verify (213/411/412/331) แล้ว notify
  const q = db.get(b.qrPaymentId); if (!q) return json(res, { responseCode: '331' });
  if (q.paidCompleted) return json(res, { responseCode: '412' });
  if (ymd(new Date(q.generatedAt)) !== ymd(new Date())) return json(res, { responseCode: '411' });
  if (Number(b.amount ?? q.amount) !== q.amount) return json(res, { responseCode: '213' });
  q.paidCompleted = true; q.paidAt = new Date().toISOString(); q.channel = 'I'; q.bblNotifyId = ulid();
  q.bank = { transRef: 'TR' + Date.now(), requestRef: 'BBL' + Date.now(), transAt: q.paidAt, fromBank: '002', termId: 'IBANK0001' };
  json(res, { responseCode: '000' });
}

http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/__state') return json(res, [...db.values()]);
  if (req.method === 'POST' && url.startsWith('/__')) {
    const b = await readJson(req) ?? {};
    if (url === '/__bank/pay') return bankPay(b, res);
    if (url === '/__bank/age') { const q = db.get(b.qrPaymentId); if (q) q.generatedAt = new Date(Date.now() - 864e5).toISOString(); return json(res, { ok: !!q }); }
    if (url === '/__fail') { failLeft = b.count ?? 1; failStatus = b.status ?? 503; return json(res, { ok: true }); }
  }
  if (!url.startsWith('/payment-gateway/api/v1/qr-payments/')) return problem(res, 404, 'Not Found');
  if (req.headers.authorization !== `Bearer ${MOCK_TOKEN}`) return problem(res, 401, 'Unauthorized');
  if (failLeft > 0) { failLeft--; return problem(res, failStatus, 'Simulated failure'); }
  const b = await readJson(req); if (b === null) return problem(res, 400, 'Invalid JSON');
  if (req.method === 'POST' && url.endsWith('/generate')) return generate(b, res);
  if (req.method === 'POST' && url.endsWith('/payment-status')) return status(b, res);
  problem(res, 404, 'Not Found');
}).listen(PORT, () => console.log(`Mock Xtra Payment Gateway ที่ http://localhost:${PORT} (token: ${MOCK_TOKEN})`));
