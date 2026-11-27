# Chokdee POS บน Cloudflare Workers + D1

ระบบ POS หน้าร้าน + หลังบ้าน เชื่อม Xtra Payment Gateway (QR พร้อมเพย์) ข้อมูลทั้งหมดอยู่ใน D1 ใช้ได้หลายเครื่อง/หลายสาขา

## โครงสร้าง
| ไฟล์ | หน้าที่ |
|---|---|
| `public/index.html` | หน้า POS (หน้าร้าน + หลังบ้าน) เสิร์ฟเป็นไฟล์สถิตของ Worker |
| `src/worker.js` | API ล็อกอิน/ซิงก์ข้อมูล + proxy ไป Gateway (เก็บโทเคน Gateway ไว้ใน secret) |
| `migrations/0001_init.sql` | โครงสร้างฐานข้อมูล D1 (accounts, kv, orders, fails) |
| `wrangler.toml` | ตั้งค่า Worker / D1 / ไฟล์สถิต |
| `tools/mock-gateway.js` | Gateway จำลองตามสเปก สำหรับซ้อมก่อนต่อ UAT จริง |
| `server.js` | (ทางเลือก) เซิร์ฟเวอร์ Node เดิม ถ้าไม่ใช้ Cloudflare — โหมดนี้เก็บข้อมูลในเบราว์เซอร์ |

## วิธี A: ขึ้นระบบผ่าน GitHub (Cloudflare Workers Builds) — แนะนำสำหรับคนไม่ใช้เทอร์มินัล
ไฟล์ในโฟลเดอร์นี้ต้องอยู่ที่ **รากของ repo** GitHub (มี `wrangler.toml`, `package.json`, `public/`, `src/`, `migrations/` ไม่ต้องอัปโหลด `node_modules`) ถ้าเก็บไว้ในโฟลเดอร์ย่อย ให้ตั้ง Root directory ที่ Worker › Settings › Build

1. **ชื่อ Worker ต้องตรงกัน** — `name` ใน `wrangler.toml` ตั้งเป็น `chokdeepos` ตามชื่อ Worker ในแดชบอร์ดแล้ว ถ้าคุณใช้ชื่ออื่น ให้แก้ให้เหมือนกันทั้งสองที่
2. **สร้างฐานข้อมูล D1** — แดชบอร์ด Cloudflare › Storage & Databases › D1 › Create database ชื่อ `chokdee-pos` แล้วคัดลอก **Database ID** ไปแทนที่ `database_id` ใน `wrangler.toml` (ไม่ใช่ความลับ) แล้ว commit ขึ้น GitHub
3. **ตั้ง GATEWAY_BASE** ใน `wrangler.toml` เป็นที่อยู่ Gateway (UAT ก่อน) แล้ว commit
4. **สร้างตาราง** เลือกวิธีใดวิธีหนึ่ง
   - (ก) Worker › Settings › Build › **Deploy command** ใส่ `npm run deploy` (สั่งสร้างตารางแล้ว deploy ให้) ถ้า build ฟ้องเรื่องสิทธิ์ D1 ให้ใช้วิธี (ข)
   - (ข) D1 › ฐานข้อมูล chokdee-pos › **Console** แล้วคัดลอกเนื้อหา `migrations/0001_init.sql` วางรัน จากนั้นทำซ้ำกับ `migrations/0002_images.sql` (ทำครั้งเดียว)
5. **ตั้งความลับ** — Worker › Settings › **Variables and Secrets** › Add: `SESSION_SECRET` (ชนิด *Secret*, ค่าสุ่มยาวๆ เช่นจาก `openssl rand -base64 48`) และ `GATEWAY_TOKEN` (ชนิด *Secret*)
6. กด **Retry build** (หรือ push commit ใหม่) แล้วเปิด URL ของ Worker (Settings › Domains & Routes ต้องเปิด workers.dev)
7. ตรวจว่าระบบทำงาน: เปิด `https://<URL ของคุณ>/api/ping` ต้องเห็น `{"ok":true,"cloud":true}` แล้วสมัคร Admin ที่หน้าแรกได้

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| Build ล้มเรื่องชื่อไม่ตรง | `name` ใน `wrangler.toml` ต้องเท่ากับชื่อ Worker ในแดชบอร์ด |
| Deploy ฟ้อง D1 not found / invalid id | ยังไม่ได้ใส่ `database_id` จริง (ข้อ 2) |
| สมัคร/ล็อกอินขึ้น "no such table" | ยังไม่ได้สร้างตาราง (ข้อ 4) |
| ขึ้น "ยังไม่ได้ตั้งค่า SESSION_SECRET" | ยังไม่ได้เพิ่ม secret (ข้อ 5) |
| QR ขึ้น "ยังไม่ได้ตั้งค่า Gateway" | ยังไม่ได้เพิ่ม `GATEWAY_TOKEN` หรือ `GATEWAY_BASE` ยังเป็นค่าตัวอย่าง |
| สมัครแล้ว error 1102 | แพ็กเกจฟรีจำกัด CPU ให้ใช้ Workers Paid หรือตั้ง `PBKDF2_ITER` ต่ำลงก่อนสมัครบัญชีแรก |

## วิธี B: ขึ้นระบบด้วยคำสั่ง (wrangler)
ต้องมีบัญชี Cloudflare และ Node.js 20+
```bash
npm install
npx wrangler login

# 1) สร้างฐานข้อมูล แล้วนำ database_id ที่ได้ไปใส่ใน wrangler.toml
npx wrangler d1 create chokdee-pos

# 2) สร้างตารางบนฐานข้อมูลจริง
npx wrangler d1 migrations apply chokdee-pos --remote

# 3) ตั้งความลับ (ไม่เก็บในไฟล์)
openssl rand -base64 48            # คัดลอกค่านี้ไปใช้เป็น SESSION_SECRET
npx wrangler secret put SESSION_SECRET
npx wrangler secret put GATEWAY_TOKEN   # Bearer token ของ Xtra Payment Gateway

# 4) แก้ GATEWAY_BASE ใน wrangler.toml เป็น URL ของ Gateway (UAT ก่อน) แล้ว deploy
npx wrangler deploy
```
ได้ URL แบบ `https://chokdee-pos.<ชื่อบัญชี>.workers.dev` (ผูกโดเมนของตัวเองได้ที่ Workers & Pages › Settings › Domains)

## เริ่มใช้งาน
1. เปิด URL → แท็บ **ผู้ดูแล (Admin)** → สร้างบัญชีด้วยอีเมลและรหัสผ่าน (อย่างน้อย 6 ตัว) → ระบบแสดง **รหัสร้าน** (เช่น CK1234)
2. **ตั้งค่า › การชำระเงิน**: โหมด = ใช้งานจริง, Service Code (8 ตัว), paymentForCode, paymentType จากผู้ดูแล Gateway (ไม่ต้องใส่ Base URL/โทเคน เพราะอยู่ที่ Worker)
3. พนักงานหน้าร้านเปิด URL เดียวกัน → แท็บ **หน้าร้าน (POS)** → ใส่รหัสร้านอย่างเดียว
4. สิ้นวัน: Admin กด **รายงาน › กระทบยอด QR** และส่งออก CSV

## ทดสอบในเครื่องก่อน (ไม่แตะบัญชี Cloudflare)
```bash
cp .dev.vars.example .dev.vars          # แก้ค่าตามต้องการ
node tools/mock-gateway.js &            # Gateway จำลอง พอร์ต 9000
npm run db:migrate:local
npm run dev                             # http://localhost:8787
```
จำลองลูกค้าจ่าย: `curl -X POST localhost:9000/__bank/pay -d '{"qrPaymentId":"<id จาก localhost:9000/__state>"}'`

## ความปลอดภัย (สรุป)
- รหัสผ่านเก็บแบบ PBKDF2-SHA256 + salt · โทเคนล็อกอินเซ็นด้วย HMAC (Admin 12 ชม., POS 30 วัน)
- จำกัดการเดารหัส: ผิดเกิน 10 ครั้งใน 10 นาทีต่อ IP จะถูกบล็อก
- สิทธิ์ตรวจที่เซิร์ฟเวอร์: POS เพิ่มบิลใหม่ได้อย่างเดียว ยกเลิกบิล/แก้เมนู/ตั้งค่าเป็นสิทธิ์ Admin
- proxy อนุญาตเฉพาะ API-01 / API-03 และบังคับ Service Code / paymentType / paymentForCode ตามที่ Admin ตั้งไว้
- โทเคน Gateway ไม่เคยลงเบราว์เซอร์และไม่ถูกบันทึกลง log

## ข้อควรระวัง
- **IP ขาออกของ Workers ไม่คงที่** ถ้า Gateway กำหนดให้แจ้ง IP (allow-list) สำหรับ API-01/03 ให้ถามผู้ดูแล Gateway ก่อน ถ้าต้องใช้ IP คงที่ให้รัน `server.js` บน VPS แทน
- การล็อกอิน/สมัครใช้ PBKDF2 ซึ่งใช้ CPU สูง ถ้าแพ็กเกจฟรีขึ้น error 1102 ให้ใช้ Workers Paid หรือตั้ง `PBKDF2_ITER` ให้ต่ำลง (ตั้งก่อนสมัครบัญชีแรก)
- เครื่องหน้าร้านโพลล์ซิงก์ทุก 15 วินาที ตรวจโควตา request/D1 ของแพ็กเกจก่อนเปิดหลายเครื่อง
- ผู้ที่รู้ **รหัสร้าน** เปิดหน้าจอ POS ได้ → เก็บรหัสเป็นความลับ (หรือใส่ Cloudflare Access ครอบโดเมน)
- โหลดบิลเข้าแอปย้อนหลัง 90 วัน; เมนู/สต๊อกถ้า Admin สองคนแก้พร้อมกันจะเอาของคนบันทึกทีหลัง
