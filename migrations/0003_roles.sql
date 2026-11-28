-- สิทธิ์ 3 ระดับ: พนักงาน (PIN) / ผู้จัดการ (บัญชีร้านเดิม) / ผู้จัดการระบบ (เห็นทุกร้าน)
-- ผู้จัดการ = แถวใน accounts ที่ role = 'manager' (ค่าเริ่มต้น ร้านเดิมทุกร้านเป็นผู้จัดการอัตโนมัติ)
ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'manager';
-- อัตรา GP (%) ที่ร้านจ่ายให้มหาวิทยาลัย และประเภทร้าน: 'in' = ในเครือโชคดี, 'out' = ร้านภายนอก
ALTER TABLE accounts ADD COLUMN gp_rate REAL NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN kind TEXT NOT NULL DEFAULT 'in';

-- พนักงานหน้าร้าน (เข้าด้วยชื่อ + PIN 4 หลัก เก็บแบบ PBKDF2 เช่นเดียวกับรหัสผ่าน)
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  store TEXT NOT NULL,
  name TEXT NOT NULL,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE INDEX users_store ON users (store);

-- บันทึกว่าบิลนี้ใครเป็นคนเปิด (ไว้ตรวจสอบ ไม่ปนใน json ของบิล)
ALTER TABLE orders ADD COLUMN staff TEXT;
