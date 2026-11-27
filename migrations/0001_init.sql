-- บัญชีผู้ดูแล/ร้าน (รหัสผ่านเก็บเป็น PBKDF2-SHA256 + salt)
CREATE TABLE accounts (
  code TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- ข้อมูลตั้งค่า/เมนู/สต๊อก/บันทึกการใช้งาน ของแต่ละร้าน (เก็บเป็น JSON ทั้งก้อนต่อคีย์)
CREATE TABLE kv (
  store TEXT NOT NULL,
  k TEXT NOT NULL,
  v TEXT NOT NULL,
  ts INTEGER NOT NULL,
  PRIMARY KEY (store, k)
);

-- บิลเก็บเป็นแถวแยก ให้หลายเครื่องเพิ่มพร้อมกันได้โดยไม่ทับกัน
CREATE TABLE orders (
  store TEXT NOT NULL,
  id TEXT NOT NULL,
  day TEXT NOT NULL,
  total REAL NOT NULL,
  cancelled INTEGER NOT NULL DEFAULT 0,
  ref TEXT,
  json TEXT NOT NULL,
  ts INTEGER NOT NULL,
  PRIMARY KEY (store, id)
);
CREATE INDEX orders_day ON orders (store, day);
-- กันบิลซ้ำจาก QR เดียวกัน (qrPaymentId) แม้จะมาจากคนละเครื่อง
CREATE UNIQUE INDEX orders_ref ON orders (store, ref) WHERE ref IS NOT NULL AND ref != '';

-- บันทึกความพยายามล็อกอินผิด (จำกัดการเดารหัส)
CREATE TABLE fails (
  k TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX fails_k ON fails (k, ts);
