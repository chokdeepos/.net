-- รูปเมนู (ย่อแล้ว ~20-40 KB ต่อรูป) เก็บแยกจากข้อมูลเมนู เมนูอ้างอิงด้วยรหัสรูป
CREATE TABLE images (
  id TEXT PRIMARY KEY,
  store TEXT NOT NULL,
  mime TEXT NOT NULL,
  data TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX images_store ON images (store);
