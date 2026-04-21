import sqlite3
import base64
import hashlib
from flask import Flask, request, jsonify, g
from flask_cors import CORS

_FLAG_ADMIN = "SMC{privilege_escalation_complete}"

def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ---------------------------------------------------------------------------
# Database bootstrap
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g.db = conn
        _init_db(conn)
    return g.db

# We keep a single module-level connection so in-memory data survives
# across requests (Flask application context tears down per request for
# the in-memory DB otherwise).
_DB_CONN = None

def get_global_db():
    global _DB_CONN
    if _DB_CONN is None:
        _DB_CONN = sqlite3.connect(":memory:", check_same_thread=False)
        _DB_CONN.row_factory = sqlite3.Row
        _init_db(_DB_CONN)
    return _DB_CONN

def _init_db(conn):
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password      TEXT NOT NULL,
            email         TEXT,
            balance       INTEGER NOT NULL DEFAULT 0,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            internal_score INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            date      TEXT NOT NULL,
            amount    INTEGER NOT NULL,
            target    TEXT NOT NULL
        );

    """)
    # Passwords stored as MD5. Charlie's slot holds the BFLA flag (not a real hash).
    # Admin password is MD5("admin1234") — rainbow-table crackable.
    users = [
        (1,  "alice",   _md5("alice1234"),   "alice@krungthepbank.th",   50000,  0, 720),
        (2,  "bob",     _md5("bob1234"),     "bob@krungthepbank.th",     99999,  0, 610),
        (3,  "charlie", "SMC{bfla_no_auth_check}", "charlie@krungthepbank.th", 30000, 0, 580),
        (99, "admin",   _md5("admin1234"),   "admin@krungthepbank.th",   999999, 1, 999),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO users (id,username,password,email,balance,is_admin,internal_score) VALUES (?,?,?,?,?,?,?)",
        users
    )
    c.executescript("""

        INSERT OR IGNORE INTO transactions (user_id, date, amount, target)
        VALUES
            (1, '2024-01-01', -500,  'bob'),
            (1, '2024-01-02', -1200, 'ร้านค้า_xyz'),
            (2, '2024-01-03', -300,  'alice'),
            (2, '2024-01-04', 5000,  'เงินเดือน'),
            (3, '2024-01-05', -800,  'alice');
    """)
    conn.commit()

# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _decode_token(token: str):
    """Decode base64 token → username. Returns None on failure."""
    try:
        username = base64.b64decode(token).decode("utf-8")
        return username
    except Exception:
        return None

def _get_user_by_token():
    """Extract Bearer token from request, look up user. Returns row or None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    username = _decode_token(token)
    if not username:
        return None
    db = get_global_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return row

def _require_auth():
    user = _get_user_by_token()
    if user is None:
        return None, (jsonify({"ข้อความ": "กรุณาเข้าสู่ระบบก่อน"}), 401)
    return user, None

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_global_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, _md5(password))
    ).fetchone()

    if not row:
        return jsonify({"ข้อความ": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"}), 401

    token = base64.b64encode(username.encode()).decode()
    return jsonify({"token": token, "ข้อความ": "เข้าสู่ระบบสำเร็จ"})


@app.route("/api/me", methods=["GET"])
def me():
    user, err = _require_auth()
    if err:
        return err
    result = {
        "id": user["id"],
        "ชื่อ": user["username"],
        "is_admin": bool(user["is_admin"]),
    }
    if user["is_admin"]:
        result["flag"] = _FLAG_ADMIN
    return jsonify(result)


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user, err = _require_auth()
    if err:
        return err

    # VULN: BOLA — no ownership check
    db = get_global_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify({"ข้อความ": "ไม่พบผู้ใช้"}), 404

    # VULN: Excessive Data Exposure — sends internal_score and is_admin
    return jsonify({
        "id": row["id"],
        "ชื่อ": row["username"],
        "อีเมล": row["email"],
        "ยอดเงิน": row["balance"],
        "is_admin": bool(row["is_admin"]),
        "internal_score": row["internal_score"]
    })


@app.route("/api/users/<int:user_id>/transactions", methods=["GET"])
def get_transactions(user_id):
    user, err = _require_auth()
    if err:
        return err

    # VULN: BOLA — no ownership check
    db = get_global_db()
    rows = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY date",
        (user_id,)
    ).fetchall()

    items = [{"วันที่": r["date"], "จำนวนเงิน": r["amount"], "ปลายทาง": r["target"]} for r in rows]
    return jsonify({"user_id": user_id, "รายการ": items})


@app.route("/api/search", methods=["GET"])
def search_users():
    user, err = _require_auth()
    if err:
        return err

    name = request.args.get("name", "")
    db = get_global_db()

    # VULN: empty name → returns all users
    if name:
        rows = db.execute(
            "SELECT id, username, email FROM users WHERE username LIKE ?",
            (f"%{name}%",)
        ).fetchall()
    else:
        rows = db.execute("SELECT id, username, email FROM users").fetchall()

    results = [{"id": r["id"], "ชื่อ": r["username"], "อีเมล": r["email"]} for r in rows]
    return jsonify({"ผลลัพธ์": results})


@app.route("/api/transfer", methods=["POST"])
def transfer():
    user, err = _require_auth()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}
    from_id = data.get("from_id")
    to_id   = data.get("to_id")
    amount  = data.get("amount")

    if from_id is None or to_id is None or amount is None:
        return jsonify({"ข้อความ": "ข้อมูลไม่ครบถ้วน"}), 400

    try:
        amount = int(amount)
    except (ValueError, TypeError):
        return jsonify({"ข้อความ": "จำนวนเงินไม่ถูกต้อง"}), 400

    if amount <= 0:
        return jsonify({"ข้อความ": "จำนวนเงินต้องมากกว่า 0"}), 400

    db = get_global_db()

    # VULN: BOLA write — no check that from_id matches token owner
    sender = db.execute("SELECT * FROM users WHERE id = ?", (from_id,)).fetchone()
    if not sender:
        return jsonify({"ข้อความ": "ไม่พบบัญชีผู้โอน"}), 404

    receiver = db.execute("SELECT * FROM users WHERE id = ?", (to_id,)).fetchone()
    if not receiver:
        return jsonify({"ข้อความ": "ไม่พบบัญชีผู้รับ"}), 404

    if sender["balance"] < amount:
        return jsonify({"ข้อความ": "ยอดเงินไม่เพียงพอ"}), 400

    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_id))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
    db.execute(
        "INSERT INTO transactions (user_id, date, amount, target) VALUES (?, date('now'), ?, ?)",
        (from_id, -amount, receiver["username"])
    )
    db.execute(
        "INSERT INTO transactions (user_id, date, amount, target) VALUES (?, date('now'), ?, ?)",
        (to_id, amount, sender["username"])
    )
    db.commit()

    return jsonify({"สถานะ": "สำเร็จ", "ข้อความ": "โอนเงินเรียบร้อยแล้ว"})


@app.route("/api/admin/users", methods=["GET"])
def admin_get_all_users():
    user, err = _require_auth()
    if err:
        return err

    # VULN: BFLA — no admin check
    db = get_global_db()
    rows = db.execute("SELECT * FROM users").fetchall()
    users = [{
        "id": r["id"],
        "username": r["username"],
        "password_hash": r["password"],
        "email": r["email"],
        "balance": r["balance"],
        "is_admin": bool(r["is_admin"]),
        "internal_score": r["internal_score"]
    } for r in rows]
    return jsonify({"users": users})


@app.route("/api/users/update", methods=["POST"])
def update_profile():
    user, err = _require_auth()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}

    # VULN: Mass Assignment — accept any field without filtering
    allowed_columns = {"username", "email", "balance", "is_admin", "internal_score", "ชื่อ", "อีเมล"}
    db = get_global_db()

    # Map Thai field names to column names
    field_map = {"ชื่อ": "username", "อีเมล": "email"}
    updates = {}
    for key, val in data.items():
        col = field_map.get(key, key)
        if col in {"username", "email", "balance", "is_admin", "internal_score", "password"}:
            updates[col] = val

    if not updates:
        return jsonify({"ข้อความ": "ไม่มีข้อมูลที่จะอัปเดต"}), 400

    set_clause = ", ".join(f"{col} = ?" for col in updates)
    values = list(updates.values()) + [user["id"]]
    db.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
    db.commit()

    return jsonify({"สถานะ": "สำเร็จ", "ข้อความ": "อัปเดตข้อมูลเรียบร้อยแล้ว"})


@app.route("/docs", methods=["GET"])
def docs():
    endpoints = [
        {"method": "POST", "path": "/api/login",                    "auth": False,  "description": "เข้าสู่ระบบ"},
        {"method": "GET",  "path": "/api/me",                        "auth": True,   "description": "ข้อมูลผู้ใช้ปัจจุบัน"},
        {"method": "GET",  "path": "/api/users/<id>",               "auth": True,   "description": "ดูข้อมูลผู้ใช้"},
        {"method": "GET",  "path": "/api/users/<id>/transactions",  "auth": True,   "description": "ดูประวัติธุรกรรม"},
        {"method": "GET",  "path": "/api/search?name=",             "auth": True,   "description": "ค้นหาผู้ใช้"},
        {"method": "POST", "path": "/api/transfer",                  "auth": True,   "description": "โอนเงิน"},
        {"method": "GET",  "path": "/api/admin/users",              "auth": True,   "description": "รายชื่อผู้ใช้ทั้งหมด (admin)"},
        {"method": "POST", "path": "/api/users/update",             "auth": True,   "description": "แก้ไขโปรไฟล์"},
        {"method": "GET",  "path": "/docs",                         "auth": False,  "description": "รายการ endpoint"},
    ]
    return jsonify({"version": "1.0", "endpoints": endpoints})


# ---------------------------------------------------------------------------
# Frontend HTML pages
# ---------------------------------------------------------------------------

NAVBAR = """
<nav style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;height:56px;gap:16px;">
  <span style="color:var(--text-main);font-weight:700;font-size:1rem;">◈ Leagues of Code</span>
  <span style="color:var(--accent);font-weight:600;font-size:1rem;">ธนาคารกรุงเทพดิจิทัล</span>
  {extra}
  <span style="flex:1"></span>
  {right}
</nav>
"""

LOGOUT_BTN = """
<button onclick="logout()"
  style="background:transparent;border:1px solid var(--text-danger);color:var(--text-danger);
         padding:6px 16px;border-radius:var(--radius);cursor:pointer;font-size:.875rem;">
  ออกจากระบบ
</button>
"""

CSS_VARS = """
<style>
:root {
  --bg-dark:#0d1117;--bg-card:#1a2233;--bg-input:#111827;
  --primary:#4f8ef7;--primary-dark:#2563eb;--accent:#f59e0b;
  --text-main:#f0f4ff;--text-muted:#8b9ab4;--text-danger:#f87171;
  --text-success:#34d399;--border:#2a3a52;--radius:10px;
  --font:'Segoe UI','Noto Sans Thai',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg-dark);color:var(--text-main);font-family:var(--font);min-height:100vh;}
input{background:var(--bg-input);border:1px solid var(--border);color:var(--text-main);
      padding:10px 14px;border-radius:var(--radius);width:100%;font-family:var(--font);font-size:.95rem;}
input:focus{outline:none;border-color:var(--primary);}
.btn-primary{background:var(--primary);color:#fff;border:none;padding:11px 20px;border-radius:var(--radius);
             cursor:pointer;font-weight:700;font-size:.95rem;width:100%;font-family:var(--font);}
.btn-primary:hover{background:var(--primary-dark);}
.btn-secondary{background:transparent;border:1px solid var(--primary);color:var(--primary);
               padding:9px 20px;border-radius:var(--radius);cursor:pointer;font-size:.875rem;
               font-family:var(--font);}
.btn-secondary:hover{background:var(--primary);color:#fff;}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:28px;}
label{display:block;color:var(--text-muted);font-size:.85rem;margin-bottom:6px;margin-top:16px;}
label:first-of-type{margin-top:0;}
</style>
"""


@app.route("/")
def page_login():
    return CSS_VARS + """
<script src="/static/app.js"></script>
<nav style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 24px;
            display:flex;align-items:center;height:56px;gap:16px;">
  <span style="color:var(--text-main);font-weight:700;">◈ Leagues of Code</span>
  <span style="color:var(--accent);font-weight:600;">ธนาคารกรุงเทพดิจิทัล</span>
</nav>
<div style="display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 56px);">
  <div class="card" style="width:400px;">
    <div style="text-align:center;margin-bottom:24px;">
      <div style="font-size:1.5rem;font-weight:700;color:var(--text-main);margin-bottom:6px;">
        ◈ Leagues of Code
      </div>
      <div style="font-size:1.2rem;font-weight:700;color:var(--accent);margin-bottom:4px;">
        ธนาคารกรุงเทพดิจิทัล
      </div>
      <div style="color:var(--text-muted);font-size:.9rem;">เข้าสู่ระบบ Internet Banking</div>
    </div>
    <label for="username">ชื่อผู้ใช้</label>
    <input id="username" type="text" placeholder="ชื่อผู้ใช้" autocomplete="username">
    <label for="password">รหัสผ่าน</label>
    <input id="password" type="password" placeholder="รหัสผ่าน" autocomplete="current-password">
    <div style="margin-top:20px;">
      <button class="btn-primary" onclick="doLogin()">เข้าสู่ระบบ</button>
    </div>
    <div id="err" style="display:none;color:var(--text-danger);margin-top:12px;font-size:.875rem;text-align:center;"></div>
  </div>
</div>
<script>
window.authToken = window.location.hash.slice(1) || null;
async function doLogin() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const errEl = document.getElementById('err');
  errEl.style.display = 'none';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username, password})
    });
    const json = await res.json();
    if (res.ok) {
      window.authToken = json.token;
      window.location.href = '/dashboard#' + json.token;
    } else {
      errEl.textContent = json['ข้อความ'] || 'เกิดข้อผิดพลาด';
      errEl.style.display = 'block';
    }
  } catch(e) {
    errEl.textContent = 'ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์';
    errEl.style.display = 'block';
  }
}
document.addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });
</script>
"""


@app.route("/dashboard")
def page_dashboard():
    return CSS_VARS + """
<script src="/static/app.js"></script>
<nav style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 24px;
            display:flex;align-items:center;height:56px;gap:16px;">
  <span style="color:var(--text-main);font-weight:700;">◈ Leagues of Code</span>
  <span style="color:var(--accent);font-weight:600;">ธนาคารกรุงเทพดิจิทัล</span>
  <span style="flex:1"></span>
  <button onclick="logout()"
    style="background:transparent;border:1px solid var(--text-danger);color:var(--text-danger);
           padding:6px 16px;border-radius:var(--radius);cursor:pointer;font-size:.875rem;">
    ออกจากระบบ
  </button>
</nav>
<div style="padding:32px;max-width:900px;margin:0 auto;">
  <h1 style="font-size:1.4rem;margin-bottom:24px;color:var(--text-main);">หน้าหลัก</h1>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">

    <div class="card">
      <h2 style="font-size:1rem;color:var(--text-muted);margin-bottom:16px;">ข้อมูลบัญชี</h2>
      <div id="username-display" style="font-size:1.1rem;font-weight:600;margin-bottom:8px;">—</div>
      <div style="color:var(--text-muted);font-size:.8rem;margin-bottom:4px;">ยอดเงินคงเหลือ</div>
      <div id="balance-display"
           style="font-size:2rem;font-weight:700;color:var(--accent);margin-bottom:24px;">—</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        <button class="btn-secondary" onclick="navigate('/transactions')">
          ดูประวัติการทำธุรกรรม
        </button>
        <button class="btn-secondary" onclick="navigate('/transfer')">
          โอนเงิน
        </button>
      </div>
    </div>

    <div class="card">
      <h2 style="font-size:1rem;color:var(--text-muted);margin-bottom:16px;">ข้อมูลโปรไฟล์</h2>
      <div style="margin-bottom:8px;">
        <span style="color:var(--text-muted);font-size:.85rem;">ชื่อ: </span>
        <span id="profile-name">—</span>
      </div>
      <div style="margin-bottom:20px;">
        <span style="color:var(--text-muted);font-size:.85rem;">อีเมล: </span>
        <span id="profile-email" style="color:var(--text-muted);">—</span>
      </div>
      <button class="btn-secondary" onclick="navigate('/profile')">
        แก้ไขโปรไฟล์
      </button>
    </div>

  </div>

  <!-- spacer: flag is ~5 screens below -->
  <div style="height:500vh;"></div>

  <div id="flag-banner"
       style="display:none;background:#1a2e1a;border:1px solid var(--text-success);
              border-radius:var(--radius);padding:16px 20px;margin-bottom:32px;">
    <div style="color:var(--text-success);font-size:.8rem;font-weight:600;margin-bottom:4px;">
      ◈ ADMIN ACCESS GRANTED
    </div>
    <div id="flag-value"
         style="font-family:monospace;font-size:1rem;color:var(--accent);word-break:break-all;"></div>
  </div>
</div>
<script>
window.authToken = window.location.hash.slice(1) || null;
if (!window.authToken) { window.location.href = '/'; }
function navigate(path) { window.location.href = path + '#' + window.authToken; }
function logout() { window.location.href = '/'; }

async function loadDashboard() {
  try {
    const headers = { Authorization: 'Bearer ' + window.authToken };

    const [userRes, meRes] = await Promise.all([
      fetch('/api/users/1', { headers }),
      fetch('/api/me',      { headers }),
    ]);
    if (userRes.status === 401) { window.location.href = '/'; return; }

    const data   = await userRes.json();
    const meData = await meRes.json();

    document.getElementById('username-display').textContent = data['ชื่อ'] || '—';
    document.getElementById('balance-display').textContent =
      '฿' + (data['ยอดเงิน'] || 0).toLocaleString();
    document.getElementById('profile-name').textContent  = data['ชื่อ']  || '—';
    document.getElementById('profile-email').textContent = data['อีเมล'] || '—';

    if (meData.flag) {
      document.getElementById('flag-value').textContent = meData.flag;
      document.getElementById('flag-banner').style.display = 'block';
    }
  } catch(e) {
    console.error(e);
  }
}
loadDashboard();
</script>
"""


@app.route("/transactions")
def page_transactions():
    return CSS_VARS + """
<script src="/static/app.js"></script>
<nav style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 24px;
            display:flex;align-items:center;height:56px;gap:16px;">
  <span style="color:var(--text-main);font-weight:700;">◈ Leagues of Code</span>
  <span style="color:var(--accent);font-weight:600;">ธนาคารกรุงเทพดิจิทัล</span>
  <span style="color:var(--text-muted);font-size:.875rem;">/ ประวัติการทำธุรกรรม</span>
  <span style="flex:1"></span>
  <button class="btn-secondary" onclick="navigate('/dashboard')"
          style="margin-right:8px;width:auto;">← กลับ</button>
  <button onclick="logout()"
    style="background:transparent;border:1px solid var(--text-danger);color:var(--text-danger);
           padding:6px 16px;border-radius:var(--radius);cursor:pointer;font-size:.875rem;">
    ออกจากระบบ
  </button>
</nav>
<div style="padding:32px;max-width:800px;margin:0 auto;">
  <h1 id="page-title" style="font-size:1.3rem;margin-bottom:24px;">ประวัติการทำธุรกรรม — …</h1>
  <div class="card" style="padding:0;overflow:hidden;">
    <table id="tx-table"
           style="width:100%;border-collapse:collapse;display:none;">
      <thead>
        <tr style="background:var(--bg-dark);">
          <th style="padding:12px 20px;text-align:left;color:var(--text-muted);font-size:.85rem;">วันที่</th>
          <th style="padding:12px 20px;text-align:right;color:var(--text-muted);font-size:.85rem;">จำนวนเงิน</th>
          <th style="padding:12px 20px;text-align:left;color:var(--text-muted);font-size:.85rem;">ปลายทาง</th>
        </tr>
      </thead>
      <tbody id="tx-body"></tbody>
    </table>
    <div id="tx-empty"
         style="display:none;padding:40px;text-align:center;color:var(--text-muted);">
      ไม่มีรายการ
    </div>
  </div>
</div>
<script>
window.authToken = window.location.hash.slice(1) || null;
if (!window.authToken) { window.location.href = '/'; }
function navigate(path) { window.location.href = path + '#' + window.authToken; }
function logout() { window.location.href = '/'; }

async function loadTransactions() {
  try {
    const userRes = await fetch('/api/users/1', {
      headers: { Authorization: 'Bearer ' + window.authToken }
    });
    if (userRes.status === 401) { window.location.href = '/'; return; }
    const userData = await userRes.json();
    document.getElementById('page-title').textContent =
      'ประวัติการทำธุรกรรม — ' + (userData['ชื่อ'] || '');

    const res = await fetch('/api/users/1/transactions', {
      headers: { Authorization: 'Bearer ' + window.authToken }
    });
    const data = await res.json();
    const items = data['รายการ'] || [];
    if (items.length === 0) {
      document.getElementById('tx-empty').style.display = 'block';
    } else {
      const tbody = document.getElementById('tx-body');
      items.forEach((tx, i) => {
        const tr = document.createElement('tr');
        tr.style.borderTop = i > 0 ? '1px solid var(--border)' : '';
        const color = tx['จำนวนเงิน'] < 0 ? 'var(--text-danger)' : 'var(--text-success)';
        const sign  = tx['จำนวนเงิน'] >= 0 ? '+' : '';
        tr.innerHTML = `
          <td style="padding:14px 20px;font-size:.9rem;">${tx['วันที่']}</td>
          <td style="padding:14px 20px;text-align:right;font-weight:600;color:${color};">
            ${sign}${tx['จำนวนเงิน'].toLocaleString()} บาท
          </td>
          <td style="padding:14px 20px;color:var(--text-muted);font-size:.9rem;">${tx['ปลายทาง']}</td>
        `;
        tbody.appendChild(tr);
      });
      document.getElementById('tx-table').style.display = 'table';
    }
  } catch(e) { console.error(e); }
}
loadTransactions();
</script>
"""


@app.route("/transfer")
def page_transfer():
    return CSS_VARS + """
<script src="/static/app.js"></script>
<nav style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 24px;
            display:flex;align-items:center;height:56px;gap:16px;">
  <span style="color:var(--text-main);font-weight:700;">◈ Leagues of Code</span>
  <span style="color:var(--accent);font-weight:600;">ธนาคารกรุงเทพดิจิทัล</span>
  <span style="color:var(--text-muted);font-size:.875rem;">/ โอนเงิน</span>
  <span style="flex:1"></span>
  <button class="btn-secondary" onclick="navigate('/dashboard')"
          style="margin-right:8px;width:auto;">← กลับ</button>
  <button onclick="logout()"
    style="background:transparent;border:1px solid var(--text-danger);color:var(--text-danger);
           padding:6px 16px;border-radius:var(--radius);cursor:pointer;font-size:.875rem;">
    ออกจากระบบ
  </button>
</nav>
<div style="display:flex;justify-content:center;padding:40px 16px;">
  <div class="card" style="width:480px;">
    <h2 style="font-size:1.1rem;margin-bottom:24px;">โอนเงิน</h2>
    <label for="to-id">รหัสบัญชีผู้รับ</label>
    <input id="to-id" type="number" placeholder="กรอกรหัสบัญชี เช่น 2">
    <label for="amount">จำนวนเงิน (บาท)</label>
    <input id="amount" type="number" placeholder="0.00">
    <div style="margin-top:24px;">
      <button class="btn-primary" onclick="doTransfer()">โอนเงิน</button>
    </div>
    <div id="result" style="display:none;margin-top:14px;font-size:.875rem;text-align:center;"></div>
  </div>
</div>
<script>
window.authToken = window.location.hash.slice(1) || null;
if (!window.authToken) { window.location.href = '/'; }
function navigate(path) { window.location.href = path + '#' + window.authToken; }
function logout() { window.location.href = '/'; }

async function doTransfer() {
  const toId  = parseInt(document.getElementById('to-id').value);
  const amount = parseInt(document.getElementById('amount').value);
  const resEl = document.getElementById('result');
  resEl.style.display = 'none';
  try {
    const res = await fetch('/api/transfer', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + window.authToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ from_id: 1, to_id: toId, amount: amount })
    });
    const data = await res.json();
    resEl.style.display = 'block';
    if (res.ok) {
      resEl.style.color = 'var(--text-success)';
      resEl.textContent = data['ข้อความ'];
    } else {
      resEl.style.color = 'var(--text-danger)';
      resEl.textContent = data['ข้อความ'] || 'เกิดข้อผิดพลาด';
    }
  } catch(e) {
    resEl.style.display = 'block';
    resEl.style.color = 'var(--text-danger)';
    resEl.textContent = 'ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์';
  }
}
</script>
"""


@app.route("/profile")
def page_profile():
    return CSS_VARS + """
<script src="/static/app.js"></script>
<nav style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 24px;
            display:flex;align-items:center;height:56px;gap:16px;">
  <span style="color:var(--text-main);font-weight:700;">◈ Leagues of Code</span>
  <span style="color:var(--accent);font-weight:600;">ธนาคารกรุงเทพดิจิทัล</span>
  <span style="color:var(--text-muted);font-size:.875rem;">/ แก้ไขโปรไฟล์</span>
  <span style="flex:1"></span>
  <button class="btn-secondary" onclick="navigate('/dashboard')"
          style="margin-right:8px;width:auto;">← กลับ</button>
  <button onclick="logout()"
    style="background:transparent;border:1px solid var(--text-danger);color:var(--text-danger);
           padding:6px 16px;border-radius:var(--radius);cursor:pointer;font-size:.875rem;">
    ออกจากระบบ
  </button>
</nav>
<div style="display:flex;justify-content:center;padding:40px 16px;">
  <div class="card" style="width:480px;">
    <h2 style="font-size:1.1rem;margin-bottom:24px;">แก้ไขโปรไฟล์</h2>
    <label for="p-name">ชื่อผู้ใช้</label>
    <input id="p-name" type="text" placeholder="ชื่อผู้ใช้">
    <label for="p-email">อีเมล</label>
    <input id="p-email" type="text" placeholder="อีเมล">
    <div style="margin-top:24px;">
      <button class="btn-primary" onclick="doUpdate()">บันทึกการเปลี่ยนแปลง</button>
    </div>
    <div id="result" style="display:none;margin-top:14px;font-size:.875rem;text-align:center;"></div>
  </div>
</div>
<script>
window.authToken = window.location.hash.slice(1) || null;
if (!window.authToken) { window.location.href = '/'; }
function navigate(path) { window.location.href = path + '#' + window.authToken; }
function logout() { window.location.href = '/'; }

async function loadProfile() {
  const res = await fetch('/api/users/1', {
    headers: { Authorization: 'Bearer ' + window.authToken }
  });
  if (res.status === 401) { window.location.href = '/'; return; }
  const data = await res.json();
  document.getElementById('p-name').value  = data['ชื่อ']  || '';
  document.getElementById('p-email').value = data['อีเมล'] || '';
}

async function doUpdate() {
  const resEl = document.getElementById('result');
  resEl.style.display = 'none';
  const body = {
    'ชื่อ':  document.getElementById('p-name').value,
    'อีเมล': document.getElementById('p-email').value
  };
  try {
    const res = await fetch('/api/users/update', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + window.authToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    resEl.style.display = 'block';
    if (res.ok) {
      resEl.style.color = 'var(--text-success)';
      resEl.textContent = data['ข้อความ'];
    } else {
      resEl.style.color = 'var(--text-danger)';
      resEl.textContent = data['ข้อความ'] || 'เกิดข้อผิดพลาด';
    }
  } catch(e) {
    resEl.style.display = 'block';
    resEl.style.color = 'var(--text-danger)';
    resEl.textContent = 'ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์';
  }
}
loadProfile();
</script>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
