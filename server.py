import os, hashlib, base64, json, time, hmac as _hmac
import uuid as _uuid, datetime, logging
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

log = logging.getLogger("hela")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
SYNC_SECRET  = os.environ.get("HELA_SYNC_SECRET", "hela_sync_secret")
_SECRET      = os.environ.get("HELA_JWT_SECRET", "hela_sacco_jwt_v3")

if DATABASE_URL.startswith("postgres"):
    import psycopg2, psycopg2.extras
    _pg = None

    def _con():
        global _pg
        try:
            if _pg is None or _pg.closed:
                _pg = psycopg2.connect(DATABASE_URL,
                      cursor_factory=psycopg2.extras.RealDictCursor)
                _pg.autocommit = True
        except Exception:
            _pg = psycopg2.connect(DATABASE_URL,
                  cursor_factory=psycopg2.extras.RealDictCursor)
            _pg.autocommit = True
        return _pg

    def db1(sql, p=()):
        sql = sql.replace("?", "%s")
        try:
            with _con().cursor() as c:
                c.execute(sql, p)
                r = c.fetchone()
                return dict(r) if r else None
        except Exception as e:
            log.error(f"db1: {e} | SQL: {sql[:80]}")
            if "no such table" in str(e) or "does not exist" in str(e):
                try: init_db()
                except: pass
            return None

    def dba(sql, p=()):
        sql = sql.replace("?", "%s")
        try:
            with _con().cursor() as c:
                c.execute(sql, p)
                rows = c.fetchall()
                return [dict(r) for r in rows] if rows else []
        except Exception as e:
            log.error(f"dba: {e} | SQL: {sql[:80]}")
            if "no such table" in str(e) or "does not exist" in str(e):
                try: init_db()
                except: pass
            return []

    def dbx(sql, p=()):
        sql = sql.replace("?", "%s")
        try:
            with _con().cursor() as c:
                c.execute(sql, p)
        except Exception as e:
            log.error(f"dbx: {e} | SQL: {sql[:80]}")
            raise

    def init_db():
        log.warning("Creating PostgreSQL tables if not exist...")
        global _pg
        # Force fresh connection for init
        try:
            _pg = psycopg2.connect(DATABASE_URL,
                  cursor_factory=psycopg2.extras.RealDictCursor)
            _pg.autocommit = True
        except Exception as ce:
            log.error(f"DB connect failed: {ce}")
            raise
        dbx("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, salt TEXT NOT NULL,
            iterations INTEGER DEFAULT 10000, role TEXT DEFAULT 'member',
            full_name TEXT, email TEXT, phone TEXT, member_id TEXT,
            is_active INTEGER DEFAULT 1, created_at TEXT, updated_at TEXT)""")
        dbx("""CREATE TABLE IF NOT EXISTS members (
            id TEXT PRIMARY KEY, member_no TEXT UNIQUE NOT NULL,
            first_name TEXT, last_name TEXT, full_name_search TEXT,
            phone TEXT, email TEXT, id_number TEXT,
            kyc_status TEXT DEFAULT 'pending', is_active INTEGER DEFAULT 1,
            membership_date TEXT, created_at TEXT, updated_at TEXT)""")
        dbx("""CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY, member_id TEXT NOT NULL,
            account_no TEXT UNIQUE NOT NULL, account_type TEXT DEFAULT 'savings',
            balance_minor INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1,
            opening_date TEXT, created_at TEXT, updated_at TEXT)""")
        dbx("""CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
            transaction_type TEXT NOT NULL, amount_minor INTEGER NOT NULL,
            description TEXT, channel TEXT DEFAULT 'web',
            reference_number TEXT, created_at TEXT)""")
        dbx("""CREATE TABLE IF NOT EXISTS loans (
            id TEXT PRIMARY KEY, loan_no TEXT,
            member_id TEXT NOT NULL, principal_amount_minor INTEGER NOT NULL,
            outstanding_principal_minor INTEGER DEFAULT 0,
            term_months INTEGER NOT NULL, interest_rate REAL DEFAULT 1.5,
            loan_purpose TEXT, status TEXT DEFAULT 'pending',
            next_payment_date TEXT, next_payment_amount_minor INTEGER DEFAULT 0,
            created_at TEXT, updated_at TEXT)""")
        dbx("""CREATE TABLE IF NOT EXISTS investments (
            id TEXT PRIMARY KEY, member_id TEXT NOT NULL,
            name TEXT, investment_type TEXT, principal_minor INTEGER DEFAULT 0,
            interest_earned_minor INTEGER DEFAULT 0, interest_rate REAL DEFAULT 0,
            start_date TEXT, maturity_date TEXT, status TEXT DEFAULT 'active',
            created_at TEXT)""")
        dbx("""CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY, user_id TEXT, action TEXT, detail TEXT,
            level TEXT DEFAULT 'info', created_at TEXT)""")
else:
    import sqlite3, threading
    _loc = threading.local()
    _DB  = os.environ.get("SQLITE_PATH", "kivy_app.db")

    def _con():
        if not hasattr(_loc, "c") or _loc.c is None:
            _loc.c = sqlite3.connect(_DB, check_same_thread=False)
            _loc.c.row_factory = sqlite3.Row
        return _loc.c

    def db1(sql, p=()):
        try:
            r = _con().execute(sql, p).fetchone()
            return dict(r) if r else None
        except Exception as e:
            log.error(f"db1: {e}")
            return None

    def dba(sql, p=()):
        try:
            return [dict(r) for r in _con().execute(sql, p).fetchall()]
        except Exception as e:
            log.error(f"dba: {e}")
            return []

    def dbx(sql, p=()):
        try:
            _con().execute(sql, p)
            _con().commit()
        except Exception as e:
            log.error(f"dbx: {e}")

    def init_db():
        pass


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sign_jwt(payload, hours=24):
    p = dict(payload)
    p["exp"] = int(time.time()) + hours * 3600
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    b = _b64u(json.dumps(p, separators=(",", ":")).encode())
    s = _b64u(_hmac.new(_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
    return f"{h}.{b}.{s}"

def verify_jwt(token):
    try:
        h, b, s = token.split(".")
        e = _b64u(_hmac.new(_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
        if not _hmac.compare_digest(s, e):
            return None
        p = json.loads(base64.urlsafe_b64decode(b + "=="))
        return None if p.get("exp", 0) < time.time() else p
    except Exception:
        return None

def _hash(pw, salt=None, iters=10000):
    if not salt:
        salt = base64.b64encode(os.urandom(32)).decode()
    h = base64.b64encode(hashlib.pbkdf2_hmac(
        "sha256", pw.encode(), base64.b64decode(salt), iters, 32)).decode()
    return h, salt

def _phone(p):
    p = p.strip().replace(" ", "").replace("-", "").replace("+", "")
    return "254" + p[1:] if p.startswith("0") else p

def _auth_user(request: Request):
    a = request.headers.get("Authorization", "")
    u = verify_jwt(a[7:]) if a.startswith("Bearer ") else None
    if not u:
        raise HTTPException(401, "Not authenticated")
    return u

def _mid(uid):
    r = db1("SELECT member_id FROM users WHERE id=?", (uid,))
    return (r or {}).get("member_id") or uid

def _get_html():
    for name in ["hela_portal.html", "index.html"]:
        if os.path.exists(name):
            return open(name, encoding="utf-8").read()
    return "<h2>HELA SACCO</h2><p>hela_portal.html not found</p>"


app = FastAPI(title="HELA SMART SACCO", docs_url=None, redoc_url=None)

# Create tables immediately at module load (before any request)
try:
    init_db()
    log.warning("HELA: Tables ready at module load")
except Exception as _e:
    log.error(f"HELA: Module-level init_db failed: {_e}")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
async def startup():
    try:
        log.warning("=== HELA: Running init_db ===")
        init_db()
        r = db1("SELECT COUNT(*) as c FROM users")
        cnt = (r or {}).get('c', 0)
        log.warning(f"=== HELA: init_db OK, {cnt} users ===")

        # AUTO-PROMOTE ADMIN — reads ADMIN_PHONE env var (set on Render)
        admin_phone = os.environ.get("ADMIN_PHONE", "0704363089")
        norm = "254" + admin_phone.lstrip("0") if admin_phone.startswith("0") else admin_phone
        local = "0" + norm[3:] if norm.startswith("254") else admin_phone
        user = (
            db1("SELECT id,username,role FROM users WHERE username=? OR phone=?", (admin_phone, admin_phone)) or
            db1("SELECT id,username,role FROM users WHERE username=? OR phone=?", (norm, norm)) or
            db1("SELECT id,username,role FROM users WHERE username=? OR phone=?", (local, local))
        )
        if user and user.get("role") != "admin":
            dbx("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
            log.warning("=== HELA: Auto-promoted " + str(user.get("username")) + " to admin ===")
        elif user:
            log.warning("=== HELA: " + str(user.get("username")) + " is already admin ===")
        else:
            log.warning(f"=== HELA: Admin phone {admin_phone} not yet registered ===")
    except Exception as e:
        log.error(f"=== HELA: startup FAILED: {e} ===")
        import traceback; traceback.print_exc()


@app.post("/api/auth/login")
async def login(request: Request):
    b     = await request.json()
    phone = str(b.get("phone", "")).strip()
    pw    = str(b.get("password", "")).strip()
    if not phone or not pw:
        raise HTTPException(400, "Phone and password required")
    p = _phone(phone)
    # Build all possible formats for the identifier
    raw  = phone  # original input
    norm = _phone(raw)  # 254XXXXXXXXX format
    # Also try 0XXXXXXXXX format
    local = "0" + norm[3:] if norm.startswith("254") and len(norm) == 12 else raw

    m = (db1(
            "SELECT u.id as uid, u.password_hash, u.salt, u.iterations, "
            "u.role, u.full_name, u.member_id, mem.member_no "
            "FROM users u LEFT JOIN members mem ON mem.id=u.member_id "
            "WHERE (u.phone=? OR u.phone=? OR u.phone=? "
            "    OR u.username=? OR u.username=? OR u.email=? "
            "    OR mem.phone=? OR mem.phone=? OR mem.phone=? OR mem.email=?) "
            "AND u.is_active=1",
            (raw, norm, local, raw, norm, raw, raw, norm, local, raw))
        or db1(
            "SELECT u.id as uid, u.password_hash, u.salt, u.iterations, "
            "u.role, u.full_name, u.member_id, mem.member_no "
            "FROM members mem JOIN users u ON u.member_id=mem.id "
            "WHERE mem.member_no=? AND u.is_active=1", (raw,)))
    if not m:
        raise HTTPException(401, "Phone number or password is incorrect")
    uid    = m["uid"]
    iters  = int(m.get("iterations") or 10000)
    stored = m["password_hash"]
    salt   = m["salt"]
    fast_h, _ = _hash(pw, salt, 10000)
    if fast_h == stored:
        ok = True
    elif iters > 10000:
        slow_h, _ = _hash(pw, salt, iters)
        ok = (slow_h == stored)
        if ok:
            try:
                dbx("UPDATE users SET password_hash=?,iterations=? WHERE id=?",
                    (fast_h, 10000, uid))
            except Exception:
                pass
    else:
        ok = False
    if not ok:
        raise HTTPException(401, "Phone number or password is incorrect")
    role = (m.get("role") or "member").lower()
    return {"token": sign_jwt({"sub": uid, "role": role}),
            "role": role, "name": m.get("full_name") or ""}


@app.post("/api/auth/register")
async def register(request: Request):
    b     = await request.json()
    first = str(b.get("first_name", "")).strip()
    last  = str(b.get("last_name",  "")).strip()
    phone = str(b.get("phone",      "")).strip()
    id_no = str(b.get("id_number",  "")).strip()
    email = str(b.get("email",      "")).strip()
    pw    = str(b.get("password",   "")).strip()
    if not first or not last:
        raise HTTPException(400, "Full name required")
    if not phone:
        raise HTTPException(400, "Phone number required")
    if not id_no:
        raise HTTPException(400, "National ID required")
    if len(pw) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    p = _phone(phone)
    if db1("SELECT id FROM members WHERE phone=? OR phone=?", (phone, p)):
        raise HTTPException(409, "Phone number already registered")
    if db1("SELECT id FROM members WHERE id_number=?", (id_no,)):
        raise HTTPException(409, "National ID already registered")
    now  = datetime.datetime.now().isoformat()
    uid  = str(_uuid.uuid4())
    mid  = str(_uuid.uuid4())
    full = f"{first} {last}"
    cnt  = (db1("SELECT COUNT(*) as c FROM members") or {}).get("c", 0)
    mno  = f"HLS{str(cnt + 1).zfill(5)}"
    pw_h, salt = _hash(pw)
    dbx("INSERT INTO users (id,username,password_hash,salt,iterations,"
        "role,full_name,phone,member_id,is_active,created_at,updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,1,?,?)",
        (uid, p, pw_h, salt, 10000, "member", full, p, mid, now, now))
    dbx("INSERT INTO members (id,member_no,first_name,last_name,"
        "full_name_search,phone,email,id_number,is_active,kyc_status,"
        "membership_date,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,1,'pending',?,?,?)",
        (mid, mno, first, last, full.lower(), p, email, id_no, now[:10], now, now))
    dbx("INSERT INTO accounts (id,member_id,account_no,account_type,"
        "balance_minor,is_active,opening_date,created_at,updated_at) "
        "VALUES (?,?,?,'savings',0,1,?,?,?)",
        (str(_uuid.uuid4()), mid, f"SAV{mno[3:]}", now[:10], now, now))
    return {"token": sign_jwt({"sub": uid, "role": "member"}),
            "role": "member", "name": full, "member_no": mno,
            "message": "Account created! Visit a branch to complete KYC."}


@app.get("/api/me")
async def get_me(u: dict = Depends(_auth_user)):
    uid = u["sub"]
    user_row = db1("SELECT * FROM users WHERE id=?", (uid,))
    if not user_row:
        raise HTTPException(404, "User not found")
    member_id = user_row.get("member_id")
    mem_row = db1("SELECT * FROM members WHERE id=?", (member_id,)) if member_id else None
    if not mem_row:
        # No member record yet — return basic info from users table
        return {
            "id": uid,
            "name": user_row.get("full_name",""),
            "member_no": "",
            "phone": user_row.get("phone",""),
            "email": user_row.get("email",""),
            "kyc_status": "pending",
            "balance": 0,
            "account_no": "",
            "account_id": "",
            "loans": [],
        }
    m = {**mem_row, "username": user_row.get("username",""),
         "role": user_row.get("role","member"),
         "u_name": user_row.get("full_name","")}
    mid = member_id
    acc = db1("SELECT * FROM accounts WHERE member_id=? "
              "AND account_type='savings' ORDER BY opening_date LIMIT 1", (mid,))
    loans = dba("SELECT id,principal_amount_minor,outstanding_principal_minor,status,"
                "next_payment_date,next_payment_amount_minor FROM loans "
                "WHERE member_id=? AND status IN ('active','disbursed','overdue') "
                "ORDER BY created_at DESC", (mid,))
    return {
        "id": mid,
        "name": m.get("full_name") or m.get("u_name") or m.get("username", ""),
        "member_no": m.get("member_no", ""),
        "phone": m.get("phone", ""),
        "email": m.get("email", ""),
        "kyc_status": m.get("kyc_status", "pending"),
        "balance": (acc or {}).get("balance_minor", 0) / 100,
        "account_no": (acc or {}).get("account_no", ""),
        "account_id": (acc or {}).get("id", ""),
        "loans": [{"id": l["id"],
                   "principal": l["principal_amount_minor"] / 100,
                   "outstanding": l["outstanding_principal_minor"] / 100,
                   "status": l["status"],
                   "next_due": str(l.get("next_payment_date", "") or ""),
                   "installment": l.get("next_payment_amount_minor", 0) / 100}
                  for l in loans],
    }


@app.get("/api/me/statement")
async def get_statement(limit: int = 30, offset: int = 0,
                        u: dict = Depends(_auth_user)):
    mid  = _mid(u["sub"])
    txns = dba("SELECT t.* FROM transactions t "
               "JOIN accounts a ON a.id=t.account_id "
               "WHERE a.member_id=? ORDER BY t.created_at DESC LIMIT ? OFFSET ?",
               (mid, min(limit, 100), offset))
    return {"transactions": [{"id": t["id"], "type": t["transaction_type"],
                               "amount": t["amount_minor"] / 100, "balance": 0,
                               "description": t.get("description", ""),
                               "channel": t.get("channel", ""),
                               "date": str(t.get("created_at", "")),
                               "reference": t.get("reference_number", "")}
                              for t in txns]}


@app.get("/api/me/loans")
async def get_loans(u: dict = Depends(_auth_user)):
    mid   = _mid(u["sub"])
    loans = dba("SELECT id,principal_amount_minor,outstanding_principal_minor,status,"
                "next_payment_date,next_payment_amount_minor,term_months,"
                "interest_rate,loan_purpose FROM loans "
                "WHERE member_id=? ORDER BY created_at DESC", (mid,))
    return {"loans": [{"id": l["id"],
                        "amount": l["principal_amount_minor"] / 100,
                        "outstanding": l.get("outstanding_principal_minor", 0) / 100,
                        "status": l["status"],
                        "next_due": str(l.get("next_payment_date", "") or ""),
                        "installment": l.get("next_payment_amount_minor", 0) / 100,
                        "term_months": l.get("term_months", 0),
                        "interest_rate": l.get("interest_rate", 0),
                        "purpose": l.get("loan_purpose", "")}
                       for l in loans]}


@app.get("/api/me/investments")
async def get_investments(u: dict = Depends(_auth_user)):
    mid  = _mid(u["sub"])
    invs = dba("SELECT * FROM investments WHERE member_id=? "
               "ORDER BY created_at DESC", (mid,))
    return {"investments": [{"id": i["id"], "name": i.get("name", ""),
                              "type": i.get("investment_type", ""),
                              "principal": i.get("principal_minor", 0) / 100,
                              "interest": i.get("interest_earned_minor", 0) / 100,
                              "rate": i.get("interest_rate", 0),
                              "start": str(i.get("start_date", "")),
                              "maturity": str(i.get("maturity_date", "")),
                              "status": i.get("status", "")}
                             for i in invs]}


@app.post("/api/me/loan_apply")
async def loan_apply(request: Request, u: dict = Depends(_auth_user)):
    mid  = _mid(u["sub"])
    b    = await request.json()
    amt  = float(b.get("amount", 0))
    term = int(b.get("term_months", 12))
    purp = str(b.get("purpose", "Personal")).strip()
    if amt < 1000:
        raise HTTPException(400, "Minimum loan is KSh 1,000")
    if not 1 <= term <= 60:
        raise HTTPException(400, "Term must be 1-60 months")
    lid = str(_uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    lno = f"LN{now[:10].replace('-','')}{lid[:6].upper()}"
    dbx("INSERT INTO loans (id,loan_no,member_id,principal_amount_minor,"
        "outstanding_principal_minor,term_months,loan_purpose,status,"
        "interest_rate,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'pending',1.5,?,?)",
        (lid, lno, mid, int(amt * 100), int(amt * 100), term, purp, now, now))
    return {"status": "submitted", "loan_id": lid,
            "message": "Application submitted. We'll contact you within 24 hours."}


@app.post("/api/me/stk_deposit")
async def stk_deposit(u: dict = Depends(_auth_user)):
    raise HTTPException(503, "STK Push not available on web. Use the mobile app.")


@app.post("/mpesa/stk_callback")
async def stk_cb():
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


@app.post("/mpesa/b2c_callback")
async def b2c_cb():
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


@app.post("/api/ai/chat")
async def ai_chat(request: Request, u: dict = Depends(_auth_user)):
    b = await request.json()
    messages  = b.get("messages", [])
    system_p  = b.get("system", "You are HELA AI, a helpful SACCO assistant.")
    if not messages:
        raise HTTPException(400, "No messages provided")

    import urllib.request as _ur, json as _json
    payload = _json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1000,
        "system": system_p,
        "messages": messages[-20:]
    }).encode()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(503, "AI service not configured")

    req = _ur.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )
    try:
        with _ur.urlopen(req, timeout=30) as resp:
            result = _json.loads(resp.read())
            text = " ".join(blk["text"] for blk in result.get("content", []) if blk.get("type") == "text")
            return {"reply": text}
    except _ur.HTTPError as e:
        body = e.read().decode()
        log.error(f"AI chat HTTP error: {e.code} {body}")
        raise HTTPException(502, f"AI error: {e.code}")
    except Exception as e:
        log.error(f"AI chat error: {type(e).__name__}: {e}")
        raise HTTPException(502, "AI service temporarily unavailable")



# ══════════════════════════════════════════════════════════
# OTP — Send & Verify
# ══════════════════════════════════════════════════════════
import random, string
_otp_store = {}  # {phone: {otp, expires}}

def _norm_phone(p):
    p = str(p).strip().replace(" ", "").replace("-","")
    if p.startswith("0") and len(p)==10: return "254"+p[1:]
    if p.startswith("+254"): return p[1:]
    return p

@app.post("/api/auth/send_otp")
async def send_otp(request: Request):
    b = await request.json()
    phone = _norm_phone(b.get("phone",""))
    if not phone: raise HTTPException(400,"Phone required")
    otp = "".join(random.choices(string.digits,k=6))
    _otp_store[phone] = {"otp":otp,"expires":time.time()+120}
    # Send via Africa's Talking (or log if no key)
    at_key = os.environ.get("AT_API_KEY","")
    at_user = os.environ.get("AT_USERNAME","sandbox")
    msg = f"Your HELA SMART SACCO verification code is: {otp}. Valid for 2 minutes. Do not share."
    if at_key:
        try:
            import urllib.request as _ur2, urllib.parse as _up
            data = _up.urlencode({"username":at_user,"to":"+"+phone,"message":msg}).encode()
            req2 = _ur2.Request("https://api.africastalking.com/version1/messaging",
                data=data,
                headers={"apiKey":at_key,"Accept":"application/json",
                         "Content-Type":"application/x-www-form-urlencoded"})
            with _ur2.urlopen(req2,timeout=10) as resp:
                log.info(f"OTP SMS sent to {phone}")
        except Exception as e:
            log.error(f"SMS failed: {e}")
    else:
        log.warning(f"OTP for {phone}: {otp} (no AT_API_KEY set)")
    return {"status":"ok","message":f"OTP sent to {phone[-4:].rjust(10,'*')}"}

@app.post("/api/auth/verify_otp")
async def verify_otp(request: Request):
    b = await request.json()
    phone = _norm_phone(b.get("phone",""))
    otp = str(b.get("otp","")).strip()
    stored = _otp_store.get(phone)
    if not stored: raise HTTPException(400,"No OTP sent to this number")
    if time.time() > stored["expires"]: 
        del _otp_store[phone]
        raise HTTPException(400,"OTP has expired. Request a new one.")
    if stored["otp"] != otp: raise HTTPException(400,"Incorrect OTP code")
    del _otp_store[phone]
    # Find user by phone and return token
    user = (db1("SELECT u.id as uid,u.role,u.full_name,u.member_id,mem.member_no "
                "FROM users u LEFT JOIN members mem ON mem.id=u.member_id "
                "WHERE (u.phone=? OR u.phone=?) AND u.is_active=1",(phone,"0"+phone[3:] if phone.startswith("254") else phone,))
            or db1("SELECT u.id as uid,u.role,u.full_name,u.member_id,mem.member_no "
                   "FROM users u LEFT JOIN members mem ON mem.id=u.member_id "
                   "WHERE u.phone=? AND u.is_active=1",(phone,)))
    if not user: raise HTTPException(404,"User not found for this phone number")
    token = sign_jwt({"sub":user["uid"],"role":user.get("role","member")})
    _log_audit(user["uid"],"login","OTP login verified")
    return {"token":token,"name":user.get("full_name",""),"member_no":user.get("member_no","")}

# ══════════════════════════════════════════════════════════
# AUDIT LOG
# ══════════════════════════════════════════════════════════
def _log_audit(user_id, action, detail="", level="info"):
    try:
        dbx("INSERT INTO audit_log (id,user_id,action,detail,level,created_at) VALUES (?,?,?,?,?,?)",
            (_uuid.uuid4().hex, user_id, action, detail, level, datetime.datetime.now().isoformat()))
    except Exception as e:
        log.error(f"Audit log failed: {e}")

@app.get("/api/me/audit")
async def get_audit(request: Request, limit:int=50, u:dict=Depends(_auth_user)):
    logs = dba("SELECT * FROM audit_log WHERE user_id=? ORDER BY created_at DESC LIMIT ?",(u["sub"],limit))
    return {"logs":logs}

# ══════════════════════════════════════════════════════════
# KYC UPLOAD
# ══════════════════════════════════════════════════════════
@app.post("/api/me/kyc_upload")
async def kyc_upload(request: Request, u:dict=Depends(_auth_user)):
    b = await request.json()
    front = b.get("front_image","")
    back  = b.get("back_image","")
    if not front or not back: raise HTTPException(400,"Both front and back images required")
    uid = u["sub"]
    now = datetime.datetime.now().isoformat()
    # Save base64 images to DB (store reference)
    dbx("UPDATE users SET updated_at=? WHERE id=?",(now,uid))
    dbx("UPDATE members SET kyc_status='submitted',updated_at=? WHERE id=(SELECT member_id FROM users WHERE id=?)",(now,uid))
    _log_audit(uid,"kyc_upload","KYC documents submitted for review")
    return {"status":"ok","message":"KYC documents submitted. Review takes 1-2 business days."}

# ══════════════════════════════════════════════════════════
# ADMIN ENDPOINTS
# ══════════════════════════════════════════════════════════
def _require_admin(u:dict=Depends(_auth_user)):
    if u.get("role","member") not in ("admin","superadmin"):
        raise HTTPException(403,"Admin access required")
    return u

@app.get("/api/admin/stats")
async def admin_stats(u:dict=Depends(_require_admin)):
    total_members = (db1("SELECT COUNT(*) as c FROM members WHERE is_active=1") or {}).get("c",0)
    total_savings  = (db1("SELECT COALESCE(SUM(balance_minor),0) as s FROM accounts WHERE is_active=1") or {}).get("s",0)
    active_loans   = (db1("SELECT COUNT(*) as c FROM loans WHERE status IN ('active','disbursed')") or {}).get("c",0)
    pending_kyc    = (db1("SELECT COUNT(*) as c FROM members WHERE kyc_status='pending' AND is_active=1") or {}).get("c",0)
    pending_loans  = (db1("SELECT COUNT(*) as c FROM loans WHERE status='pending'") or {}).get("c",0)
    return {"total_members":total_members,"total_savings":total_savings/100,
            "active_loans":active_loans,"pending_kyc":pending_kyc,"pending_loans":pending_loans}

@app.get("/api/admin/members")
async def admin_members(limit:int=50, u:dict=Depends(_require_admin)):
    members = dba("""SELECT m.id,m.member_no,m.full_name_search as full_name,m.phone,m.email,
                            m.kyc_status,m.membership_date,
                            COALESCE(a.balance_minor,0)/100.0 as balance
                     FROM members m LEFT JOIN accounts a ON a.member_id=m.id
                     WHERE m.is_active=1 ORDER BY m.created_at DESC LIMIT ?""",(limit,))
    return {"members":members}

@app.get("/api/admin/loans")
async def admin_loans(status:str="pending", u:dict=Depends(_require_admin)):
    loans = dba("""SELECT l.*,m.full_name_search as member_name,m.member_no,
                          l.principal_amount_minor/100.0 as amount
                   FROM loans l JOIN members m ON m.id=l.member_id
                   WHERE l.status=? ORDER BY l.created_at DESC LIMIT 100""",(status,))
    return {"loans":loans}

@app.post("/api/admin/loans/{loan_id}/{action}")
async def admin_loan_action(loan_id:str, action:str, u:dict=Depends(_require_admin)):
    if action not in ("approved","rejected"): raise HTTPException(400,"Invalid action")
    now = datetime.datetime.now().isoformat()
    loan = db1("SELECT * FROM loans WHERE id=?",(loan_id,))
    if not loan: raise HTTPException(404,"Loan not found")
    new_status = "approved" if action=="approved" else "rejected"
    dbx("UPDATE loans SET status=?,updated_at=? WHERE id=?",(new_status,now,loan_id))
    _log_audit(u["sub"],"loan_"+action,f"Loan {loan_id} {action}")
    return {"status":"ok","message":f"Loan {action}"}

_broadcasts = []  # In-memory broadcast store
@app.post("/api/admin/broadcast")
async def broadcast(request:Request, u:dict=Depends(_require_admin)):
    b = await request.json()
    msg = str(b.get("message","")).strip()
    if not msg: raise HTTPException(400,"Message required")
    _broadcasts.insert(0,{"id":_uuid.uuid4().hex,"message":msg,
                           "created_at":datetime.datetime.now().isoformat(),"sender":u["sub"]})
    _broadcasts[:] = _broadcasts[:50]  # Keep last 50
    _log_audit(u["sub"],"broadcast",f"Sent: {msg[:50]}")
    return {"status":"ok","sent_to":"all members"}

# ── ONE-TIME ADMIN SETUP (no auth, protected by secret key) ──────────────────
@app.get("/api/setup-admin")
async def setup_admin(phone: str, secret: str):
    expected = os.environ.get("ADMIN_SETUP_SECRET", "hela_master_2024")
    if secret != expected:
        raise HTTPException(403, "Invalid secret key")
    # Try all phone formats
    norm = "254" + phone.lstrip("0") if phone.startswith("0") else phone
    local = "0" + norm[3:] if norm.startswith("254") else phone
    user = (
        db1("SELECT id,username,role FROM users WHERE username=? OR phone=?", (phone, phone)) or
        db1("SELECT id,username,role FROM users WHERE username=? OR phone=?", (norm, norm)) or
        db1("SELECT id,username,role FROM users WHERE username=? OR phone=?", (local, local))
    )
    if not user:
        all_u = dba("SELECT id, username, phone, role FROM users LIMIT 30")
        db_path = os.environ.get("SQLITE_PATH", "kivy_app.db")
        return {
            "error": f"User not found for: {phone} / {norm} / {local}",
            "db_path": db_path,
            "registered_users": [dict(u) for u in all_u]
        }
    dbx("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
    return {"success": True, "message": "✅ Promoted to admin!", "username": user["username"], "role": "admin"}

@app.get("/api/list-users")
async def list_users(secret: str):
    expected = os.environ.get("ADMIN_SETUP_SECRET", "hela_master_2024")
    if secret != expected:
        raise HTTPException(403, "Invalid secret key")
    users = dba("SELECT id, username, phone, role, created_at FROM users ORDER BY created_at DESC LIMIT 30")
    return {"users": [dict(u) for u in users]}

@app.get("/api/notifications")
async def get_notifications(u:dict=Depends(_auth_user)):
    """Return broadcasts + personal notifications"""
    notes = list(_broadcasts[:10])
    return {"notifications":notes}

@app.post("/api/me/change_password")
async def change_password(request: Request, u: dict = Depends(_auth_user)):
    uid = u["sub"]
    b   = await request.json()
    old_pw = str(b.get("old_password","")).strip()
    new_pw = str(b.get("new_password","")).strip()
    if not old_pw or not new_pw:
        raise HTTPException(400, "Both passwords required")
    if len(new_pw) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    user = db1("SELECT * FROM users WHERE id=?", (uid,))
    if not user:
        raise HTTPException(404, "User not found")
    stored = user["password_hash"]
    salt   = user["salt"]
    iters  = int(user.get("iterations") or 10000)
    check_h, _ = _hash(old_pw, salt, iters)
    if check_h != stored:
        raise HTTPException(401, "Current password is incorrect")
    new_h, new_salt = _hash(new_pw)
    now = datetime.datetime.now().isoformat()
    dbx("UPDATE users SET password_hash=?,salt=?,iterations=?,updated_at=? WHERE id=?",
        (new_h, new_salt, 10000, now, uid))
    return {"status": "ok", "message": "Password changed successfully"}


@app.post("/api/sync/push")
async def sync_push(request: Request):
    if request.headers.get("X-Sync-Secret") != SYNC_SECRET:
        raise HTTPException(403, "Invalid sync secret")
    data  = await request.json()
    stats = {"members": 0, "users": 0, "accounts": 0,
             "transactions": 0, "loans": 0}
    for u in data.get("users", []):
        if db1("SELECT id FROM users WHERE id=?", (u["id"],)):
            dbx("UPDATE users SET username=?,full_name=?,phone=?,role=?,"
                "member_id=?,is_active=?,updated_at=? WHERE id=?",
                (u.get("username", ""), u.get("full_name", ""), u.get("phone", ""),
                 u.get("role", "member"), u.get("member_id"),
                 u.get("is_active", 1), u.get("updated_at", ""), u["id"]))
        else:
            dbx("INSERT INTO users (id,username,password_hash,salt,iterations,"
                "role,full_name,phone,member_id,is_active,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (u["id"], u.get("username", ""), u.get("password_hash", ""),
                 u.get("salt", ""), u.get("iterations", 10000),
                 u.get("role", "member"), u.get("full_name", ""),
                 u.get("phone", ""), u.get("member_id"),
                 u.get("is_active", 1), u.get("created_at", ""),
                 u.get("updated_at", "")))
        stats["users"] += 1
    for m in data.get("members", []):
        if db1("SELECT id FROM members WHERE id=?", (m["id"],)):
            dbx("UPDATE members SET member_no=?,first_name=?,last_name=?,"
                "full_name_search=?,phone=?,email=?,id_number=?,"
                "kyc_status=?,is_active=?,updated_at=? WHERE id=?",
                (m.get("member_no", ""), m.get("first_name", ""),
                 m.get("last_name", ""), m.get("full_name_search", ""),
                 m.get("phone", ""), m.get("email", ""), m.get("id_number", ""),
                 m.get("kyc_status", "pending"), m.get("is_active", 1),
                 m.get("updated_at", ""), m["id"]))
        else:
            dbx("INSERT INTO members (id,member_no,first_name,last_name,"
                "full_name_search,phone,email,id_number,kyc_status,is_active,"
                "membership_date,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (m["id"], m.get("member_no", ""), m.get("first_name", ""),
                 m.get("last_name", ""), m.get("full_name_search", ""),
                 m.get("phone", ""), m.get("email", ""), m.get("id_number", ""),
                 m.get("kyc_status", "pending"), m.get("is_active", 1),
                 m.get("membership_date", ""), m.get("created_at", ""),
                 m.get("updated_at", "")))
        stats["members"] += 1
    for a in data.get("accounts", []):
        if db1("SELECT id FROM accounts WHERE id=?", (a["id"],)):
            dbx("UPDATE accounts SET balance_minor=?,is_active=?,updated_at=? WHERE id=?",
                (a.get("balance_minor", 0), a.get("is_active", 1),
                 a.get("updated_at", ""), a["id"]))
        else:
            dbx("INSERT INTO accounts (id,member_id,account_no,account_type,"
                "balance_minor,is_active,opening_date,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (a["id"], a.get("member_id", ""), a.get("account_no", ""),
                 a.get("account_type", "savings"), a.get("balance_minor", 0),
                 a.get("is_active", 1), a.get("opening_date", ""),
                 a.get("created_at", ""), a.get("updated_at", "")))
        stats["accounts"] += 1
    for t in data.get("transactions", []):
        if not db1("SELECT id FROM transactions WHERE id=?", (t["id"],)):
            dbx("INSERT INTO transactions (id,account_id,transaction_type,"
                "amount_minor,description,channel,reference_number,created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (t["id"], t.get("account_id", ""), t.get("transaction_type", ""),
                 t.get("amount_minor", 0), t.get("description", ""),
                 t.get("channel", ""), t.get("reference_number", ""),
                 t.get("created_at", "")))
            stats["transactions"] += 1
    for l in data.get("loans", []):
        if db1("SELECT id FROM loans WHERE id=?", (l["id"],)):
            dbx("UPDATE loans SET status=?,outstanding_principal_minor=?,"
                "next_payment_date=?,updated_at=? WHERE id=?",
                (l.get("status", "pending"),
                 l.get("outstanding_principal_minor",
                        l.get("principal_amount_minor", 0)),
                 l.get("next_payment_date"), l.get("updated_at", ""), l["id"]))
        else:
            dbx("INSERT INTO loans (id,loan_no,member_id,principal_amount_minor,"
                "outstanding_principal_minor,term_months,interest_rate,loan_purpose,"
                "status,next_payment_date,next_payment_amount_minor,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (l["id"], l.get("loan_no", ""), l.get("member_id", ""),
                 l.get("principal_amount_minor", 0),
                 l.get("outstanding_principal_minor",
                        l.get("principal_amount_minor", 0)),
                 l.get("term_months", 12), l.get("interest_rate", 1.5),
                 l.get("loan_purpose", ""), l.get("status", "pending"),
                 l.get("next_payment_date"), l.get("next_payment_amount_minor", 0),
                 l.get("created_at", ""), l.get("updated_at", "")))
        stats["loans"] += 1
    return {"status": "ok", "synced": stats,
            "timestamp": datetime.datetime.now().isoformat()}


@app.get("/api/sync/status")
async def sync_status(request: Request):
    if request.headers.get("X-Sync-Secret") != SYNC_SECRET:
        raise HTTPException(403, "Invalid sync secret")
    return {
        "members":      (db1("SELECT COUNT(*) as c FROM members") or {}).get("c", 0),
        "users":        (db1("SELECT COUNT(*) as c FROM users") or {}).get("c", 0),
        "accounts":     (db1("SELECT COUNT(*) as c FROM accounts") or {}).get("c", 0),
        "transactions": (db1("SELECT COUNT(*) as c FROM transactions") or {}).get("c", 0),
        "loans":        (db1("SELECT COUNT(*) as c FROM loans") or {}).get("c", 0),
        "timestamp":    datetime.datetime.now().isoformat(),
    }


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(_get_html())


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa(full_path: str):
    return HTMLResponse(_get_html())
