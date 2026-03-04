# main.py - HELA SMART SACCO FastAPI Server (Render deployment)
import os, hashlib, base64, json, time, hmac as _hmac
import uuid as _uuid, datetime, logging
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

log = logging.getLogger("hela")

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")

if DATABASE_URL.startswith("postgres"):
    # Render PostgreSQL
    import psycopg2, psycopg2.extras
    _pg_conn = None

    def get_db():
        global _pg_conn
        try:
            if _pg_conn is None or _pg_conn.closed:
                _pg_conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
                _pg_conn.autocommit = True
        except Exception:
            _pg_conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            _pg_conn.autocommit = True
        return _pg_conn

    def db_fetch_one(sql, params=()):
        sql = sql.replace("?", "%s")
        with get_db().cursor() as cur:
            cur.execute(sql, params)
            return dict(cur.fetchone()) if cur.rowcount != 0 and cur.description else None

    def db_fetch_all(sql, params=()):
        sql = sql.replace("?", "%s")
        with get_db().cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            return [dict(r) for r in rows] if rows else []

    def db_execute(sql, params=()):
        sql = sql.replace("?", "%s")
        with get_db().cursor() as cur:
            cur.execute(sql, params)

    def init_db():
        db_execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, salt TEXT NOT NULL,
            iterations INTEGER DEFAULT 10000, role TEXT DEFAULT 'member',
            full_name TEXT, email TEXT, phone TEXT, member_id TEXT,
            is_active INTEGER DEFAULT 1, created_at TEXT, updated_at TEXT
        )""")
        db_execute("""
        CREATE TABLE IF NOT EXISTS members (
            id TEXT PRIMARY KEY, member_no TEXT UNIQUE NOT NULL,
            first_name TEXT, last_name TEXT, full_name_search TEXT,
            phone TEXT, email TEXT, id_number TEXT,
            kyc_status TEXT DEFAULT 'pending',
            is_active INTEGER DEFAULT 1,
            membership_date TEXT, created_at TEXT, updated_at TEXT
        )""")
        db_execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY, member_id TEXT NOT NULL,
            account_no TEXT UNIQUE NOT NULL, account_type TEXT DEFAULT 'savings',
            balance_minor INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1,
            opening_date TEXT, created_at TEXT, updated_at TEXT
        )""")
        db_execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
            transaction_type TEXT NOT NULL, amount_minor INTEGER NOT NULL,
            description TEXT, channel TEXT DEFAULT 'web',
            reference_number TEXT, created_at TEXT
        )""")
        db_execute("""
        CREATE TABLE IF NOT EXISTS loans (
            id TEXT PRIMARY KEY, loan_no TEXT UNIQUE,
            member_id TEXT NOT NULL, principal_amount_minor INTEGER NOT NULL,
            outstanding_principal_minor INTEGER DEFAULT 0,
            term_months INTEGER NOT NULL, interest_rate REAL DEFAULT 1.5,
            loan_purpose TEXT, status TEXT DEFAULT 'pending',
            next_payment_date TEXT, next_payment_amount_minor INTEGER DEFAULT 0,
            disbursement_date TEXT, created_at TEXT, updated_at TEXT
        )""")
        db_execute("""
        CREATE TABLE IF NOT EXISTS investments (
            id TEXT PRIMARY KEY, member_id TEXT NOT NULL,
            name TEXT, investment_type TEXT, principal_minor INTEGER DEFAULT 0,
            interest_earned_minor INTEGER DEFAULT 0, interest_rate REAL DEFAULT 0,
            start_date TEXT, maturity_date TEXT, status TEXT DEFAULT 'active',
            created_at TEXT
        )""")
        log.warning("PostgreSQL tables initialized")

else:
    # Local SQLite fallback
    import sqlite3, threading
    _sqlite_local = threading.local()
    _DB_PATH = os.environ.get("SQLITE_PATH", "kivy_app.db")

    def _conn():
        if not hasattr(_sqlite_local, "conn") or _sqlite_local.conn is None:
            _sqlite_local.conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
            _sqlite_local.conn.row_factory = sqlite3.Row
        return _sqlite_local.conn

    def db_fetch_one(sql, params=()):
        try:
            cur = _conn().execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None
        except Exception as e:
            log.error(f"db_fetch_one: {e} | {sql}")
            return None

    def db_fetch_all(sql, params=()):
        try:
            cur = _conn().execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            log.error(f"db_fetch_all: {e}")
            return []

    def db_execute(sql, params=()):
        try:
            _conn().execute(sql, params)
            _conn().commit()
        except Exception as e:
            log.error(f"db_execute: {e} | {sql}")

    def init_db(): pass  # SQLite schema managed by Kivy app


# ── JWT ───────────────────────────────────────────────────────────────────────
_SECRET = os.environ.get("HELA_JWT_SECRET", "hela_sacco_jwt_v3_change_in_prod")

def _b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sign_jwt(payload: dict, hours: int = 24) -> str:
    p = dict(payload); p["exp"] = int(time.time()) + hours * 3600
    h = _b64u(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    b = _b64u(json.dumps(p, separators=(",",":")).encode())
    s = _b64u(_hmac.new(_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
    return f"{h}.{b}.{s}"

def verify_jwt(token: str) -> Optional[dict]:
    try:
        h, b, s = token.split(".")
        exp = _b64u(_hmac.new(_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
        if not _hmac.compare_digest(s, exp): return None
        p = json.loads(base64.urlsafe_b64decode(b + "=="))
        return None if p.get("exp", 0) < time.time() else p
    except: return None

def _hash(pw: str, salt: str = None, iters: int = 10000):
    if not salt: salt = base64.b64encode(os.urandom(32)).decode()
    h = base64.b64encode(hashlib.pbkdf2_hmac(
        "sha256", pw.encode(), base64.b64decode(salt), iters, 32)).decode()
    return h, salt

def _phone(p: str) -> str:
    p = p.strip().replace(" ","").replace("-","").replace("+","")
    return "254" + p[1:] if p.startswith("0") else p

def _auth_user(request: Request) -> dict:
    a = request.headers.get("Authorization", "")
    u = verify_jwt(a[7:]) if a.startswith("Bearer ") else None
    if not u: raise HTTPException(401, "Not authenticated")
    return u

def _mid(uid: str) -> str:
    r = db_fetch_one("SELECT member_id FROM users WHERE id=?", (uid,))
    return (r or {}).get("member_id") or uid


# ── Portal HTML ───────────────────────────────────────────────────────────────
def _get_html():
    for name in ["hela_portal.html", "index.html"]:
        if os.path.exists(name):
            return open(name, encoding="utf-8").read()
    return "<h2>HELA SACCO</h2><p>hela_portal.html not found</p>"


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="HELA SMART SACCO", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def startup():
    init_db()
    log.warning("HELA SMART SACCO API started")


# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(request: Request):
    b     = await request.json()
    phone = str(b.get("phone","")).strip()
    pw    = str(b.get("password","")).strip()
    if not phone or not pw:
        raise HTTPException(400, "Phone and password are required")
    p = _phone(phone)
    m = (db_fetch_one(
            "SELECT u.id as uid, u.password_hash, u.salt, u.iterations, "
            "u.role, u.full_name, u.member_id, mem.member_no "
            "FROM users u LEFT JOIN members mem ON mem.id=u.member_id "
            "WHERE (u.phone=? OR u.phone=? OR u.username=? OR u.username=?) "
            "AND u.is_active=1", (phone, p, phone, p))
         or db_fetch_one(
            "SELECT id as uid, password_hash, salt, iterations, role, "
            "full_name, member_id, NULL as member_no "
            "FROM users WHERE username=? AND is_active=1", (phone,)))
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
            try: db_execute("UPDATE users SET password_hash=?,iterations=? WHERE id=?",
                            (fast_h, 10000, uid))
            except: pass
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
    first = str(b.get("first_name","")).strip()
    last  = str(b.get("last_name", "")).strip()
    phone = str(b.get("phone",    "")).strip()
    id_no = str(b.get("id_number","")).strip()
    email = str(b.get("email",    "")).strip()
    pw    = str(b.get("password", "")).strip()
    if not first or not last: raise HTTPException(400, "Full name required")
    if not phone:             raise HTTPException(400, "Phone number required")
    if not id_no:             raise HTTPException(400, "National ID required")
    if len(pw) < 6:           raise HTTPException(400, "Password min 6 characters")
    p = _phone(phone)
    if db_fetch_one("SELECT id FROM members WHERE phone=? OR phone=?", (phone, p)):
        raise HTTPException(409, "Phone number already registered")
    if db_fetch_one("SELECT id FROM members WHERE id_number=?", (id_no,)):
        raise HTTPException(409, "National ID already registered")
    now  = datetime.datetime.now().isoformat()
    uid  = str(_uuid.uuid4()); mid = str(_uuid.uuid4())
    full = f"{first} {last}"
    cnt  = (db_fetch_one("SELECT COUNT(*) as c FROM members") or {}).get("c", 0)
    mno  = f"HLS{str(cnt+1).zfill(5)}"
    pw_h, salt = _hash(pw)
    db_execute("INSERT INTO users (id,username,password_hash,salt,iterations,"
               "role,full_name,phone,member_id,is_active,created_at,updated_at) "
               "VALUES (?,?,?,?,?,?,?,?,?,1,?,?)",
               (uid,p,pw_h,salt,10000,"member",full,p,mid,now,now))
    db_execute("INSERT INTO members (id,member_no,first_name,last_name,"
               "full_name_search,phone,email,id_number,is_active,kyc_status,"
               "membership_date,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,1,'pending',?,?,?)",
               (mid,mno,first,last,full.lower(),p,email,id_no,now[:10],now,now))
    db_execute("INSERT INTO accounts (id,member_id,account_no,account_type,"
               "balance_minor,is_active,opening_date,created_at,updated_at) "
               "VALUES (?,?,?,'savings',0,1,?,?,?)",
               (str(_uuid.uuid4()),mid,f"SAV{mno[3:]}",now[:10],now,now))
    return {"token": sign_jwt({"sub":uid,"role":"member"}), "role":"member",
            "name": full, "member_no": mno,
            "message": "Account created! Visit a branch to complete KYC verification."}


# ── Member endpoints ──────────────────────────────────────────────────────────
@app.get("/api/me")
async def get_me(u: dict = Depends(_auth_user)):
    uid = u["sub"]
    m = db_fetch_one(
        "SELECT mem.*, u.username, u.role, u.full_name as u_name "
        "FROM users u LEFT JOIN members mem ON mem.id=u.member_id WHERE u.id=?", (uid,))
    if not m: raise HTTPException(404, "Member not found")
    mid = m.get("id") or _mid(uid)
    acc = db_fetch_one("SELECT * FROM accounts WHERE member_id=? "
                       "AND account_type='savings' ORDER BY opening_date LIMIT 1", (mid,))
    loans = db_fetch_all(
        "SELECT id,principal_amount_minor,outstanding_principal_minor,status,"
        "next_payment_date,next_payment_amount_minor FROM loans "
        "WHERE member_id=? AND status IN ('active','disbursed','overdue') "
        "ORDER BY created_at DESC", (mid,))
    return {
        "id": mid,
        "name": m.get("full_name") or m.get("u_name") or m.get("username",""),
        "member_no": m.get("member_no",""), "phone": m.get("phone",""),
        "email": m.get("email",""), "kyc_status": m.get("kyc_status","pending"),
        "balance": (acc or {}).get("balance_minor", 0) / 100,
        "account_no": (acc or {}).get("account_no",""),
        "account_id": (acc or {}).get("id",""),
        "loans": [{"id":l["id"],
            "principal": l["principal_amount_minor"]/100,
            "outstanding": l["outstanding_principal_minor"]/100,
            "status": l["status"],
            "next_due": str(l.get("next_payment_date","") or ""),
            "installment": l.get("next_payment_amount_minor",0)/100,
        } for l in loans],
    }


@app.get("/api/me/statement")
async def get_statement(request: Request, limit: int=30, offset: int=0,
                        u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    txns = db_fetch_all(
        "SELECT t.* FROM transactions t "
        "JOIN accounts a ON a.id=t.account_id "
        "WHERE a.member_id=? ORDER BY t.created_at DESC LIMIT ? OFFSET ?",
        (mid, min(limit,100), offset))
    return {"transactions": [{
        "id": t["id"], "type": t["transaction_type"],
        "amount": t["amount_minor"]/100, "balance": 0,
        "description": t.get("description",""), "channel": t.get("channel",""),
        "date": str(t.get("created_at","")), "reference": t.get("reference_number",""),
    } for t in txns]}


@app.get("/api/me/loans")
async def get_loans(u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    loans = db_fetch_all(
        "SELECT id,principal_amount_minor,outstanding_principal_minor,status,"
        "next_payment_date,next_payment_amount_minor,term_months,interest_rate,"
        "loan_purpose FROM loans WHERE member_id=? ORDER BY created_at DESC", (mid,))
    return {"loans": [{
        "id": l["id"], "amount": l["principal_amount_minor"]/100,
        "outstanding": l.get("outstanding_principal_minor",0)/100,
        "status": l["status"], "next_due": str(l.get("next_payment_date","") or ""),
        "installment": l.get("next_payment_amount_minor",0)/100,
        "term_months": l.get("term_months",0), "interest_rate": l.get("interest_rate",0),
        "purpose": l.get("loan_purpose",""),
    } for l in loans]}


@app.get("/api/me/investments")
async def get_investments(u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    invs = db_fetch_all(
        "SELECT * FROM investments WHERE member_id=? ORDER BY created_at DESC", (mid,))
    return {"investments": [{
        "id": i["id"], "name": i.get("name",""), "type": i.get("investment_type",""),
        "principal": i.get("principal_minor",0)/100,
        "interest": i.get("interest_earned_minor",0)/100,
        "rate": i.get("interest_rate",0), "start": str(i.get("start_date","")),
        "maturity": str(i.get("maturity_date","")), "status": i.get("status",""),
    } for i in invs]}


@app.post("/api/me/loan_apply")
async def loan_apply(request: Request, u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    b   = await request.json()
    amt  = float(b.get("amount", 0))
    term = int(b.get("term_months", 12))
    purp = str(b.get("purpose","Personal")).strip()
    if amt < 1000:         raise HTTPException(400, "Minimum loan is KSh 1,000")
    if not 1 <= term <= 60: raise HTTPException(400, "Term must be 1–60 months")
    lid = str(_uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    lno = f"LN{now[:10].replace('-','')}{lid[:6].upper()}"
    db_execute("INSERT INTO loans (id,loan_no,member_id,principal_amount_minor,"
               "outstanding_principal_minor,term_months,loan_purpose,status,"
               "interest_rate,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'pending',1.5,?,?)",
               (lid,lno,mid,int(amt*100),int(amt*100),term,purp,now,now))
    return {"status":"submitted","loan_id":lid,
            "message":"Application submitted. We'll contact you within 24 hours."}


@app.post("/api/me/stk_deposit")
async def stk_deposit(request: Request, u: dict = Depends(_auth_user)):
    raise HTTPException(503, "STK Push not available on web deployment. "
                             "Please use the mobile app or visit a branch.")


# ── M-Pesa callbacks (for Kivy app running locally) ──────────────────────────
@app.post("/mpesa/stk_callback")
async def stk_cb(request: Request):
    return {"ResultCode": 0, "ResultDesc": "Accepted"}

@app.post("/mpesa/b2c_callback")
async def b2c_cb(request: Request):
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


SYNC_SECRET = os.environ.get("HELA_SYNC_SECRET", "hela_sync_secret_change_me")

@app.post("/api/sync/push")
async def sync_push(request: Request):
    """Receive data pushed from Kivy phone app and upsert into cloud DB."""
    # Verify sync secret
    if request.headers.get("X-Sync-Secret") != SYNC_SECRET:
        raise HTTPException(403, "Invalid sync secret")

    data  = await request.json()
    stats = {"members":0, "users":0, "accounts":0, "transactions":0, "loans":0}

    # ── Users ────────────────────────────────────────────────────────────────
    for u in data.get("users", []):
        existing = db_fetch_one("SELECT id FROM users WHERE id=?", (u["id"],))
        if existing:
            db_execute(
                "UPDATE users SET username=?,full_name=?,phone=?,role=?,"
                "member_id=?,is_active=?,updated_at=? WHERE id=?",
                (u.get("username",""), u.get("full_name",""), u.get("phone",""),
                 u.get("role","member"), u.get("member_id"),
                 u.get("is_active",1), u.get("updated_at",""), u["id"]))
        else:
            db_execute(
                "INSERT INTO users (id,username,password_hash,salt,iterations,"
                "role,full_name,phone,member_id,is_active,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (u["id"], u.get("username",""), u.get("password_hash",""),
                 u.get("salt",""), u.get("iterations",10000), u.get("role","member"),
                 u.get("full_name",""), u.get("phone",""), u.get("member_id"),
                 u.get("is_active",1), u.get("created_at",""), u.get("updated_at","")))
        stats["users"] += 1

    # ── Members ───────────────────────────────────────────────────────────────
    for m in data.get("members", []):
        existing = db_fetch_one("SELECT id FROM members WHERE id=?", (m["id"],))
        if existing:
            db_execute(
                "UPDATE members SET member_no=?,first_name=?,last_name=?,"
                "full_name_search=?,phone=?,email=?,id_number=?,"
                "kyc_status=?,is_active=?,updated_at=? WHERE id=?",
                (m.get("member_no",""), m.get("first_name",""), m.get("last_name",""),
                 m.get("full_name_search",""), m.get("phone",""), m.get("email",""),
                 m.get("id_number",""), m.get("kyc_status","pending"),
                 m.get("is_active",1), m.get("updated_at",""), m["id"]))
        else:
            db_execute(
                "INSERT INTO members (id,member_no,first_name,last_name,"
                "full_name_search,phone,email,id_number,kyc_status,is_active,"
                "membership_date,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (m["id"], m.get("member_no",""), m.get("first_name",""),
                 m.get("last_name",""), m.get("full_name_search",""),
                 m.get("phone",""), m.get("email",""), m.get("id_number",""),
                 m.get("kyc_status","pending"), m.get("is_active",1),
                 m.get("membership_date",""), m.get("created_at",""), m.get("updated_at","")))
        stats["members"] += 1

    # ── Accounts ──────────────────────────────────────────────────────────────
    for a in data.get("accounts", []):
        existing = db_fetch_one("SELECT id FROM accounts WHERE id=?", (a["id"],))
        if existing:
            db_execute(
                "UPDATE accounts SET balance_minor=?,account_no=?,"
                "is_active=?,updated_at=? WHERE id=?",
                (a.get("balance_minor",0), a.get("account_no",""),
                 a.get("is_active",1), a.get("updated_at",""), a["id"]))
        else:
            db_execute(
                "INSERT INTO accounts (id,member_id,account_no,account_type,"
                "balance_minor,is_active,opening_date,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (a["id"], a.get("member_id",""), a.get("account_no",""),
                 a.get("account_type","savings"), a.get("balance_minor",0),
                 a.get("is_active",1), a.get("opening_date",""),
                 a.get("created_at",""), a.get("updated_at","")))
        stats["accounts"] += 1

    # ── Transactions (insert only — never update) ─────────────────────────────
    for t in data.get("transactions", []):
        if not db_fetch_one("SELECT id FROM transactions WHERE id=?", (t["id"],)):
            db_execute(
                "INSERT INTO transactions (id,account_id,transaction_type,"
                "amount_minor,description,channel,reference_number,created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (t["id"], t.get("account_id",""), t.get("transaction_type",""),
                 t.get("amount_minor",0), t.get("description",""),
                 t.get("channel",""), t.get("reference_number",""),
                 t.get("created_at","")))
            stats["transactions"] += 1

    # ── Loans ─────────────────────────────────────────────────────────────────
    for l in data.get("loans", []):
        existing = db_fetch_one("SELECT id FROM loans WHERE id=?", (l["id"],))
        if existing:
            db_execute(
                "UPDATE loans SET status=?,outstanding_principal_minor=?,"
                "next_payment_date=?,next_payment_amount_minor=?,updated_at=? WHERE id=?",
                (l.get("status","pending"),
                 l.get("outstanding_principal_minor", l.get("principal_amount_minor",0)),
                 l.get("next_payment_date"), l.get("next_payment_amount_minor",0),
                 l.get("updated_at",""), l["id"]))
        else:
            db_execute(
                "INSERT INTO loans (id,loan_no,member_id,principal_amount_minor,"
                "outstanding_principal_minor,term_months,interest_rate,loan_purpose,"
                "status,next_payment_date,next_payment_amount_minor,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (l["id"], l.get("loan_no",""), l.get("member_id",""),
                 l.get("principal_amount_minor",0),
                 l.get("outstanding_principal_minor", l.get("principal_amount_minor",0)),
                 l.get("term_months",12), l.get("interest_rate",1.5),
                 l.get("loan_purpose",""), l.get("status","pending"),
                 l.get("next_payment_date"), l.get("next_payment_amount_minor",0),
                 l.get("created_at",""), l.get("updated_at","")))
        stats["loans"] += 1

    return {"status": "ok", "synced": stats,
            "timestamp": datetime.datetime.now().isoformat()}


@app.get("/api/sync/status")
async def sync_status(request: Request):
    if request.headers.get("X-Sync-Secret") != SYNC_SECRET:
        raise HTTPException(403, "Invalid sync secret")
    return {
        "members":      (db_fetch_one("SELECT COUNT(*) as c FROM members") or {}).get("c",0),
        "users":        (db_fetch_one("SELECT COUNT(*) as c FROM users")   or {}).get("c",0),
        "accounts":     (db_fetch_one("SELECT COUNT(*) as c FROM accounts")or {}).get("c",0),
        "transactions": (db_fetch_one("SELECT COUNT(*) as c FROM transactions")or{}).get("c",0),
        "loans":        (db_fetch_one("SELECT COUNT(*) as c FROM loans")   or {}).get("c",0),
        "timestamp":    datetime.datetime.now().isoformat(),
    }


# ── Serve portal ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root(): return HTMLResponse(_get_html())

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa(full_path: str): return HTMLResponse(_get_html())
            start_date TEXT, maturity_date TEXT, status TEXT DEFAULT 'active',
            created_at TEXT
        )""")
        log.warning("PostgreSQL tables initialized")

else:
    # Local SQLite fallback
    import sqlite3, threading
    _sqlite_local = threading.local()
    _DB_PATH = os.environ.get("SQLITE_PATH", "kivy_app.db")

    def _conn():
        if not hasattr(_sqlite_local, "conn") or _sqlite_local.conn is None:
            _sqlite_local.conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
            _sqlite_local.conn.row_factory = sqlite3.Row
        return _sqlite_local.conn

    def db_fetch_one(sql, params=()):
        try:
            cur = _conn().execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None
        except Exception as e:
            log.error(f"db_fetch_one: {e} | {sql}")
            return None

    def db_fetch_all(sql, params=()):
        try:
            cur = _conn().execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            log.error(f"db_fetch_all: {e}")
            return []

    def db_execute(sql, params=()):
        try:
            _conn().execute(sql, params)
            _conn().commit()
        except Exception as e:
            log.error(f"db_execute: {e} | {sql}")

    def init_db(): pass  # SQLite schema managed by Kivy app


# ── JWT ───────────────────────────────────────────────────────────────────────
_SECRET = os.environ.get("HELA_JWT_SECRET", "hela_sacco_jwt_v3_change_in_prod")

def _b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sign_jwt(payload: dict, hours: int = 24) -> str:
    p = dict(payload); p["exp"] = int(time.time()) + hours * 3600
    h = _b64u(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    b = _b64u(json.dumps(p, separators=(",",":")).encode())
    s = _b64u(_hmac.new(_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
    return f"{h}.{b}.{s}"

def verify_jwt(token: str) -> Optional[dict]:
    try:
        h, b, s = token.split(".")
        exp = _b64u(_hmac.new(_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
        if not _hmac.compare_digest(s, exp): return None
        p = json.loads(base64.urlsafe_b64decode(b + "=="))
        return None if p.get("exp", 0) < time.time() else p
    except: return None

def _hash(pw: str, salt: str = None, iters: int = 10000):
    if not salt: salt = base64.b64encode(os.urandom(32)).decode()
    h = base64.b64encode(hashlib.pbkdf2_hmac(
        "sha256", pw.encode(), base64.b64decode(salt), iters, 32)).decode()
    return h, salt

def _phone(p: str) -> str:
    p = p.strip().replace(" ","").replace("-","").replace("+","")
    return "254" + p[1:] if p.startswith("0") else p

def _auth_user(request: Request) -> dict:
    a = request.headers.get("Authorization", "")
    u = verify_jwt(a[7:]) if a.startswith("Bearer ") else None
    if not u: raise HTTPException(401, "Not authenticated")
    return u

def _mid(uid: str) -> str:
    r = db_fetch_one("SELECT member_id FROM users WHERE id=?", (uid,))
    return (r or {}).get("member_id") or uid


# ── Portal HTML ───────────────────────────────────────────────────────────────
def _get_html():
    for name in ["hela_portal.html", "index.html"]:
        if os.path.exists(name):
            return open(name, encoding="utf-8").read()
    return "<h2>HELA SACCO</h2><p>hela_portal.html not found</p>"


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="HELA SMART SACCO", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def startup():
    init_db()
    log.warning("HELA SMART SACCO API started")


# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(request: Request):
    b     = await request.json()
    phone = str(b.get("phone","")).strip()
    pw    = str(b.get("password","")).strip()
    if not phone or not pw:
        raise HTTPException(400, "Phone and password are required")
    p = _phone(phone)
    m = (db_fetch_one(
            "SELECT u.id as uid, u.password_hash, u.salt, u.iterations, "
            "u.role, u.full_name, u.member_id, mem.member_no "
            "FROM users u LEFT JOIN members mem ON mem.id=u.member_id "
            "WHERE (u.phone=? OR u.phone=? OR u.username=? OR u.username=?) "
            "AND u.is_active=1", (phone, p, phone, p))
         or db_fetch_one(
            "SELECT id as uid, password_hash, salt, iterations, role, "
            "full_name, member_id, NULL as member_no "
            "FROM users WHERE username=? AND is_active=1", (phone,)))
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
            try: db_execute("UPDATE users SET password_hash=?,iterations=? WHERE id=?",
                            (fast_h, 10000, uid))
            except: pass
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
    first = str(b.get("first_name","")).strip()
    last  = str(b.get("last_name", "")).strip()
    phone = str(b.get("phone",    "")).strip()
    id_no = str(b.get("id_number","")).strip()
    email = str(b.get("email",    "")).strip()
    pw    = str(b.get("password", "")).strip()
    if not first or not last: raise HTTPException(400, "Full name required")
    if not phone:             raise HTTPException(400, "Phone number required")
    if not id_no:             raise HTTPException(400, "National ID required")
    if len(pw) < 6:           raise HTTPException(400, "Password min 6 characters")
    p = _phone(phone)
    if db_fetch_one("SELECT id FROM members WHERE phone=? OR phone=?", (phone, p)):
        raise HTTPException(409, "Phone number already registered")
    if db_fetch_one("SELECT id FROM members WHERE id_number=?", (id_no,)):
        raise HTTPException(409, "National ID already registered")
    now  = datetime.datetime.now().isoformat()
    uid  = str(_uuid.uuid4()); mid = str(_uuid.uuid4())
    full = f"{first} {last}"
    cnt  = (db_fetch_one("SELECT COUNT(*) as c FROM members") or {}).get("c", 0)
    mno  = f"HLS{str(cnt+1).zfill(5)}"
    pw_h, salt = _hash(pw)
    db_execute("INSERT INTO users (id,username,password_hash,salt,iterations,"
               "role,full_name,phone,member_id,is_active,created_at,updated_at) "
               "VALUES (?,?,?,?,?,?,?,?,?,1,?,?)",
               (uid,p,pw_h,salt,10000,"member",full,p,mid,now,now))
    db_execute("INSERT INTO members (id,member_no,first_name,last_name,"
               "full_name_search,phone,email,id_number,is_active,kyc_status,"
               "membership_date,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,1,'pending',?,?,?)",
               (mid,mno,first,last,full.lower(),p,email,id_no,now[:10],now,now))
    db_execute("INSERT INTO accounts (id,member_id,account_no,account_type,"
               "balance_minor,is_active,opening_date,created_at,updated_at) "
               "VALUES (?,?,?,'savings',0,1,?,?,?)",
               (str(_uuid.uuid4()),mid,f"SAV{mno[3:]}",now[:10],now,now))
    return {"token": sign_jwt({"sub":uid,"role":"member"}), "role":"member",
            "name": full, "member_no": mno,
            "message": "Account created! Visit a branch to complete KYC verification."}


# ── Member endpoints ──────────────────────────────────────────────────────────
@app.get("/api/me")
async def get_me(u: dict = Depends(_auth_user)):
    uid = u["sub"]
    m = db_fetch_one(
        "SELECT mem.*, u.username, u.role, u.full_name as u_name "
        "FROM users u LEFT JOIN members mem ON mem.id=u.member_id WHERE u.id=?", (uid,))
    if not m: raise HTTPException(404, "Member not found")
    mid = m.get("id") or _mid(uid)
    acc = db_fetch_one("SELECT * FROM accounts WHERE member_id=? "
                       "AND account_type='savings' ORDER BY opening_date LIMIT 1", (mid,))
    loans = db_fetch_all(
        "SELECT id,principal_amount_minor,outstanding_principal_minor,status,"
        "next_payment_date,next_payment_amount_minor FROM loans "
        "WHERE member_id=? AND status IN ('active','disbursed','overdue') "
        "ORDER BY created_at DESC", (mid,))
    return {
        "id": mid,
        "name": m.get("full_name") or m.get("u_name") or m.get("username",""),
        "member_no": m.get("member_no",""), "phone": m.get("phone",""),
        "email": m.get("email",""), "kyc_status": m.get("kyc_status","pending"),
        "balance": (acc or {}).get("balance_minor", 0) / 100,
        "account_no": (acc or {}).get("account_no",""),
        "account_id": (acc or {}).get("id",""),
        "loans": [{"id":l["id"],
            "principal": l["principal_amount_minor"]/100,
            "outstanding": l["outstanding_principal_minor"]/100,
            "status": l["status"],
            "next_due": str(l.get("next_payment_date","") or ""),
            "installment": l.get("next_payment_amount_minor",0)/100,
        } for l in loans],
    }


@app.get("/api/me/statement")
async def get_statement(request: Request, limit: int=30, offset: int=0,
                        u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    txns = db_fetch_all(
        "SELECT t.* FROM transactions t "
        "JOIN accounts a ON a.id=t.account_id "
        "WHERE a.member_id=? ORDER BY t.created_at DESC LIMIT ? OFFSET ?",
        (mid, min(limit,100), offset))
    return {"transactions": [{
        "id": t["id"], "type": t["transaction_type"],
        "amount": t["amount_minor"]/100, "balance": 0,
        "description": t.get("description",""), "channel": t.get("channel",""),
        "date": str(t.get("created_at","")), "reference": t.get("reference_number",""),
    } for t in txns]}


@app.get("/api/me/loans")
async def get_loans(u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    loans = db_fetch_all(
        "SELECT id,principal_amount_minor,outstanding_principal_minor,status,"
        "next_payment_date,next_payment_amount_minor,term_months,interest_rate,"
        "loan_purpose FROM loans WHERE member_id=? ORDER BY created_at DESC", (mid,))
    return {"loans": [{
        "id": l["id"], "amount": l["principal_amount_minor"]/100,
        "outstanding": l.get("outstanding_principal_minor",0)/100,
        "status": l["status"], "next_due": str(l.get("next_payment_date","") or ""),
        "installment": l.get("next_payment_amount_minor",0)/100,
        "term_months": l.get("term_months",0), "interest_rate": l.get("interest_rate",0),
        "purpose": l.get("loan_purpose",""),
    } for l in loans]}


@app.get("/api/me/investments")
async def get_investments(u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    invs = db_fetch_all(
        "SELECT * FROM investments WHERE member_id=? ORDER BY created_at DESC", (mid,))
    return {"investments": [{
        "id": i["id"], "name": i.get("name",""), "type": i.get("investment_type",""),
        "principal": i.get("principal_minor",0)/100,
        "interest": i.get("interest_earned_minor",0)/100,
        "rate": i.get("interest_rate",0), "start": str(i.get("start_date","")),
        "maturity": str(i.get("maturity_date","")), "status": i.get("status",""),
    } for i in invs]}


@app.post("/api/me/loan_apply")
async def loan_apply(request: Request, u: dict = Depends(_auth_user)):
    mid = _mid(u["sub"])
    b   = await request.json()
    amt  = float(b.get("amount", 0))
    term = int(b.get("term_months", 12))
    purp = str(b.get("purpose","Personal")).strip()
    if amt < 1000:         raise HTTPException(400, "Minimum loan is KSh 1,000")
    if not 1 <= term <= 60: raise HTTPException(400, "Term must be 1–60 months")
    lid = str(_uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    lno = f"LN{now[:10].replace('-','')}{lid[:6].upper()}"
    db_execute("INSERT INTO loans (id,loan_no,member_id,principal_amount_minor,"
               "outstanding_principal_minor,term_months,loan_purpose,status,"
               "interest_rate,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'pending',1.5,?,?)",
               (lid,lno,mid,int(amt*100),int(amt*100),term,purp,now,now))
    return {"status":"submitted","loan_id":lid,
            "message":"Application submitted. We'll contact you within 24 hours."}


@app.post("/api/me/stk_deposit")
async def stk_deposit(request: Request, u: dict = Depends(_auth_user)):
    raise HTTPException(503, "STK Push not available on web deployment. "
                             "Please use the mobile app or visit a branch.")


# ── M-Pesa callbacks (for Kivy app running locally) ──────────────────────────
@app.post("/mpesa/stk_callback")
async def stk_cb(request: Request):
    return {"ResultCode": 0, "ResultDesc": "Accepted"}

@app.post("/mpesa/b2c_callback")
async def b2c_cb(request: Request):
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


# ── Serve portal ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root(): return HTMLResponse(_get_html())

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa(full_path: str): return HTMLResponse(_get_html())
