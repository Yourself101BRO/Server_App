import os
import time
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from passlib.hash import bcrypt

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DB_PATH = "maze.db"

ROLE_PLAYER = "player"
ROLE_ADMIN = "admin"
ROLE_SUPERADMIN = "superadmin"

DIFFICULTIES = {"Easy", "Medium", "Hard"}

app = Flask(__name__)
CORS(app)

def now():
    return int(time.time())

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pass_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        banned INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        difficulty TEXT NOT NULL,
        best_ms INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(user_id, difficulty)
    )
    """)

    conn.commit()
    conn.close()

init_db()

# =========================
# KEEP THESE ROUTES
# =========================
@app.route("/")
def root():
    return jsonify({"ok": True, "service": "countdown-maze-server"})

@app.route("/health")
def health():
    return jsonify({"ok": True})

# =========================
# AUTH
# =========================
def make_token(user_row):
    payload = {
        "uid": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "exp": now() + 7 * 24 * 3600
    }
    return jwt.encode(payload, APP_SECRET, algorithm="HS256")

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing token"}), 401
        token = auth.split(" ", 1)[1]

        try:
            data = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        except Exception:
            return jsonify({"ok": False, "error": "Invalid token"}), 401

        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id=?", (data["uid"],))
        user = cur.fetchone()
        conn.close()

        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 401
        if user["banned"]:
            return jsonify({"ok": False, "error": "Banned"}), 403

        request.user = user
        return fn(*args, **kwargs)
    return wrapper

def role_at_least(role, needed):
    order = {ROLE_PLAYER: 0, ROLE_ADMIN: 1, ROLE_SUPERADMIN: 2}
    return order.get(role, 0) >= order.get(needed, 0)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username.isalnum() or not (3 <= len(username) <= 16):
        return jsonify({"ok": False, "error": "Username must be 3-16 letters/numbers"}), 400
    if len(password) < 4:
        return jsonify({"ok": False, "error": "Password too short"}), 400

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM users")
    first = cur.fetchone()["c"] == 0
    role = ROLE_SUPERADMIN if first else ROLE_PLAYER

    try:
        cur.execute(
            "INSERT INTO users(username, pass_hash, role, created_at) VALUES (?,?,?,?)",
            (username, bcrypt.hash(password), role, now())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "Username taken"}), 409

    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()

    return jsonify({
        "ok": True,
        "token": make_token(user),
        "username": user["username"],
        "role": user["role"]
    })

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()

    if not user or not bcrypt.verify(password, user["pass_hash"]):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401
    if user["banned"]:
        return jsonify({"ok": False, "error": "Banned"}), 403

    return jsonify({
        "ok": True,
        "token": make_token(user),
        "username": user["username"],
        "role": user["role"]
    })

# =========================
# LEADERBOARD
# =========================
@app.route("/leaderboard", methods=["GET"])
def leaderboard():
    diff = request.args.get("difficulty", "Easy")
    if diff not in DIFFICULTIES:
        return jsonify({"ok": False, "error": "Bad difficulty"}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.username, s.best_ms
        FROM scores s
        JOIN users u ON u.id = s.user_id
        WHERE s.difficulty=? AND u.banned=0
        ORDER BY s.best_ms ASC
        LIMIT 10
    """, (diff,))
    rows = cur.fetchall()
    conn.close()

    return jsonify({
        "ok": True,
        "entries": [{"username": r["username"], "best_ms": r["best_ms"]} for r in rows]
    })

@app.route("/submit_score", methods=["POST"])
@auth_required
def submit_score():
    data = request.get_json(silent=True) or {}
    diff = data.get("difficulty")
    best_ms = data.get("best_ms")

    if diff not in DIFFICULTIES or not isinstance(best_ms, int) or best_ms <= 0:
        return jsonify({"ok": False, "error": "Bad score data"}), 400

    u = request.user
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT best_ms FROM scores WHERE user_id=? AND difficulty=?", (u["id"], diff))
    row = cur.fetchone()

    if row is None or best_ms < row["best_ms"]:
        cur.execute(
            "INSERT OR REPLACE INTO scores(user_id, difficulty, best_ms, updated_at) VALUES (?,?,?,?)",
            (u["id"], diff, best_ms, now())
        )
        conn.commit()

    conn.close()
    return jsonify({"ok": True})

# =========================
# ADMIN COMMANDS
# =========================
@app.route("/admin/command", methods=["POST"])
@auth_required
def admin_command():
    actor = request.user
    if not role_at_least(actor["role"], ROLE_ADMIN):
        return jsonify({"ok": False, "error": "Not admin"}), 403

    data = request.get_json(silent=True) or {}
    raw = (data.get("cmd") or "").strip()
    parts = raw.split()
    if not parts:
        return jsonify({"ok": False, "error": "Empty command"}), 400

    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else None

    conn = db()
    cur = conn.cursor()

    if cmd == "help":
        conn.close()
        return jsonify({"ok": True, "result": "Commands: help | ban <user> | unban <user> | grant_admin <user> | revoke_admin <user>"})

    if cmd == "ban" and arg:
        cur.execute("UPDATE users SET banned=1 WHERE username=?", (arg,))
        cur.execute("DELETE FROM scores WHERE user_id=(SELECT id FROM users WHERE username=?)", (arg,))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "result": f"Banned {arg} and wiped scores"})

    if cmd == "unban" and arg:
        cur.execute("UPDATE users SET banned=0 WHERE username=?", (arg,))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "result": f"Unbanned {arg}"})

    if cmd in ("grant_admin", "revoke_admin") and arg:
        if actor["role"] != ROLE_SUPERADMIN:
            conn.close()
            return jsonify({"ok": False, "error": "Need superadmin"}), 403
        new_role = ROLE_ADMIN if cmd == "grant_admin" else ROLE_PLAYER
        cur.execute("UPDATE users SET role=? WHERE username=?", (new_role, arg))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "result": f"Set {arg} role to {new_role}"})

    conn.close()
    return jsonify({"ok": False, "error": "Unknown command"}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
