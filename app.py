import os
import time
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from passlib.hash import bcrypt

# =========================
# CONFIG
# =========================
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret")
DB_PATH = "maze.db"

ROLE_PLAYER = "player"
ROLE_ADMIN = "admin"
ROLE_SUPERADMIN = "superadmin"

DIFFICULTIES = {"Easy", "Medium", "Hard"}

# =========================
# APP SETUP
# =========================
app = Flask(__name__)
CORS(app)

# =========================
# BASIC ROUTES (KEEP FOREVER)
# =========================
@app.route("/")
def root():
    return jsonify({"ok": True, "service": "maze-server"})

@app.route("/health")
def health():
    return jsonify({"ok": True})

# =========================
# DATABASE
# =========================
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def now():
    return int(time.time())

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
# AUTH HELPERS
# =========================
def make_token(user):
    payload = {
        "uid": user["id"],
        "username": user["username"],
        "role": user["role"],
        "exp": now() + 7 * 24 * 3600
    }
    return jwt.encode(payload, APP_SECRET, algorithm="HS256")

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing token"}), 401

        try:
            data = jwt.decode(auth.split(" ", 1)[1], APP_SECRET, algorithms=["HS256"])
        except Exception:
            return jsonify({"ok": False, "error": "Invalid token"}), 401

        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id=?", (data["uid"],))
        user = cur.fetchone()
        conn.close()

        if not user or user["banned"]:
            return jsonify({"ok": False, "error": "Access denied"}), 403

        request.user = user
        return fn(*args, **kwargs)
    return wrapper

def is_at_least(role, needed):
    order = {ROLE_PLAYER: 0, ROLE_ADMIN: 1, ROLE_SUPERADMIN: 2}
    return order[role] >= order[needed]

# =========================
# AUTH ROUTES
# =========================
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    u = data.get("username", "").strip()
    p = data.get("password", "")

    if not u.isalnum() or len(u) < 3 or len(p) < 4:
        return jsonify({"ok": False, "error": "Invalid input"}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM users")
    first = cur.fetchone()["c"] == 0
    role = ROLE_SUPERADMIN if first else ROLE_PLAYER

    try:
        cur.execute(
            "INSERT INTO users(username, pass_hash, role, created_at) VALUES (?,?,?,?)",
            (u, bcrypt.hash(p), role, now())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "Username taken"}), 409

    cur.execute("SELECT * FROM users WHERE username=?", (u,))
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
    data = request.get_json() or {}
    u = data.get("username", "")
    p = data.get("password", "")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (u,))
    user = cur.fetchone()
    conn.close()

    if not user or not bcrypt.verify(p, user["pass_hash"]):
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
@app.route("/leaderboard")
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
    data = request.get_json() or {}
    diff = data.get("difficulty")
    ms = data.get("best_ms")

    if diff not in DIFFICULTIES or not isinstance(ms, int):
        return jsonify({"ok": False, "error": "Bad data"}), 400

    u = request.user
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT best_ms FROM scores WHERE user_id=? AND difficulty=?", (u["id"], diff))
    row = cur.fetchone()

    if row is None or ms < row["best_ms"]:
        cur.execute(
            "INSERT OR REPLACE INTO scores(user_id, difficulty, best_ms, updated_at) VALUES (?,?,?,?)",
            (u["id"], diff, ms, now())
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
    if not is_at_least(actor["role"], ROLE_ADMIN):
        return jsonify({"ok": False, "error": "Not admin"}), 403

    cmd = (request.get_json() or {}).get("cmd", "").split()
    if not cmd:
        return jsonify({"ok": False, "error": "Empty command"}), 400

    conn = db()
    cur = conn.cursor()

    if cmd[0] == "ban" and len(cmd) == 2:
        cur.execute("UPDATE users SET banned=1 WHERE username=?", (cmd[1],))
        cur.execute("""
            DELETE FROM scores
            WHERE user_id=(SELECT id FROM users WHERE username=?)
        """, (cmd[1],))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "result": "User banned"})

    if cmd[0] == "grant_admin" and len(cmd) == 2:
        if actor["role"] != ROLE_SUPERADMIN:
            return jsonify({"ok": False, "error": "Need superadmin"}), 403
        cur.execute("UPDATE users SET role=? WHERE username=?", (ROLE_ADMIN, cmd[1]))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "result": "Granted admin"})

    conn.close()
    return jsonify({"ok": False, "error": "Unknown command"}), 400

# =========================
# ENTRYPOINT
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
