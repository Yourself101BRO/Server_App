import os
import time
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from passlib.hash import bcrypt

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
DB_PATH = os.environ.get("DB_PATH", "maze.db")

ALLOWED_DIFFICULTIES = {"Easy", "Medium", "Hard"}

ROLE_PLAYER = "player"
ROLE_ADMIN = "admin"
ROLE_SUPERADMIN = "superadmin"

app = Flask(__name__)
CORS(app)


def now() -> int:
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
        banned INTEGER NOT NULL DEFAULT 0,
        timeout_until INTEGER NOT NULL DEFAULT 0,
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
        UNIQUE(user_id, difficulty),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()


init_db()


def make_token(user_row):
    payload = {
        "uid": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "iat": now(),
        "exp": now() + 7 * 24 * 3600,  # 7 days
    }
    return jwt.encode(payload, APP_SECRET, algorithm="HS256")


def decode_token(token: str):
    return jwt.decode(token, APP_SECRET, algorithms=["HS256"])


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing token"}), 401
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = decode_token(token)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid/expired token"}), 401

        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (payload["uid"],))
        user = cur.fetchone()
        conn.close()

        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 401

        request.user = user
        return fn(*args, **kwargs)
    return wrapper


def role_at_least(user_role: str, needed: str) -> bool:
    order = {ROLE_PLAYER: 0, ROLE_ADMIN: 1, ROLE_SUPERADMIN: 2}
    return order.get(user_role, -1) >= order.get(needed, 999)


def require_role(min_role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = getattr(request, "user", None)
            if not u:
                return jsonify({"ok": False, "error": "Auth required"}), 401
            if not role_at_least(u["role"], min_role):
                return jsonify({"ok": False, "error": "Insufficient role"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return deco


def clean_username(u: str) -> str:
    return (u or "").strip()


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = clean_username(data.get("username", ""))
    password = data.get("password", "")

    if not (3 <= len(username) <= 16) or not username.isalnum():
        return jsonify({"ok": False, "error": "Username must be 3-16 alphanumeric chars"}), 400
    if not (4 <= len(password) <= 64):
        return jsonify({"ok": False, "error": "Password must be 4-64 chars"}), 400

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM users")
    count = cur.fetchone()["c"]
    role = ROLE_SUPERADMIN if count == 0 else ROLE_PLAYER

    try:
        cur.execute(
            "INSERT INTO users(username, pass_hash, role, banned, timeout_until, created_at) VALUES(?,?,?,?,?,?)",
            (username, bcrypt.hash(password), role, 0, 0, now())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "Username already taken"}), 409

    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()

    token = make_token(user)
    return jsonify({"ok": True, "token": token, "username": user["username"], "role": user["role"]})


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = clean_username(data.get("username", ""))
    password = data.get("password", "")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()

    if not user or not bcrypt.verify(password, user["pass_hash"]):
        return jsonify({"ok": False, "error": "Invalid username or password"}), 401

    if user["banned"] == 1:
        return jsonify({"ok": False, "error": "Banned"}), 403

    if user["timeout_until"] > now():
        remain = user["timeout_until"] - now()
        return jsonify({"ok": False, "error": f"Timed out ({remain}s)"}), 403

    token = make_token(user)
    return jsonify({"ok": True, "token": token, "username": user["username"], "role": user["role"]})


@app.get("/leaderboard")
def leaderboard():
    difficulty = request.args.get("difficulty", "Easy")
    if difficulty not in ALLOWED_DIFFICULTIES:
        return jsonify({"ok": False, "error": "Bad difficulty"}), 400

    try:
        limit = int(request.args.get("limit", "10"))
        limit = max(1, min(50, limit))
    except ValueError:
        limit = 10

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.username, s.best_ms
        FROM scores s
        JOIN users u ON u.id = s.user_id
        WHERE s.difficulty = ?
          AND u.banned = 0
        ORDER BY s.best_ms ASC
        LIMIT ?
    """, (difficulty, limit))
    rows = cur.fetchall()
    conn.close()

    return jsonify({
        "ok": True,
        "difficulty": difficulty,
        "entries": [{"username": r["username"], "best_ms": r["best_ms"]} for r in rows]
    })


@app.post("/submit_score")
@auth_required
def submit_score():
    u = request.user
    if u["banned"] == 1:
        return jsonify({"ok": False, "error": "Banned"}), 403
    if u["timeout_until"] > now():
        return jsonify({"ok": False, "error": "Timed out"}), 403

    data = request.get_json(silent=True) or {}
    difficulty = data.get("difficulty", "")
    best_ms = data.get("best_ms", None)

    if difficulty not in ALLOWED_DIFFICULTIES:
        return jsonify({"ok": False, "error": "Bad difficulty"}), 400
    if not isinstance(best_ms, int):
        return jsonify({"ok": False, "error": "best_ms must be int"}), 400

    if best_ms < 500 or best_ms > 30 * 60 * 1000:
        return jsonify({"ok": False, "error": "Score out of range"}), 400

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT best_ms FROM scores WHERE user_id=? AND difficulty=?", (u["id"], difficulty))
    row = cur.fetchone()

    if row is None:
        cur.execute(
            "INSERT INTO scores(user_id, difficulty, best_ms, updated_at) VALUES(?,?,?,?)",
            (u["id"], difficulty, best_ms, now())
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "updated": True, "best_ms": best_ms})

    old = row["best_ms"]
    if best_ms < old:
        cur.execute(
            "UPDATE scores SET best_ms=?, updated_at=? WHERE user_id=? AND difficulty=?",
            (best_ms, now(), u["id"], difficulty)
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "updated": True, "best_ms": best_ms})

    conn.close()
    return jsonify({"ok": True, "updated": False, "best_ms": old})


# ---- admin helpers ----
def get_user_by_name(username: str):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


def update_user(username: str, **fields):
    if not fields:
        return
    keys = list(fields.keys())
    vals = list(fields.values())
    sets = ", ".join([f"{k}=?" for k in keys])
    conn = db()
    cur = conn.cursor()
    cur.execute(f"UPDATE users SET {sets} WHERE username=?", (*vals, username))
    conn.commit()
    conn.close()


def delete_scores(username: str):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if row:
        cur.execute("DELETE FROM scores WHERE user_id=?", (row["id"],))
    conn.commit()
    conn.close()


@app.post("/admin/command")
@auth_required
@require_role(ROLE_ADMIN)
def admin_command():
    actor = request.user
    data = request.get_json(silent=True) or {}
    cmdline = (data.get("cmd") or "").strip()
    if not cmdline:
        return jsonify({"ok": False, "error": "Empty command"}), 400

    parts = cmdline.split()
    cmd = parts[0].lower()
    args = parts[1:]

    def ok(msg):
        return jsonify({"ok": True, "result": msg})

    def bad(msg, code=400):
        return jsonify({"ok": False, "error": msg}), code

    if cmd in {"help", "?"}:
        return ok(
            "Commands: help | timeout <user> <seconds> | ban <user> | unban <user> | "
            "grant_admin <user> | revoke_admin <user> | clear_stats <user>"
        )

    if cmd == "timeout":
        if len(args) != 2:
            return bad("Usage: timeout <user> <seconds>")
        target, seconds = args
        try:
            seconds = int(seconds)
        except ValueError:
            return bad("seconds must be int")
        seconds = max(1, min(7 * 24 * 3600, seconds))

        tu = get_user_by_name(target)
        if not tu:
            return bad("User not found", 404)

        if role_at_least(tu["role"], ROLE_ADMIN) and actor["role"] != ROLE_SUPERADMIN:
            return bad("Only superadmin can timeout admins/superadmins", 403)

        update_user(target, timeout_until=now() + seconds)
        return ok(f"Timed out {target} for {seconds}s")

    if cmd == "ban":
        if len(args) != 1:
            return bad("Usage: ban <user>")
        target = args[0]

        tu = get_user_by_name(target)
        if not tu:
            return bad("User not found", 404)

        if role_at_least(tu["role"], ROLE_ADMIN) and actor["role"] != ROLE_SUPERADMIN:
            return bad("Only superadmin can ban admins/superadmins", 403)

        update_user(target, banned=1, timeout_until=0)
        delete_scores(target)
        return ok(f"Banned {target} and removed stats")

    if cmd == "unban":
        if len(args) != 1:
            return bad("Usage: unban <user>")
        target = args[0]

        tu = get_user_by_name(target)
        if not tu:
            return bad("User not found", 404)

        if role_at_least(tu["role"], ROLE_ADMIN) and actor["role"] != ROLE_SUPERADMIN:
            return bad("Only superadmin can unban admins/superadmins", 403)

        update_user(target, banned=0)
        return ok(f"Unbanned {target}")

    if cmd == "clear_stats":
        if len(args) != 1:
            return bad("Usage: clear_stats <user>")
        target = args[0]

        tu = get_user_by_name(target)
        if not tu:
            return bad("User not found", 404)

        if role_at_least(tu["role"], ROLE_ADMIN) and actor["role"] != ROLE_SUPERADMIN:
            return bad("Only superadmin can clear admins/superadmins stats", 403)

        delete_scores(target)
        return ok(f"Cleared stats for {target}")

    if cmd == "grant_admin":
        if len(args) != 1:
            return bad("Usage: grant_admin <user>")
        if actor["role"] != ROLE_SUPERADMIN:
            return bad("Only superadmin can grant admin", 403)

        target = args[0]
        tu = get_user_by_name(target)
        if not tu:
            return bad("User not found", 404)
        if tu["role"] == ROLE_SUPERADMIN:
            return bad("Cannot change superadmin")

        update_user(target, role=ROLE_ADMIN)
        return ok(f"Granted admin to {target}")

    if cmd == "revoke_admin":
        if len(args) != 1:
            return bad("Usage: revoke_admin <user>")
        if actor["role"] != ROLE_SUPERADMIN:
            return bad("Only superadmin can revoke admin", 403)

        target = args[0]
        tu = get_user_by_name(target)
        if not tu:
            return bad("User not found", 404)
        if tu["role"] != ROLE_ADMIN:
            return bad("Target is not admin")

        update_user(target, role=ROLE_PLAYER)
        return ok(f"Revoked admin from {target}")

    return bad("Unknown command. Type: help")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
