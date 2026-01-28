from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def root():
    return jsonify({"ok": True, "msg": "SERVER UP"})

@app.route("/health")
def health():
    return jsonify({"ok": True})
