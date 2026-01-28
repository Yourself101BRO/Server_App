from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def root():
    return jsonify({"ok": True, "msg": "ROOT WORKS"})

@app.route("/health")
def health():
    return jsonify({"ok": True})
