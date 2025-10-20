from flask import Flask, jsonify
import json, os, time

LOG = "data/alerts.jsonl"
app = Flask(__name__)

@app.get("/status")
def status():
    if not os.path.exists(LOG):
        return jsonify({"ok": True, "latest": None})
    *_, last = open(LOG, "r", encoding="utf-8").read().splitlines() or [None]
    latest = json.loads(last) if last else None
    return jsonify({"ok": True, "latest": latest})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
