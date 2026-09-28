#!/usr/bin/env python3
"""Local web server that puts a GUI in front of the REAL sshdetect.py engine.

No detection logic lives here or in the frontend — this just imports Detector,
Config and parse_line from sshdetect.py, runs them, and returns JSON. The GUI
is a thin client; sshdetect.py stays the single source of truth.

Run:
    pip install flask
    python app.py
    open http://127.0.0.1:5000
"""
from dataclasses import asdict, fields
from datetime import datetime

from flask import Flask, jsonify, request, send_from_directory

from sshdetect import Config, Detector, parse_line

app = Flask(__name__, static_folder="static", static_url_path="")

CFG_FIELDS = {f.name for f in fields(Config)} - {"offhours_ignore_users"}


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/sample")
def sample():
    """Serve the same sample log the CLI tests against, so the GUI and CLI use identical data."""
    with open("sample/auth.log") as f:
        return f.read(), 200, {"Content-Type": "text/plain"}


@app.post("/analyze")
def analyze():
    """Body: {log: str, year: int, cfg: {bf_threshold: 5, ...}, offhours_ignore_users: "backup,cron"}"""
    body = request.get_json(force=True)
    log_text = body.get("log", "")
    year = int(body.get("year") or datetime.now().year)

    raw_cfg = body.get("cfg", {}) or {}
    cfg_kwargs = {k: int(v) for k, v in raw_cfg.items() if k in CFG_FIELDS}
    ignore = body.get("offhours_ignore_users", "") or ""
    cfg = Config(**cfg_kwargs, offhours_ignore_users=frozenset(
        u.strip() for u in ignore.split(",") if u.strip()))

    # This is the exact same code path sshdetect.py's CLI uses.
    events = [e for e in (parse_line(l, year) for l in log_text.splitlines()) if e]
    events.sort(key=lambda e: e.ts)
    det = Detector(cfg)
    alerts = []
    for ev in events:
        alerts += det.process(ev)

    out = [dict(asdict(a), ts=a.ts) for a in alerts]  # ts already a string (isoformat) from Alert
    return jsonify({"event_count": len(events), "alerts": out})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
