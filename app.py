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
from dataclasses import fields
from datetime import datetime
import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from sshdetect import Config, Detector, parse_line, parse_windows_xml
from storage import (
    audit_report, clear_storage, delete_alert, delete_alert_type, list_alerts,
    save_run, search_events, update_case,
)

app = Flask(__name__, static_folder="static", static_url_path="")
ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SSHDETECT_DB", ROOT / "sshdetect.sqlite3"))

CFG_FIELDS = {f.name for f in fields(Config)} - {"offhours_ignore_users"}


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/sample")
def sample():
    """Serve the same sample log the CLI tests against, so the GUI and CLI use identical data."""
    with (ROOT / "sample" / "auth.log").open(encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/plain"}


@app.post("/analyze")
def analyze():
    """Ingest Linux text or Windows Security XML sources and persist the resulting run."""
    body = request.get_json(force=True)
    year = int(body.get("year") or datetime.now().year)

    raw_cfg = body.get("cfg", {}) or {}
    cfg_kwargs = {k: int(v) for k, v in raw_cfg.items() if k in CFG_FIELDS}
    ignore = body.get("offhours_ignore_users", "") or ""
    cfg = Config(**cfg_kwargs, offhours_ignore_users=frozenset(
        u.strip() for u in ignore.split(",") if u.strip()))

    sources = body.get("sources") or [{"name": "auth.log", "content": body.get("log", "")}]
    events = []
    names = []
    for source in sources:
        name = str(source.get("name") or "auth.log")
        content = str(source.get("content") or "")
        names.append(name)
        if name.lower().endswith(".xml") or content.lstrip().startswith("<Event"):
            events.extend(parse_windows_xml(content))
        else:
            events.extend(e for e in (parse_line(line, year) for line in content.splitlines()) if e)
    events.sort(key=lambda e: e.ts)
    det = Detector(cfg)
    alerts = []
    for ev in events:
        alerts += det.process(ev)

    source_name = ", ".join(names)[:250] or "manual input"
    out = save_run(DB_PATH, source_name, events, alerts)
    return jsonify({"event_count": len(events), "alerts": out})


@app.get("/events")
def events():
    return jsonify(search_events(DB_PATH, request.args.get("q", "")[:200]))


@app.get("/alerts")
def alerts():
    return jsonify(list_alerts(DB_PATH, request.args.get("q", "")[:200],
                               request.args.get("status", "")))


@app.post("/alerts/<int:alert_id>")
def update_alert(alert_id):
    body = request.get_json(force=True)
    try:
        updated = update_case(DB_PATH, alert_id, body.get("status", "open"), body.get("notes", ""))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    if not updated:
        return jsonify({"error": "alert not found"}), 404
    return jsonify({"id": alert_id, "status": body.get("status", "open")})


@app.delete("/alerts/<int:alert_id>")
def remove_alert(alert_id):
    if not delete_alert(DB_PATH, alert_id):
        return jsonify({"error": "alert not found"}), 404
    return jsonify({"id": alert_id, "deleted": True})


@app.delete("/alerts/type/<rule>")
def remove_alert_type(rule):
    return jsonify({"rule": rule, "deleted_count": delete_alert_type(DB_PATH, rule)})


@app.delete("/storage")
def remove_storage():
    return jsonify(clear_storage(DB_PATH))


@app.get("/report")
def report():
    days = max(1, min(int(request.args.get("days", 30)), 3650))
    return jsonify(audit_report(DB_PATH, days))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
