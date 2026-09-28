#!/usr/bin/env python3
"""sshdetect - a small rule-based detection engine for SSH / auth logs.

Reads syslog-style auth logs (Debian/Ubuntu /var/log/auth.log, RHEL /var/log/secure),
normalizes each line into an Event, runs it through 5 detection rules, and emits Alerts.

Rules
  1. brute_force            many failed logins from one IP in a short window
  2. success_after_failures a successful login right after a burst of failures (likely compromise)
  3. user_enumeration       one IP trying many different usernames (spraying / enumeration)
  4. off_hours_login        successful login outside business hours
  5. suspicious_command     known-bad patterns in sudo commands (download+exec, shadow, persistence...)

Standard library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

# --------------------------------------------------------------------------- #
# 1. Parsing / normalization
# --------------------------------------------------------------------------- #

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\da-fA-F.:]+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port \d+"
)
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.*)$")


@dataclass
class Event:
    """Normalized event. Every log source is mapped into this shape."""
    ts: datetime
    host: str
    kind: str          # "failed" | "accepted" | "sudo"
    user: str = ""
    ip: str = ""
    cmd: str = ""
    raw: str = ""
    source: str = "linux"


def parse_line(line: str, year: int) -> Optional[Event]:
    """Turn one raw log line into an Event, or None if we don't care about it."""
    line = line.rstrip("\n")
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    try:
        # syslog timestamps have no year, so we supply one
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    base = dict(ts=ts, host=m["host"], raw=line)
    proc, msg = m["proc"], m["msg"]
    if proc == "sshd":
        if (f := FAILED_RE.search(msg)):
            return Event(kind="failed", user=f["user"], ip=f["ip"], **base)
        if (a := ACCEPTED_RE.search(msg)):
            return Event(kind="accepted", user=a["user"], ip=a["ip"], **base)
    elif proc == "sudo":
        if (s := SUDO_RE.match(msg)):
            return Event(kind="sudo", user=s["user"], cmd=s["cmd"].strip(), **base)
    return None


def parse_windows_xml(xml_text: str) -> list[Event]:
    """Normalize Windows Security events 4624, 4625, and 4688."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    def child_text(parent, name):
        for child in parent.iter():
            if child.tag.rsplit("}", 1)[-1] == name:
                return child.text or ""
        return ""

    records = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "Event"]
    events = []
    for record in records:
        event_id = child_text(record, "EventID")
        kind = {"4624": "accepted", "4625": "failed", "4688": "sudo"}.get(event_id)
        if not kind:
            continue

        timestamp = ""
        for node in record.iter():
            if node.tag.rsplit("}", 1)[-1] == "TimeCreated":
                timestamp = node.attrib.get("SystemTime", node.text or "")
                break
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if ts.tzinfo is not None:
                ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            continue

        data = {}
        for node in record.iter():
            if node.tag.rsplit("}", 1)[-1] == "Data":
                data[node.attrib.get("Name", "")] = node.text or ""

        user = data.get("TargetUserName") or data.get("SubjectUserName", "")
        ip = data.get("IpAddress", "")
        command = data.get("CommandLine") or data.get("NewProcessName", "")
        host = child_text(record, "Computer")
        events.append(Event(ts=ts, host=host, kind=kind, user=user, ip=ip,
                            cmd=command, raw=ET.tostring(record, encoding="unicode"), source="windows"))
    return events


# --------------------------------------------------------------------------- #
# 2. Config + Alert
# --------------------------------------------------------------------------- #

@dataclass
class Config:
    bf_threshold: int = 5          # failures ...
    bf_window: int = 60            # ... within this many seconds
    sf_threshold: int = 5          # failures before a success ...
    sf_lookback: int = 300         # ... within this many seconds
    enum_threshold: int = 4        # distinct usernames ...
    enum_window: int = 120         # ... within this many seconds
    hours_start: int = 7           # business hours: [start, end)
    hours_end: int = 20
    offhours_ignore_users: frozenset = field(default_factory=frozenset)
    cooldown: int = 300            # don't repeat the same alert for this many seconds


@dataclass
class Alert:
    ts: str
    rule: str
    severity: str
    entity: str        # what we're alerting on: an IP, or a username for command alerts
    message: str
    host: str
    evidence: str      # the raw log line that triggered it


# Command patterns for rule 5. (name, regex). Tune these to your environment.
SUSPICIOUS_COMMANDS = [(n, re.compile(p, re.I)) for n, p in [
    ("download_and_execute", r"\b(curl|wget)\b[^|;]*\|\s*(ba|z)?sh\b|\b(curl|wget)\b.*\s(-O|>)\s*/(tmp|dev/shm)/"),
    ("credential_file_access", r"/etc/shadow|/etc/sudoers|authorized_keys|id_rsa"),
    ("reverse_shell", r"\bnc(at)?\b.*\s-e\b|/dev/tcp/|\bbash\s+-i\b"),
    ("persistence_new_user", r"\b(useradd|adduser)\b|\busermod\b.*\b(sudo|wheel)\b"),
    ("permission_tampering", r"\bchmod\b\s+(\+s|u\+s|[2467]\d{3})\b"),
    ("log_tampering", r"\b(rm|truncate|shred)\b.*(/var/log|\.bash_history)|\bhistory\s+-c\b"),
]]


# --------------------------------------------------------------------------- #
# 3. Detection engine (stateful, processes events in time order)
# --------------------------------------------------------------------------- #

class Detector:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._fails = defaultdict(deque)      # ip -> deque[timestamp] of failures
        self._users = defaultdict(deque)      # ip -> deque[(timestamp, username)] of failures
        self._last_alert = {}                 # (rule, key) -> timestamp, for cooldown
        self._compromised_sessions = {}       # (host, user) -> (timestamp, source IP)

    def _emit(self, rule, severity, ev, entity, message, key=None):
        k = (rule, key or entity)
        last = self._last_alert.get(k)
        if last is not None and (ev.ts - last).total_seconds() < self.cfg.cooldown:
            return []
        self._last_alert[k] = ev.ts
        return [Alert(ev.ts.isoformat(sep=" "), rule, severity, entity, message, ev.host, ev.raw)]

    def process(self, ev: Event) -> list:
        c, out = self.cfg, []

        if ev.kind == "failed":
            # keep only as much history as the widest rule needs
            dq = self._fails[ev.ip]
            dq.append(ev.ts)
            while (ev.ts - dq[0]).total_seconds() > max(c.bf_window, c.sf_lookback):
                dq.popleft()

            # Rule 1: brute force
            n = sum(1 for t in dq if (ev.ts - t).total_seconds() <= c.bf_window)
            if n >= c.bf_threshold:
                out += self._emit("brute_force", "high", ev, ev.ip,
                                  f"{n} failed logins from {ev.ip} in {c.bf_window}s (latest user: {ev.user})")

            # Rule 3: user enumeration / password spraying
            ud = self._users[ev.ip]
            ud.append((ev.ts, ev.user))
            while (ev.ts - ud[0][0]).total_seconds() > c.enum_window:
                ud.popleft()
            distinct = {u for _, u in ud}
            if len(distinct) >= c.enum_threshold:
                out += self._emit("user_enumeration", "medium", ev, ev.ip,
                                  f"{ev.ip} tried {len(distinct)} different usernames in {c.enum_window}s: "
                                  f"{', '.join(sorted(distinct))}")

        elif ev.kind == "accepted":
            # Rule 2: success right after a burst of failures from the same IP
            n = sum(1 for t in self._fails.get(ev.ip, ()) if 0 <= (ev.ts - t).total_seconds() <= c.sf_lookback)
            if n >= c.sf_threshold:
                out += self._emit("success_after_failures", "critical", ev, ev.ip,
                                  f"login for '{ev.user}' from {ev.ip} succeeded after {n} failures in {c.sf_lookback}s")
                self._compromised_sessions[(ev.host, ev.user)] = (ev.ts, ev.ip)

            # Rule 4: off-hours login
            if (ev.ts.hour < c.hours_start or ev.ts.hour >= c.hours_end) and ev.user not in c.offhours_ignore_users:
                out += self._emit("off_hours_login", "medium", ev, ev.ip,
                                  f"login for '{ev.user}' from {ev.ip} at {ev.ts:%H:%M} (outside {c.hours_start:02d}:00-{c.hours_end:02d}:00)",
                                  key=f"{ev.ip}|{ev.user}")

        elif ev.kind == "sudo":
            # Rule 5: suspicious command patterns
            for name, rx in SUSPICIOUS_COMMANDS:
                if rx.search(ev.cmd):
                    out += self._emit("suspicious_command", "high", ev, ev.user,
                                      f"user '{ev.user}' ran a command matching '{name}': {ev.cmd}",
                                      key=f"{ev.user}|{name}")
                    session = self._compromised_sessions.get((ev.host, ev.user))
                    if session and 0 <= (ev.ts - session[0]).total_seconds() <= 900:
                        out += self._emit(
                            "attack_chain", "critical", ev, session[1],
                            f"'{ev.user}' logged in after repeated failures and ran a suspicious command within 900s",
                            key=f"{session[1]}|{ev.user}")
                    self._compromised_sessions.pop((ev.host, ev.user), None)
        return out


def run(lines: Iterable[str], cfg: Config, year: int) -> Iterator[Alert]:
    events = [e for e in (parse_line(l, year) for l in lines) if e]
    events.sort(key=lambda e: e.ts)          # rules assume time order
    det = Detector(cfg)
    for ev in events:
        yield from det.process(ev)


# --------------------------------------------------------------------------- #
# 4. Output + CLI
# --------------------------------------------------------------------------- #

def send_webhook(url: str, alert: Alert) -> None:
    req = urllib.request.Request(url, data=json.dumps(asdict(alert)).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:  # alerting must never crash detection
        print(f"webhook failed: {e}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Detect suspicious activity in SSH/auth logs.")
    p.add_argument("logfile", help="path to auth.log, or - for stdin")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year of the log (syslog has none)")
    p.add_argument("--out", help="write alerts as JSON Lines to this file")
    p.add_argument("--webhook", help="POST each alert as JSON to this URL")
    p.add_argument("--quiet", action="store_true", help="no console output")
    d = Config()
    for name in ("bf_threshold", "bf_window", "sf_threshold", "sf_lookback", "enum_threshold",
                 "enum_window", "hours_start", "hours_end", "cooldown"):
        p.add_argument("--" + name.replace("_", "-"), type=int, default=getattr(d, name))
    p.add_argument("--offhours-ignore-users", default="",
                   help="comma-separated service accounts allowed to log in at any hour")
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    cfg = Config(**{k: getattr(a, k) for k in ("bf_threshold", "bf_window", "sf_threshold", "sf_lookback",
                                              "enum_threshold", "enum_window", "hours_start", "hours_end", "cooldown")},
                 offhours_ignore_users=frozenset(u for u in a.offhours_ignore_users.split(",") if u))
    src = sys.stdin if a.logfile == "-" else open(a.logfile, errors="replace")
    out = open(a.out, "w") if a.out else None
    count = 0
    with src:
        for alert in run(src, cfg, a.year):
            count += 1
            if not a.quiet:
                print(f"[{alert.severity.upper():8}] {alert.ts}  {alert.rule:22} {alert.entity:16} {alert.message}")
            if out:
                out.write(json.dumps(asdict(alert)) + "\n")
            if a.webhook:
                send_webhook(a.webhook, alert)
    if out:
        out.close()
    print(f"{count} alert(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
