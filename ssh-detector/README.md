# sshdetect: a small SSH/auth-log detection engine

Blue Team final project. Reads a Linux `auth.log`, normalizes it, runs 5 detection rules, and prints/writes alerts.
Pure Python 3.9+, **no dependencies**, so it runs anywhere and you can explain every line in your presentation.

## Why SSH/auth logs?
Auth logs are the best place to learn detection: the attack patterns (brute force, spraying, valid-account abuse) are
simple to describe, they're everywhere in real life (any internet-facing SSH box gets probed within minutes), and every
rule maps cleanly to a MITRE ATT&CK technique.

## Layout
```
ssh-detector/
  sshdetect.py          # parser + 5 rules + CLI  (the tool)
  gen_sample_log.py     # builds sample/auth.log + sample/labels.json (fixed seed)
  evaluate.py           # precision / recall / F1 against labels
  tests/test_sshdetect.py   # 17 unit tests (stdlib unittest)
  sample/               # auth.log, labels.json, alerts.jsonl, alerts_no_allowlist.jsonl
  Dockerfile
```

## Quick start
```bash
python gen_sample_log.py                                   # make the sample data
python sshdetect.py sample/auth.log --year 2026 \
       --offhours-ignore-users backup --out sample/alerts.jsonl
python evaluate.py sample/alerts.jsonl sample/labels.json  # metrics
python -m unittest discover -s tests -t .                  # tests

# on a real box
sudo python sshdetect.py /var/log/auth.log --quiet --out alerts.jsonl --webhook https://hooks.example/alert
tail -n 5000 /var/log/auth.log | python sshdetect.py -     # stdin works too
```
All thresholds are CLI flags (`--bf-threshold`, `--bf-window`, `--hours-start`, ...). Run `--help`.

## Data model
Every line becomes an `Event(ts, host, kind, user, ip, cmd, raw)` where `kind` is `failed`, `accepted` or `sudo`.
Rules only ever see Events, so adding another log source (nginx, Windows) means writing a new parser, not new rules.

Alerts are JSON Lines: `ts, rule, severity, entity, message, host, evidence` (the raw log line that fired it).

## The rules

| # | Rule | Fires when | Attack it's based on | ATT&CK | Sev |
|---|------|-----------|----------------------|--------|-----|
| 1 | `brute_force` | ≥5 failed logins from one IP within 60 s | Automated password guessing (Hydra, Medusa) | T1110.001 | high |
| 2 | `success_after_failures` | successful login from an IP that had ≥5 failures in the previous 300 s | The guess worked. This is the moment failure noise becomes an actual compromise | T1110 → T1078 | critical |
| 3 | `user_enumeration` | one IP tries ≥4 distinct usernames within 120 s | Password spraying / username enumeration (admin, oracle, postgres...) | T1110.003 | medium |
| 4 | `off_hours_login` | successful login outside 07:00–20:00 (service accounts allowlisted) | Attackers use stolen creds when nobody's watching | T1078 | medium |
| 5 | `suspicious_command` | sudo command matches a bad pattern: download-and-execute, `/etc/shadow`, reverse shell, new user, `chmod +s`, log deletion | Post-exploitation: tooling, credential theft, persistence, cleanup | T1105, T1003.008, T1136.001, T1070.002 | high |

Rule 2 is the most valuable one. Rule 1 alone tells you "someone knocked"; rule 2 tells you "someone got in".
Alerts are de-duplicated with a 300 s cooldown per (rule, entity) so a 10,000-attempt attack gives 1 alert, not 10,000.

## Test data and results
`sample/auth.log` (85 lines) has normal traffic, **near misses that must not alert**, and 3 attack scenarios:

| Scenario | What's in the log |
|----------|-------------------|
| Normal | alice/bob logins in business hours, alice mistypes twice, bob forgets his password (4 failures, then success), 5 one-off internet probes, benign `sudo apt update` etc. |
| A | 30 failed root logins from 198.51.100.23 in 40 s |
| B | slow spray from 203.0.113.77: 1 attempt every 20 s, 6 different usernames |
| C | 192.0.2.99: 12 failures on `alice` → success at 03:41 → `cat /etc/shadow`, `curl … \| sh`, `useradd`, `rm /var/log/auth.log` |

`labels.json` lists the 6 (rule, entity) alerts a correct tool should raise. Result of the refinement loop:

| Run | TP | FP | FN | Precision | Recall | F1 |
|-----|----|----|----|-----------|--------|----|
| v1, no allowlist | 6 | 1 | 0 | 0.86 | 1.00 | 0.92 |
| v2, `--offhours-ignore-users backup` | 6 | 0 | 0 | 1.00 | 1.00 | 1.00 |

**False positive found in v1:** the nightly `backup` service account logs in at 02:00 and tripped `off_hours_login`.
Fix: per-account allowlist. **Threshold tuning:** bob's 4 failures + success is deliberately just under the
threshold of 5. Lower it to 4 and you get a false positive; that's the precision/recall trade-off in one example.
Note that 100% on a dataset I generated myself proves the rules work as designed, **not** that they'd catch everything
in the wild. Run it on a real `auth.log` (any public-facing VPS has one) and look at what it flags.

## Limitations: how an attacker evades this
- **Slow-and-low:** one attempt every 45 s or slower stays under rules 1 *and* 3. I tested 8 usernames at 45 s spacing from one IP: zero alerts.
- **Distributed attacks:** every rule is keyed on source IP. A botnet giving each IP 4 tries gets zero alerts (tested: 10 IPs × 4 attempts). Fix: also aggregate per *target username*.
- **Valid credentials / phished creds:** no failures means rule 2 never fires. Only rule 4 (and 5) can catch it, and rule 4 is defeated by logging in during business hours or from a familiar country.
- **Command rule is regex on sudo only:** obfuscation (`base64 -d | sh`, `c""url`, renaming binaries, `$IFS` tricks), commands run *without* sudo or as root directly, and anything inside an interactive shell are invisible.
- **Log tampering:** an attacker with root can edit/delete the log, so ship logs off-host in real time.
- **Off-hours is crude:** fixed hours, no timezone/per-user baseline, and a patient attacker just matches the victim's schedule.
- **Parser assumptions:** OpenSSH message formats and syslog timestamps (no year); other distros/versions differ. Lines that don't match are silently skipped, which is itself a blind spot.
- **No state across runs:** each run starts empty, so an attack straddling two runs is missed.

**Improvements with more time:** per-username and per-subnet aggregation; per-user baselines (usual hours, usual source
countries via GeoIP); "impossible travel"; a `pam`/`auditd` source for real command visibility; persistent state;
an Isolation Forest on per-IP features (failures/min, distinct users, inter-arrival variance) as a *second opinion* next to the rules.

## Deployment / alerting
- **CLI / cron:** `*/5 * * * * python sshdetect.py /var/log/auth.log --quiet --out /var/log/sshdetect.jsonl`
- **Docker:** see `Dockerfile` (mount logs read-only).
- **Alerts:** console, JSONL file (ship it to ELK with Filebeat, which is a nice tie-in to what you used in the program), or `--webhook` (Slack/Teams/any HTTP endpoint).
- Prototype reads the whole file into memory and sorts it. For huge logs, switch to streaming (the `Detector` class is already stream-friendly).
