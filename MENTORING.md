# Mentoring plan: from the project brief to a working detection tool

About 25-30 hours total, spread over 2 weeks. Each milestone maps to a line in the brief. Do the **exercise** yourself
before reading the answer in the code; that's where the learning is.

| # | Milestone | Brief item | Time |
|---|-----------|-----------|------|
| M0 | Setup & read a real log | Choose a log type | 1.5 h |
| M1 | Parser + normalization | Write a script that reads a log | 3 h |
| M2 | Rule 1 & 2 (brute force, success after failures) | Design ≥4 rules | 4 h |
| M3 | Rules 3-5 | Design ≥4 rules | 5 h |
| M4 | Test data + evaluation | Test on a realistic log | 4 h |
| M5 | Refine (false positives / misses) | Refine rules | 3 h |
| M6 | Write-up + limitations | Deliverables | 3 h |
| M7 | Presentation + live demo | 20-25 min talk | 4 h |
| Stretch | ML second opinion | | 4 h |

## M0: Setup (1.5 h)
- [ ] Create the repo, copy in `sshdetect.py`, run it on `sample/auth.log`
- [ ] Look at a **real** auth log (`sudo less /var/log/auth.log`, or spin up a cheap VPS/VM and wait an hour; you'll get attacked)
- [ ] Write down 5 line formats you see (failed, accepted, invalid user, session opened, sudo)

**Exercise:** `grep "Failed password" auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head`. Who's the top attacker?
**Review criteria:** you can explain each field in one raw line.

## M1: Parser (3 h)
- [ ] Regex for the syslog prefix (timestamp, host, process)
- [ ] Regexes for failed / accepted / sudo messages
- [ ] Map to an `Event` dataclass; ignore everything else
- [ ] Unit tests: valid line, invalid-user line, garbage line

**Exercises:** (1) handle `Failed publickey`. (2) Add `Invalid user X from IP` lines. (3) Make the parser survive a line with an IPv6 address.
**Review criteria:** parser never crashes on junk; each regex has a test; you can explain why the year has to be supplied.

## M2: Rules 1 and 2 (4 h)
- [ ] Sliding window per IP using a `deque` (drop old timestamps as you go)
- [ ] Brute force: count in window ≥ threshold → alert
- [ ] Success-after-failures: on `accepted`, look back at that IP's failures
- [ ] Cooldown so one attack = one alert

**Exercises:** (1) Write the test that shows rule 1 does *not* fire at 4 failures. (2) Why does rule 2 need a *longer* window than rule 1? (3) What happens without the cooldown? Try it.
**Review criteria:** tests on both sides of the threshold; you can draw the sliding window on paper.

## M3: Rules 3, 4, 5 (5 h)
- [ ] Enumeration: distinct usernames per IP in a window
- [ ] Off-hours: hour check + service-account allowlist
- [ ] Commands: list of (name, regex); test each with a bad *and* a benign command

**Exercises:** (1) Add a 6th rule: successful **direct root login** (`Accepted … for root`). (2) Add weekend awareness to rule 4. (3) Add a command pattern of your own, e.g. `python -c 'import pty'` (TTY upgrade).
**Review criteria:** every rule has an "attack pattern → why it matters" sentence you can say out loud without notes.

## M4: Test data + evaluation (4 h)
- [ ] Generate a log: normal traffic **and** near-misses **and** attacks (`gen_sample_log.py`)
- [ ] Write ground truth labels *before* running the tool (otherwise you'll unconsciously fit the labels to the output)
- [ ] `evaluate.py`: precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = harmonic mean
- [ ] Also run on a real log and manually review every alert

**Exercise:** Add a scenario the tool *should* miss (e.g. 8 usernames at 45 s spacing) and record it as a known false negative.
**Review criteria:** labels written first; you can say what precision and recall mean in *security* terms (precision = analyst time wasted, recall = attacks missed).

## M5: Refine (3 h)
- [ ] Run v1, list every FP and FN, fix each with a *reason* (not just "changed the number")
- [ ] Keep a changelog: v1 → v2 metrics table (see README)

**Exercise:** find a threshold value that's the worst trade-off and explain it.
**Review criteria:** each change is justified by a specific log line.

## M6: Write-up (3 h)
- [ ] Per rule: what it catches, the real attack, why it matters, its ATT&CK ID
- [ ] Limitations: for each rule, *what would I do as the attacker?* Test at least two evasions in code
- [ ] Sample log + generated alerts included

**Review criteria:** limitations are tested, not just guessed.

## M7: Presentation (4 h), 20-25 min
| Slot | Content |
|------|---------|
| 0-3 min | Why detection engineering; why SSH logs |
| 3-8 | Architecture: log → Event → rules → alert |
| 8-15 | Each rule: attack, log line, code snippet |
| 15-20 | **Live demo:** run on `sample/auth.log`, show scenario C alerts in order (brute force → success → commands) |
| 20-25 | Evasions (show the slow spray demo), improvements, Q&A |

Rehearse the demo twice and keep a screenshot of the output as a fallback. Prepare answers for: *"why not just use fail2ban?"*
(fail2ban blocks; this *detects and tells a story*, and detection logic is what a SIEM is made of), *"how would this scale?"*, *"why regex and not ML?"*

## Stretch: ML second opinion (4 h)
`pip install pandas scikit-learn`. Build one row per (IP, 5-minute bucket): failures, distinct users, success count,
mean gap between attempts. Fit `IsolationForest(contamination=0.05)`. Compare its top-scored IPs to your rule alerts.
**Discussion point:** it may flag the slow spray your rules miss, but it can't tell you *why*, which is why production
systems layer both. Only add this once M0-M6 are solid; rules you can explain beat a model you can't.

## How I'll review your work
Send me code + tests + the metrics table at each milestone and I'll check: correctness, edge cases, whether every
threshold has a reason, and whether your explanation matches what the code actually does.
