import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import app as app_module


class TestApp(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_database = app_module.DB_PATH
        app_module.DB_PATH = Path(self.temp_dir.name) / "test.sqlite3"
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.DB_PATH = self.previous_database
        self.temp_dir.cleanup()

    def test_sample_uses_workspace_path(self):
        response = self.client.get("/sample")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Failed password", response.get_data(as_text=True))

    def test_mixed_source_ingestion_persists_events_and_correlated_alert(self):
        start = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0)
        linux_lines = [
            f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} host01 sshd[1]: Failed password for alice from 1.2.3.4 port 22 ssh2"
            for dt in (start + timedelta(seconds=offset) for offset in range(5))
        ]
        accepted = start + timedelta(seconds=10)
        linux_lines.append(
            f"{accepted:%b} {accepted.day:2d} {accepted:%H:%M:%S} host01 sshd[1]: Accepted password for alice from 1.2.3.4 port 22 ssh2"
        )
        command_time = start + timedelta(seconds=20)
        linux_lines.append(
            f"{command_time:%b} {command_time.day:2d} {command_time:%H:%M:%S} host01 sudo:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        )
        windows_xml = """<Events><Event><System><EventID>4625</EventID>
          <TimeCreated SystemTime="2026-09-14T10:00:00Z" /><Computer>win01</Computer></System>
          <EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">5.6.7.8</Data></EventData>
          </Event></Events>"""

        response = self.client.post("/analyze", json={"sources": [
            {"name": "auth.log", "content": "\n".join(linux_lines)},
            {"name": "security.xml", "content": windows_xml},
        ]})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["event_count"], 8)
        self.assertIn("attack_chain", {alert["rule"] for alert in payload["alerts"]})
        self.assertEqual(len(self.client.get("/events?q=alice").get_json()), 7)
        self.assertEqual(self.client.get("/events?q=bob").get_json()[0]["source"], "windows")

        alert = next(alert for alert in payload["alerts"] if alert["rule"] == "attack_chain")
        update = self.client.post(f"/alerts/{alert['id']}", json={
            "status": "investigating", "notes": "correlated review",
        })
        self.assertEqual(update.status_code, 200)
        self.assertEqual(self.client.get("/alerts?status=investigating").get_json()[0]["notes"],
                         "correlated review")
        self.assertGreaterEqual(self.client.get("/report").get_json()["events"], 8)

    def test_delete_alert_type_and_all_stored_history(self):
        start = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0)
        lines = [
            f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} host01 sshd[1]: Failed password for alice from 1.2.3.4 port 22 ssh2"
            for dt in (start + timedelta(seconds=offset) for offset in range(5))
        ]

        first = self.client.post("/analyze", json={"log": "\n".join(lines)}).get_json()
        first_alert_id = first["alerts"][0]["id"]
        self.assertEqual(self.client.delete(f"/alerts/{first_alert_id}").status_code, 200)
        self.assertEqual(len(self.client.get("/events").get_json()), 5)
        self.assertEqual(self.client.delete(f"/alerts/{first_alert_id}").status_code, 404)

        second = self.client.post("/analyze", json={"log": "\n".join(lines)}).get_json()
        self.assertEqual(self.client.delete("/alerts/type/brute_force").get_json()["deleted_count"], 1)
        self.assertEqual(len(self.client.get("/events").get_json()), 10)
        self.assertGreaterEqual(len(second["alerts"]), 1)

        self.client.post("/analyze", json={"log": "\n".join(lines)})
        self.assertEqual(self.client.delete("/storage").get_json(), {"events": 15, "alerts": 1})
        self.assertEqual(self.client.get("/events").get_json(), [])
        self.assertEqual(self.client.get("/alerts").get_json(), [])


if __name__ == "__main__":
    unittest.main()
