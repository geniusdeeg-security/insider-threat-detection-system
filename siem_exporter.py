#!/usr/bin/env python3
# ============================================
# UPGRADE 10 - SIEM EXPORTER
# ============================================
# Exports alerts in SIEM-friendly formats: JSON, JSON Lines, and CEF.
#
# NOTE: the class shell below (__init__, get_alerts, normalize_alert)
# was reconstructed from context - the pasted spec started mid-file,
# inside export_json(), with no class definition, constructor, or
# helper methods before it. Reconstructed to match:
#   - the shape __main__ needs (SIEMExporter(engine))
#   - the fields export_cef() reads directly off each alert dict
#     (alert["alert_type"], alert["description"], alert["user_ip"],
#     alert["severity"], alert["id"]) - i.e. get_alerts() must return
#     raw alerts-table rows as dicts, not pre-normalized events
#   - the event shape shown in Step 10.5's example output, which
#     matches the same normalized-event fields used later in
#     dashboard.py's /api/siem/alerts endpoint (Step 10.8)

from sqlalchemy import create_engine, text
import json
import os


class SIEMExporter:
    def __init__(self, engine, output_directory="siem_output"):
        self.engine = engine
        self.output_directory = output_directory
        os.makedirs(self.output_directory, exist_ok=True)

    def get_alerts(self):
        """Fetch all alerts as plain dicts, most recent first.

        Returns raw alerts-table rows (not normalized events) - both
        export_cef() and normalize_alert() expect to read straight off
        these dicts (alert["alert_type"], alert["evidence"], etc.).
        """
        with self.engine.connect() as conn:
            result = conn.execute(text("""
                SELECT
                    id,
                    timestamp,
                    user_ip,
                    alert_type,
                    severity,
                    description,
                    evidence,
                    status
                FROM alerts
                ORDER BY timestamp DESC
            """))

            return [dict(row._mapping) for row in result]

    def normalize_alert(self, alert):
        """Convert a raw alerts-table row into a standard SIEM event.

        Field shape matches Step 10.5's example output exactly, and the
        same shape dashboard.py's /api/siem/alerts endpoint builds
        independently for the live API - this is the "at rest" (file
        export) version of the same normalization.
        """
        evidence = alert.get("evidence")

        if evidence is None:
            evidence = {}

        timestamp = alert.get("timestamp")

        return {
            "event_id": f"ITD-ALERT-{alert['id']}",
            "event_type": "security_alert",
            "event_time": timestamp.isoformat() if timestamp else None,
            "source": "insider-threat-detection",
            "category": "network_security",
            "severity": alert.get("severity"),
            "status": alert.get("status"),
            "user_ip": str(alert.get("user_ip")),
            "alert_type": alert.get("alert_type"),
            "description": alert.get("description"),
            "evidence": evidence
        }

    def export_json(self):
        """Export all alerts as a single JSON array file"""
        alerts = self.get_alerts()

        events = [
            self.normalize_alert(alert)
            for alert in alerts
        ]

        output_file = os.path.join(
            self.output_directory,
            "security_events.json"
        )

        with open(output_file, "w") as f:
            json.dump(
                events,
                f,
                indent=2,
                default=str
            )

        print(
            f"[✓] JSON export created: "
            f"{output_file}"
        )

        print(
            f"[✓] Exported events: "
            f"{len(events)}"
        )

        return output_file

    def export_jsonl(self):
        """Export all alerts as JSON Lines - one JSON object per line"""
        alerts = self.get_alerts()

        output_file = os.path.join(
            self.output_directory,
            "security_events.jsonl"
        )

        with open(
            output_file,
            "w"
        ) as f:

            for alert in alerts:

                event = self.normalize_alert(
                    alert
                )

                f.write(
                    json.dumps(
                        event,
                        default=str
                    )
                    + "\n"
                )

        print(
            f"[✓] JSONL export created: "
            f"{output_file}"
        )

        print(
            f"[✓] Exported events: "
            f"{len(alerts)}"
        )

        return output_file

    def escape_cef(self, value):

        if value is None:
            return ""

        value = str(value)

        return (
            value
            .replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("=", "\\=")
            .replace("\n", "\\n")
        )

    def severity_to_cef(self, severity):

        mapping = {
            "low": 3,
            "medium": 6,
            "high": 8,
            "critical": 10
        }

        return mapping.get(
            str(severity).lower(),
            5
        )

    def export_cef(self):
        """Export all alerts in ArcSight Common Event Format (CEF)"""
        alerts = self.get_alerts()

        output_file = os.path.join(
            self.output_directory,
            "security_events.cef"
        )

        with open(
            output_file,
            "w"
        ) as f:

            for alert in alerts:

                name = self.escape_cef(
                    alert["alert_type"]
                )

                description = self.escape_cef(
                    alert["description"]
                )

                user_ip = self.escape_cef(
                    alert["user_ip"]
                )

                cef_line = (
                    "CEF:0|"
                    "InsiderThreatDetection|"
                    "ITD|"
                    "1.0|"
                    f"{name}|"
                    f"{description}|"
                    f"{self.severity_to_cef(alert['severity'])}|"
                    f"src={user_ip} "
                    f"eventId=ITD-ALERT-{alert['id']} "
                    f"cs1Label=AlertType "
                    f"cs1={name}"
                )

                f.write(
                    cef_line + "\n"
                )

        print(
            f"[✓] CEF export created: "
            f"{output_file}"
        )

        print(
            f"[✓] Exported events: "
            f"{len(alerts)}"
        )

        return output_file


if __name__ == "__main__":

    DB_CONNECTION = (
        "postgresql://threat_user:"
        "threat_pass_2024@localhost/"
        "insider_threat_db"
    )

    engine = create_engine(DB_CONNECTION)

    print("=" * 60)
    print("SIEM EXPORTER")
    print("=" * 60)

    exporter = SIEMExporter(engine)

    exporter.export_json()

    exporter.export_jsonl()

    exporter.export_cef()

    print()
    print("[✓] SIEM export complete")
