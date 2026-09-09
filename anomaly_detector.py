#!/usr/bin/env python3
# ============================================
# PROJECT 1: STEP 5 - ANOMALY DETECTION ENGINE
# ============================================
# Detects deviations from normal behavior
from sqlalchemy import create_engine, text
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import numpy as np
from datetime import datetime, timedelta
import json
import uuid

from detection_rules import DetectionRules, MITRE_MAPPING
from threat_intel import ThreatIntelEngine


class AnomalyDetector:
    def __init__(self, db_connection_string):
        """Initialize detector"""
        self.engine = create_engine(db_connection_string)
        self.scaler = StandardScaler()

    def detect_volume_anomalies(self, z_threshold=3):
        """Detect unusual traffic volumes using Z-score analysis.

        Z-score = (actual_bytes - avg_bytes) / std_bytes
        A value above z_threshold (default 3, i.e. 3 standard deviations
        above the baseline mean) is flagged as anomalous. This replaces
        the old fixed percent-deviation threshold, which flagged the same
        percentage jump regardless of how volatile that particular
        user/destination pair normally is - producing far more false
        positives on naturally bursty traffic.
        """
        print(f"[*] Detecting volume anomalies (Z-score threshold: {z_threshold})...")

        with self.engine.connect() as conn:
            # Compare current traffic to baseline
            query = """
                SELECT 
                    t.id,
                    t.timestamp,
                    t.user_ip,
                    t.destination_ip,
                    t.destination_port,
                    t.protocol,
                    t.bytes_transferred,
                    b.avg_bytes_per_hour,
                    b.max_bytes_per_hour,
                    b.std_bytes_per_hour
                FROM traffic_events t
                LEFT JOIN baselines b ON 
                    t.user_ip = b.user_ip AND
                    t.destination_ip = b.destination_ip AND
                    t.destination_port = b.destination_port AND
                    t.protocol = b.protocol
                WHERE t.timestamp > NOW() - INTERVAL '1 hour'
                AND t.is_anomaly = FALSE
                ORDER BY t.timestamp DESC
            """

            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=[
                'id', 'timestamp', 'user_ip', 'destination_ip', 
                'destination_port', 'protocol', 'bytes_transferred',
                'avg_bytes', 'max_bytes', 'std_bytes'
            ])

            if df.empty:
                print("    No recent traffic to analyze")
                return

            # Calculate Z-score: how many standard deviations the current
            # transfer is above this pair's normal baseline. Treat a
            # std_bytes of 0/NULL (e.g. a baseline with too little history)
            # as unknown rather than letting it divide-by-zero into inf.
            safe_std = df['std_bytes'].replace(0, np.nan)
            df['z_score'] = (df['bytes_transferred'] - df['avg_bytes']) / safe_std

            # Find anomalies: traffic more than z_threshold std deviations
            # above the baseline mean
            anomalies = df[df['z_score'] > z_threshold]

            print(f"    Found {len(anomalies)} volume anomalies")

            # Store anomalies
            for idx, row in anomalies.iterrows():
                if pd.notna(row['z_score']):
                    self._store_anomaly(
                        user_ip=row['user_ip'],
                        destination_ip=row['destination_ip'],
                        destination_port=row['destination_port'],
                        protocol=row['protocol'],
                        expected_bytes=row['avg_bytes'],
                        actual_bytes=row['bytes_transferred'],
                        deviation_percent=row['z_score'],
                        deviation_type='volume',
                        severity=self._calculate_severity(row['z_score'])
                    )

                    # Mark as analyzed
                    update_query = """
                        UPDATE traffic_events 
                        SET is_anomaly = TRUE, 
                            anomaly_score = :score,
                            reason_for_anomaly = :reason
                        WHERE id = :id
                    """
                    conn.execute(text(update_query), {
                        'id': row['id'],
                        'score': row['z_score'],
                        'reason': f'Volume anomaly: Z-score {row["z_score"]:.2f}'
                    })

            conn.commit()

    def detect_time_anomalies(self):
        """Detect traffic at unusual times"""
        print("[*] Detecting time-based anomalies...")

        with self.engine.connect() as conn:
            # Check for traffic outside normal hours
            query = """
                SELECT 
                    t.id,
                    t.timestamp,
                    t.user_ip,
                    t.destination_ip,
                    t.destination_port,
                    t.protocol,
                    t.bytes_transferred,
                    EXTRACT(HOUR FROM t.timestamp) as hour_of_day,
                    b.typical_hours
                FROM traffic_events t
                LEFT JOIN baselines b ON 
                    t.user_ip = b.user_ip AND
                    t.destination_ip = b.destination_ip AND
                    t.destination_port = b.destination_port AND
                    t.protocol = b.protocol
                WHERE t.timestamp > NOW() - INTERVAL '1 hour'
                AND t.is_anomaly = FALSE
            """

            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=[
                'id', 'timestamp', 'user_ip', 'destination_ip',
                'destination_port', 'protocol', 'bytes_transferred',
                'hour_of_day', 'typical_hours'
            ])

            if df.empty:
                return

            # Find out-of-hours traffic
            anomalies = df[
                (df['hour_of_day'] < 9) |   # Before 9 AM
                (df['hour_of_day'] > 17)    # After 5 PM
            ]

            print(f"    Found {len(anomalies)} time-based anomalies")

            # Store anomalies
            for idx, row in anomalies.iterrows():
                self._store_anomaly(
                    user_ip=row['user_ip'],
                    destination_ip=row['destination_ip'],
                    destination_port=row['destination_port'],
                    protocol=row['protocol'],
                    expected_bytes=0,
                    actual_bytes=row['bytes_transferred'],
                    deviation_percent=100,
                    deviation_type='time',
                    severity='medium'
                )

    def detect_ml_anomalies(self):
        """Use Isolation Forest ML for anomaly detection"""
        print("[*] Running ML-based anomaly detection...")

        with self.engine.connect() as conn:
            query = """
                SELECT 
                    id, user_ip, destination_ip, destination_port, protocol,
                    bytes_transferred, packet_count, 
                    EXTRACT(HOUR FROM timestamp) as hour,
                    EXTRACT(MINUTE FROM timestamp) as minute
                FROM traffic_events
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                AND is_anomaly = FALSE
                LIMIT 10000
            """

            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=[
                'id', 'user_ip', 'destination_ip', 'destination_port', 'protocol',
                'bytes_transferred', 'packet_count', 'hour', 'minute'
            ])

            if df.empty or len(df) < 100:
                print("    Not enough data for ML training")
                return

            # Prepare features
            features = df[['bytes_transferred', 'packet_count', 'hour', 'minute']].copy()
            features['bytes_log'] = np.log1p(features['bytes_transferred'])
            features = features[['bytes_transferred', 'bytes_log', 'packet_count', 'hour']]

            # Scale features
            features_scaled = self.scaler.fit_transform(features)

            # Train Isolation Forest
            clf = IsolationForest(contamination=0.05, random_state=42)  # Expect 5% anomalies
            predictions = clf.fit_predict(features_scaled)

            # Find anomalies (predictions == -1)
            anomaly_indices = np.where(predictions == -1)[0]
            anomalies = df.iloc[anomaly_indices]

            print(f"    ML detected {len(anomalies)} anomalies")

            # Store anomalies
            for idx, row in anomalies.iterrows():
                self._store_anomaly(
                    user_ip=row['user_ip'],
                    destination_ip=row['destination_ip'],
                    destination_port=row['destination_port'],
                    protocol=row['protocol'],
                    expected_bytes=0,
                    actual_bytes=row['bytes_transferred'],
                    deviation_percent=0,
                    deviation_type='ml_detected',
                    severity='high'
                )

    def detect_exfiltration(self, volume_threshold_mb=50):
        """
        Detect large outbound transfers using aggregated flows
        """
        print(f"[*] Detecting exfiltration (>{volume_threshold_mb} MB)...")

        threshold_bytes = volume_threshold_mb * 1024 * 1024

        with self.engine.connect() as conn:
            query = """
                SELECT
                    source_ip,
                    destination_ip,
                    destination_port,
                    protocol,
                    total_packets,
                    total_bytes,
                    duration_seconds
                FROM network_flows
                WHERE total_bytes > :threshold
            """

            result = conn.execute(
                text(query),
                {"threshold": threshold_bytes}
            )
            rows = result.fetchall()

            print(f"    Found {len(rows)} suspicious flows")

            for row in rows:
                self._create_alert(
                    user_ip=str(row.source_ip),
                    alert_type="data_exfiltration",
                    severity="critical",
                    description=(
                        f"Large transfer detected "
                        f"({round(row.total_bytes / 1024 / 1024, 2)} MB)"
                    ),
                    evidence={
                        "destination_ip": str(row.destination_ip),
                        "destination_port": row.destination_port,
                        "protocol": row.protocol,
                        "total_bytes": row.total_bytes,
                        "total_packets": row.total_packets,
                        "duration_seconds": row.duration_seconds
                    }
                )

    def _store_anomaly(
        self,
        user_ip,
        destination_ip,
        destination_port,
        protocol,
        expected_bytes,
        actual_bytes,
        deviation_percent,
        deviation_type,
        severity
    ):
        """Store anomaly and automatically generate alerts"""
        with self.engine.connect() as conn:
            query = """
                INSERT INTO anomalies
                (
                    user_ip,
                    destination_ip,
                    destination_port,
                    protocol,
                    expected_bytes,
                    actual_bytes,
                    deviation_percent,
                    deviation_type,
                    severity
                )
                VALUES
                (
                    :user_ip,
                    :destination_ip,
                    :destination_port,
                    :protocol,
                    :expected_bytes,
                    :actual_bytes,
                    :deviation_percent,
                    :deviation_type,
                    :severity
                )
            """

            conn.execute(
                text(query),
                {
                    "user_ip": user_ip,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "protocol": protocol,
                    "expected_bytes": expected_bytes or 0,
                    "actual_bytes": actual_bytes,
                    "deviation_percent": deviation_percent,
                    "deviation_type": deviation_type,
                    "severity": severity
                }
            )
            conn.commit()

        # Auto-create alerts for serious findings
        if severity in ["high", "critical"]:
            self._create_alert(
                user_ip=user_ip,
                alert_type=deviation_type,
                severity=severity,
                description=(
                    f"{deviation_type} anomaly detected "
                    f"for destination {destination_ip}"
                ),
                evidence={
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "protocol": protocol,
                    "actual_bytes": actual_bytes,
                    "expected_bytes": expected_bytes,
                    "deviation_percent": deviation_percent
                }
            )

    def _calculate_risk_score(self, severity, deviation_percent=0):
        """SOC style risk scoring.

        Base score comes from severity; a small bonus is layered on for
        extreme deviation values when the caller has one to offer.
        """
        score = 0

        severity_scores = {
            "low": 20,
            "medium": 50,
            "high": 75,
            "critical": 100
        }

        score += severity_scores.get(severity.lower(), 0)

        if deviation_percent:
            if deviation_percent > 500:
                score += 50
            elif deviation_percent > 300:
                score += 30
            elif deviation_percent > 100:
                score += 15

        return min(score, 100)

    def _create_alert(self, user_ip, alert_type, severity, description, evidence):
        """Create or update a security alert.

        Deduplicates against any open alert of the same type for the same
        user in the last 30 minutes (bumps its counter instead of
        inserting a new row). A genuinely new alert gets a risk score, a
        correlation ID, and an initial escalation level.
        """
        with self.engine.connect() as conn:
            # Check for an existing open alert to fold this one into
            existing_query = """
                SELECT id, alert_count
                FROM alerts
                WHERE user_ip = :user_ip
                AND alert_type = :alert_type
                AND status = 'open'
                AND timestamp > NOW() - INTERVAL '30 minutes'
                LIMIT 1
            """

            existing = conn.execute(
                text(existing_query),
                {
                    "user_ip": user_ip,
                    "alert_type": alert_type
                }
            ).fetchone()

            if existing:
                update_query = """
                    UPDATE alerts
                    SET
                        alert_count = alert_count + 1,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE id = :id
                """
                conn.execute(
                    text(update_query),
                    {"id": existing.id}
                )
                conn.commit()
                return

            # No recent duplicate - score, tag, and file a new alert.
            # deviation_percent is pulled from evidence when the caller
            # included one (see note below on when this actually fires).
            risk_score = self._calculate_risk_score(
                severity,
                evidence.get('deviation_percent', 0)
            )

            correlation_id = str(uuid.uuid4())

            if risk_score >= 90:
                escalation_level = 3
            elif risk_score >= 70:
                escalation_level = 2
            else:
                escalation_level = 1

            mapping = MITRE_MAPPING.get(alert_type, {})

            query = """
                INSERT INTO alerts
                (
                    user_ip,
                    alert_type,
                    severity,
                    description,
                    evidence,
                    risk_score,
                    correlation_id,
                    escalation_level,
                    mitre_technique_id,
                    mitre_technique_name,
                    mitre_tactic
                )
                VALUES
                (
                    :user_ip,
                    :alert_type,
                    :severity,
                    :description,
                    :evidence,
                    :risk_score,
                    :correlation_id,
                    :escalation_level,
                    :mitre_technique_id,
                    :mitre_technique_name,
                    :mitre_tactic
                )
            """

            conn.execute(text(query), {
                "user_ip": user_ip,
                "alert_type": alert_type,
                "severity": severity,
                "description": description,
                "evidence": json.dumps(evidence),
                "risk_score": risk_score,
                "correlation_id": correlation_id,
                "escalation_level": escalation_level,
                "mitre_technique_id": mapping.get("id"),
                "mitre_technique_name": mapping.get("name"),
                "mitre_tactic": mapping.get("tactic")
            })
            conn.commit()

    def escalate_open_alerts(self):
        """Force-escalate critical alerts that keep firing repeatedly"""
        print("[*] Escalating active alerts...")

        with self.engine.connect() as conn:
            query = """
                UPDATE alerts
                SET escalation_level = 3
                WHERE
                    severity = 'critical'
                    AND status = 'open'
                    AND alert_count > 10
            """
            conn.execute(text(query))
            conn.commit()

        print("[✓] Escalation complete")

    def correlate_alerts(self):
        """Roll up users triggering 3+ distinct alert types within an
        hour into a single possible-insider-threat alert."""
        print("[*] Correlating alerts...")

        with self.engine.connect() as conn:
            query = """
                SELECT
                    user_ip,
                    COUNT(DISTINCT alert_type) as types
                FROM alerts
                WHERE timestamp > NOW() - INTERVAL '1 hour'
                GROUP BY user_ip
                HAVING COUNT(DISTINCT alert_type) >= 3
            """

            rows = conn.execute(text(query)).fetchall()

            for row in rows:
                self._create_alert(
                    user_ip=str(row.user_ip),
                    alert_type="possible_insider_threat",
                    severity="critical",
                    description=(
                        "Multiple anomaly types "
                        "correlated within one hour"
                    ),
                    evidence={
                        "alert_types": row.types
                    }
                )

        print("[✓] Correlation complete")

    def _calculate_severity(self, z_score):
        """Calculate severity based on Z-score (std deviations above baseline).

        Thresholds are recalibrated for Z-scores (which flag at >3 and
        rarely exceed ~15) rather than the old percent-deviation scale
        (75/150/300%), which no longer applies now that volume detection
        uses Z-score instead of raw percent deviation.
        """
        if z_score > 10:
            return 'critical'
        elif z_score > 7:
            return 'high'
        elif z_score > 5:
            return 'medium'
        else:
            return 'low'


if __name__ == '__main__':
    DB_CONNECTION = "postgresql://threat_user:threat_pass_2024@localhost/insider_threat_db"

    detector = AnomalyDetector(DB_CONNECTION)
    rules = DetectionRules(DB_CONNECTION)
    intel = ThreatIntelEngine(DB_CONNECTION)

    print("\n" + "="*50)
    print("ANOMALY DETECTION ENGINE")
    print("="*50 + "\n")

    # Behavioral / ML / exfiltration detection
    detector.detect_volume_anomalies(z_threshold=3)
    detector.detect_time_anomalies()
    detector.detect_ml_anomalies()
    detector.detect_exfiltration(volume_threshold_mb=50)

    # Signature-style detection rules (Upgrade 5)
    rules.detect_port_scanning()
    rules.detect_dns_abuse()
    rules.detect_rare_ports()
    rules.detect_after_hours_activity()
    rules.detect_beaconing()

    # Threat intelligence / IOC matching (Upgrade 7)
    intel.check_ip_reputation()

    # Correlation + escalation run last so they see every alert type
    # generated above, including threat intel matches (Upgrade 4)
    detector.correlate_alerts()
    detector.escalate_open_alerts()

    print("\n[✓] Anomaly detection complete!")
