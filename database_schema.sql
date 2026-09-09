-- ============================================
-- PROJECT 1: STEP 2 - DATABASE SCHEMA
-- ============================================
-- Run: psql -U threat_user -d insider_threat_db -f database_schema.sql

-- Table 1: Network traffic baseline (normal behavior)
CREATE TABLE IF NOT EXISTS baselines (
    id SERIAL PRIMARY KEY,
    user_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    destination_port INTEGER,
    protocol VARCHAR(10),
    avg_bytes_per_hour BIGINT,
    max_bytes_per_hour BIGINT,
    typical_hours TEXT, -- JSON: "9-17" means work hours
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    std_bytes_per_hour FLOAT,
    normal_ports TEXT,
    unique_destinations INTEGER DEFAULT 0,
    UNIQUE(user_ip, destination_ip, destination_port, protocol)
);

-- Migration safeguard (Step 3.1): if `baselines` already exists from
-- before this upgrade, CREATE TABLE IF NOT EXISTS above is a no-op and
-- won't add the new columns. These are idempotent and safe to re-run.
ALTER TABLE baselines ADD COLUMN IF NOT EXISTS std_bytes_per_hour FLOAT;
ALTER TABLE baselines ADD COLUMN IF NOT EXISTS normal_ports TEXT;
ALTER TABLE baselines ADD COLUMN IF NOT EXISTS unique_destinations INTEGER DEFAULT 0;

-- Table 2: Real-time network traffic
CREATE TABLE IF NOT EXISTS traffic_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    destination_port INTEGER,
    protocol VARCHAR(10),
    bytes_transferred BIGINT,
    packet_count INTEGER,
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_score FLOAT,
    reason_for_anomaly TEXT
);

-- Table 3: Detected anomalies (deviations from baseline)
CREATE TABLE IF NOT EXISTS anomalies (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    destination_port INTEGER,
    protocol VARCHAR(10),
    expected_bytes BIGINT,
    actual_bytes BIGINT,
    deviation_percent FLOAT,
    deviation_type VARCHAR(50), -- "volume", "time", "destination"
    severity VARCHAR(20), -- "low", "medium", "high", "critical"
    status VARCHAR(20) DEFAULT 'new', -- "new", "investigating", "resolved", "false_positive"
    notes TEXT
);

-- Table 4: Security alerts (high-priority anomalies)
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_ip INET NOT NULL,
    alert_type VARCHAR(50), -- "insider_threat", "data_exfiltration", "unusual_access"
    severity VARCHAR(20), -- "low", "medium", "high", "critical"
    description TEXT,
    evidence JSONB, -- Store anomaly details as JSON
    assigned_to VARCHAR(100),
    status VARCHAR(20) DEFAULT 'open', -- "open", "investigating", "closed"
    resolved_at TIMESTAMP,
    risk_score INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    correlation_id UUID,
    escalation_level INTEGER DEFAULT 1,
    mitre_technique_id VARCHAR(20),
    mitre_technique_name VARCHAR(200),
    mitre_tactic VARCHAR(100)
);

-- Migration safeguard (Step 4.1 + Step 6.3): if `alerts` already exists
-- from before these upgrades, CREATE TABLE IF NOT EXISTS above is a
-- no-op and won't add the new columns. These are idempotent and safe to
-- re-run.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS alert_count INTEGER DEFAULT 1;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlation_id UUID;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS escalation_level INTEGER DEFAULT 1;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(20);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique_name VARCHAR(200);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(100);

-- Table 5: User profiles (for context)
CREATE TABLE IF NOT EXISTS user_profiles (
    id SERIAL PRIMARY KEY,
    user_ip INET NOT NULL UNIQUE,
    user_name VARCHAR(100),
    department VARCHAR(50),
    role VARCHAR(50),
    access_level INTEGER, -- 1=low, 2=medium, 3=high, 4=admin
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table 6: ML model baseline scores (for anomaly detection)
CREATE TABLE IF NOT EXISTS ml_baselines (
    id SERIAL PRIMARY KEY,
    user_ip INET NOT NULL UNIQUE,
    normal_score FLOAT, -- Expected score for normal behavior
    std_deviation FLOAT, -- Standard deviation (variance)
    data_points INTEGER, -- Number of data points trained on
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table 7: Detection rules registry (Upgrade 5)
-- Reference/config table for the signature-style rules in
-- detection_rules.py. NOTE: `enabled` is not currently read by any
-- detect_*() method - see the summary for what that means today.
CREATE TABLE IF NOT EXISTS detection_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) UNIQUE,
    rule_id VARCHAR(50) UNIQUE,
    severity VARCHAR(20),
    enabled BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO detection_rules
(rule_name, rule_id, severity, description)
VALUES
(
    'Port Scan Detection',
    'RULE-001',
    'high',
    'Detects many ports targeted by same source'
),
(
    'Beaconing Detection',
    'RULE-002',
    'medium',
    'Detects regular interval communication'
),
(
    'DNS Abuse',
    'RULE-003',
    'high',
    'Detects excessive DNS traffic'
),
(
    'Rare Port Access',
    'RULE-004',
    'medium',
    'Detects unusual destination ports'
)
ON CONFLICT DO NOTHING;

-- Table 8: MITRE ATT&CK technique registry (Upgrade 6)
CREATE TABLE IF NOT EXISTS mitre_attack (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(20) UNIQUE,
    technique_name VARCHAR(200),
    tactic VARCHAR(100),
    description TEXT
);

INSERT INTO mitre_attack
(technique_id, technique_name, tactic, description)
VALUES
(
    'T1046',
    'Network Service Discovery',
    'Discovery',
    'Scanning for open ports and services'
),
(
    'T1071',
    'Application Layer Protocol',
    'Command and Control',
    'Using common protocols for communication'
),
(
    'T1041',
    'Exfiltration Over C2 Channel',
    'Exfiltration',
    'Stealing data over an established channel'
),
(
    'T1021',
    'Remote Services',
    'Lateral Movement',
    'Using remote services to move laterally'
),
(
    'T1078',
    'Valid Accounts',
    'Defense Evasion',
    'Abusing legitimate credentials'
),
(
    'T1087',
    'Account Discovery',
    'Discovery',
    'Enumerating accounts on a system or network'
)
ON CONFLICT DO NOTHING;

-- Table 9: Threat intelligence feed (Upgrade 7)
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id SERIAL PRIMARY KEY,
    indicator VARCHAR(255) UNIQUE,
    indicator_type VARCHAR(50),
    threat_type VARCHAR(100),
    confidence INTEGER,
    source VARCHAR(100),
    description TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO threat_intelligence
(indicator, indicator_type, threat_type, confidence, source, description)
VALUES
(
    '185.220.101.20',
    'ip',
    'TOR Exit Node',
    95,
    'Internal Feed',
    'Known TOR relay'
),
(
    '45.95.147.236',
    'ip',
    'Command and Control',
    100,
    'Internal Feed',
    'Known malware C2'
),
(
    '103.21.244.1',
    'ip',
    'Suspicious Infrastructure',
    80,
    'Internal Feed',
    'Suspicious network activity'
)
ON CONFLICT DO NOTHING;

-- Table 10: IOC matches against live traffic (Upgrade 7)
CREATE TABLE IF NOT EXISTS threat_matches (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_ip INET,
    matched_indicator VARCHAR(255),
    threat_type VARCHAR(100),
    confidence INTEGER,
    source VARCHAR(100),
    alert_id INTEGER
);

-- Create indexes for fast queries
CREATE INDEX idx_traffic_events_timestamp ON traffic_events(timestamp DESC);
CREATE INDEX idx_traffic_events_user_ip ON traffic_events(user_ip);
CREATE INDEX idx_anomalies_user_ip ON anomalies(user_ip);
CREATE INDEX idx_anomalies_timestamp ON anomalies(timestamp DESC);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_threat_matches_user_ip ON threat_matches(user_ip);
CREATE INDEX idx_threat_matches_timestamp ON threat_matches(timestamp DESC);

-- Create view for active alerts (summary)
CREATE OR REPLACE VIEW active_alerts_summary AS
SELECT 
    a.id,
    a.timestamp,
    a.user_ip,
    a.alert_type,
    a.severity,
    a.description,
    COUNT(anom.id) as related_anomalies
FROM alerts a
LEFT JOIN anomalies anom ON a.user_ip = anom.user_ip 
    AND anom.timestamp > (a.timestamp - INTERVAL '1 hour')
WHERE a.status = 'open'
GROUP BY a.id, a.timestamp, a.user_ip, a.alert_type, a.severity, a.description
ORDER BY a.timestamp DESC;

-- Create view for anomaly trends
CREATE OR REPLACE VIEW anomaly_trends AS
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    user_ip,
    COUNT(*) as anomaly_count,
    AVG(deviation_percent) as avg_deviation
FROM anomalies
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY DATE_TRUNC('hour', timestamp), user_ip
ORDER BY hour DESC;

-- Create view for MITRE ATT&CK coverage (Upgrade 6)
CREATE OR REPLACE VIEW mitre_coverage AS
SELECT
    mitre_tactic,
    mitre_technique_id,
    mitre_technique_name,
    COUNT(*) AS total_alerts
FROM alerts
GROUP BY mitre_tactic, mitre_technique_id, mitre_technique_name;

-- Create view for threat intel match summary (Upgrade 7)
CREATE OR REPLACE VIEW threat_summary AS
SELECT
    threat_type,
    COUNT(*) AS total_matches,
    AVG(confidence) AS avg_confidence
FROM threat_matches
GROUP BY threat_type;

COMMIT;
