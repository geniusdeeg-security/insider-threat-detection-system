```markdown

# Insider Threat Detection System

**Enterprise-grade behavioral analytics for detecting insider threats using UEBA & Isolation Forest ML**

## Why I Built This Project

Organizations generate thousands of user activity events daily. Detecting malicious insider activity within that volume of data is difficult using traditional rule-based approaches.

This project demonstrates how User and Entity Behavior Analytics (UEBA) and machine learning can be used to establish behavioral baselines, identify anomalous activity, and generate investigation-ready alerts for security teams.

## 🎯 What This System Detects

✅ **Unusual Login Patterns** - Time, location, frequency anomalies  
✅ **Suspicious Data Access** - Volume spikes, unusual destinations  
✅ **Behavioral Anomalies** - Statistical outliers via ML  
✅ **Real-time Risk Scoring** - User risk assessment  

## Project Highlights

- UEBA-based insider threat detection
- Isolation Forest machine learning
- Behavioral baseline analysis
- Risk-based alerting
- PostgreSQL-backed event storage
- Flask investigation dashboard

## Project Outcome

This project demonstrates how behavioral analytics, machine learning, and event correlation can be used to identify insider threat activity and generate investigation-ready alerts for security teams.

## Security Skills Demonstrated

- User and Entity Behavior Analytics (UEBA)
- Insider Threat Detection
- Machine Learning for Security Analytics
- Detection Engineering
- PostgreSQL Database Design
- Event Correlation
- Security Alerting
- MITRE ATT&CK Mapping
- Security Dashboard Development

## 🏗️ Technical Architecture

```
User Activity Collection
        ↓
Event Parsing & Normalization
        ↓
PostgreSQL Database Storage
        ↓
Baseline Learning Window
        ↓
Anomaly Detection (Isolation Forest ML)
        ↓
Risk Scoring & Alerting
        ↓
Investigation Dashboard
```

Data Pipeline

Packet Capture
→ Traffic Parsing
→ Flow Aggregation
→ Behavioral Baseline Generation
→ Isolation Forest Analysis
→ Alert Generation
→ Dashboard Visualization

## 📊 Detection Methods

### Method 1: Baseline Learning
Learns normal user behavior over a defined observation period
- Tracks: login hours, file access patterns, network destinations
- Detects deviations from baseline

### Method 2: Isolation Forest ML
- Statistical anomaly detection algorithm
- Identifies outliers automatically
- No manual threshold tuning needed

### Method 3: Time-Based Anomalies
- Flags logins at unusual hours
- Detects after-hours data access
- Monitors weekend activity

### Method 4: Volume Anomalies
- Detects file access spikes
- Monitors data transfer volume
- Tracks email sending patterns

## 📋 Sample Detection Alert

```
[CRITICAL] Unusual Data Access Pattern

User: john.smith
Time: 2024-01-15 03:45:00 (normal hours: 09:00-17:00)
Files Accessed: 250 documents
Destination: External USB drive (first time)


Anomalies Detected:
✓ Accessing at 3:45 AM (time anomaly)
✓ Accessing 250 files in 30 minutes (volume anomaly)
✓ Using external USB (location anomaly)
✓ Machine-learning anomaly detected

Recommended Action:
1. ISOLATE user account immediately
2. Preserve all logs and evidence
3. Notify manager and HR
4. Check if data was exfiltrated
```

## 🔧 Technology Stack

- **Python 3.8+** - Detection logic
- **PostgreSQL** - Event storage
- **Pandas** - Data analysis
- **Scikit-learn** - Isolation Forest ML
- **Flask** - Web dashboard
- **SQLAlchemy** - Database ORM

## 📦 Requirements

```
pandas
sqlalchemy
psycopg2-binary
flask
pyyaml
python-dateutil
```

## 🚀 Quick Start

```bash
git clone https://github.com/geniusdeeg-security/insider-threat-detection-system
cd insider-threat-detection-system
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Project Structure

```text
insider-threat-detection-system/
│
├── Data Collection
│   ├── data_collector.py
│   └── traffic_parser.py
│
├── Detection Engine
│   ├── anomaly_detector.py
│   ├── detection_rules.py
│   └── flow_aggregator.py
│
├── Investigation & Response
│   ├── case_manager.py
│   ├── threat_intel.py
│   └── dashboard.py
│
├── Database
│   └── database_schema.sql
│
├── Automation
│   └── run_complete_pipeline.sh
│
├── Supporting Files
│   ├── requirements.txt
│   └── README.md
```


## Database Schema

```sql
-- User baseline profiles (7-day learning window)
CREATE TABLE baseline_profiles (
    user_id VARCHAR(255),
    normal_login_hours TEXT,
    normal_file_access_pattern TEXT,
    normal_data_volume_range TEXT,
    normal_destinations TEXT
);

-- Raw user activity events
CREATE TABLE security_events (
    event_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    user_name VARCHAR(255),
    event_type VARCHAR(100),
    event_data TEXT
);

-- Detected anomalies
CREATE TABLE anomalies (
    anomaly_id SERIAL PRIMARY KEY,
    user_name VARCHAR(255),
    anomaly_type VARCHAR(100),
    confidence_score FLOAT,
    evidence TEXT
);

-- Investigation-ready alerts
CREATE TABLE alerts (
    alert_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    user_name VARCHAR(255),
    severity VARCHAR(20),
    description TEXT,
    recommended_action TEXT
);
```

## Repository Scope

This repository contains the core detection framework used for learning, research, and portfolio demonstration purposes.

Sensitive deployment-specific configurations, integrations, tuning parameters, and operational workflows are intentionally excluded.

### Public Components
✅ Baseline learning algorithm  
✅ Anomaly detection framework (Isolation Forest)  
✅ Database schema  
✅ Alert generation  
✅ Flask dashboard  

### Private Components
❌ Environment-specific tuning
❌ Production deployment configurations
❌ SIEM integrations
❌ Alert-routing workflows
❌ Incident response playbooks
❌ Organization-specific detection content
❌ Proprietary threat-hunting queries





<img width="953" height="935" alt="Screenshot From 2026-09-09 16-26-31" src="https://github.com/user-attachments/assets/6adc3fdf-9d2c-4184-9e50-0bf10644865a" />

<img width="953" height="935" alt="Screenshot From 2026-09-09 16-26-45" src="https://github.com/user-attachments/assets/a4969481-2da0-47fe-af6f-83dd8ee0e29d" />

<img width="953" height="935" alt="Screenshot From 2026-09-09 16-27-21" src="https://github.com/user-attachments/assets/ffb12349-fea8-4be3-b02a-057a0258c192" />

<img width="953" height="935" alt="Screenshot From 2026-09-09 16-27-30" src="https://github.com/user-attachments/assets/9e4708c5-b9be-406f-bdd6-1b0a832bdb0d" />


<img width="953" height="935" alt="Screenshot From 2026-09-09 16-27-40" src="https://github.com/user-attachments/assets/5f1227d4-4972-413a-99d9-b068acc7382d" />


<img width="953" height="935" alt="Screenshot From 2026-09-09 16-28-01" src="https://github.com/user-attachments/assets/5197b84f-642c-46c9-9057-b41586e75f2d" />

<img width="963" height="926" alt="Screenshot From 2026-09-09 16-31-04" src="https://github.com/user-attachments/assets/85cb040c-3e98-4204-be59-51ab501f07af" />


<img width="963" height="926" alt="Screenshot From 2026-09-09 16-31-23" src="https://github.com/user-attachments/assets/78ba03c8-1da3-4a8d-bbf9-1ce688a1b4a2" />


<img width="943" height="948" alt="Screenshot From 2026-09-15 20-49-38" src="https://github.com/user-attachments/assets/967e4999-f49c-4417-a1d1-845b706d0e6f" />



<img width="944" height="958" alt="Screenshot From 2026-09-15 20-50-02" src="https://github.com/user-attachments/assets/384e2dc4-5980-4b0d-a33e-3df2830b18f0" />



<img width="931" height="600" alt="Screenshot From 2026-09-15 20-50-24" src="https://github.com/user-attachments/assets/45901f5f-a214-4900-a0a6-c58888f873f5" />



## Key Engineering Challenges Solved

### Challenge 1: Establishing User Baselines

Designed a behavioral profiling approach to learn normal user activity and identify deviations.

### Challenge 2: Reducing Alert Noise

Implemented anomaly scoring to prioritize higher-risk events.

### Challenge 3: Investigation Workflow

Created structured alerts with supporting evidence and recommended response actions.


## Connect With Me

* **LinkedIn:** [Charles Arinze](https://www.linkedin.com/in/charlesarinze)
* **GitHub:** [geniusdeeg-security](https://github.com/geniusdeeg-security)
* **Jobberman:** Available on my Jobberman professional profile


## Career Interests

Open To:
- Remote Roles
- Hybrid Roles
- On-Site Roles
- Paid Internship Opportunities

Target Roles:
- Detection Engineer
- Security Analyst
- SOC Analyst
- SOC Analyst II
- Threat Hunter
- Blue Team Analyst

## MITRE ATT&CK Mapping

- T1087 (Account Discovery)
- T1114 (Email Collection)
- T1041 (Exfiltration Over C2)
- T1537 (Transfer Data to Cloud)

## Status

✅ Fully Functional Lab Implementation
✅ Tested End-to-End
✅ Portfolio Project


## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

**Built by:** ARINZE CHARLES

```

