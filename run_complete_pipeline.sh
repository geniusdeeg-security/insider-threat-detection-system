#!/bin/bash

echo "======================================="
echo "PROJECT 1: INSIDER THREAT DETECTION"
echo "======================================="
echo ""

# Activate virtual environment
source venv/bin/activate

echo "[1/8] Collecting network traffic..."
python3 data_collector.py
sleep 2

echo ""
echo "[2/8] Parsing traffic into database..."
python3 traffic_parser.py
sleep 2

echo ""
echo "[3/8] Building network flows..."
python3 flow_aggregator.py
sleep 2

echo ""
echo "[4/8] Running anomaly detection..."
python3 anomaly_detector.py
sleep 2

echo ""
echo "[5/8] Running detection rules..."
python3 detection_rules.py
sleep 2

echo ""
echo "[6/8] Running threat intelligence..."
python3 threat_intel.py
sleep 2

echo ""
echo "[7/8] Exporting SIEM events..."
python3 siem_exporter.py
sleep 2

echo ""
echo "[8/8] Starting dashboard..."
echo ""

echo "======================================="
echo "[✓] PIPELINE COMPLETE"
echo "======================================="
echo ""
echo "Dashboard: http://localhost:5000"
echo ""

python3 dashboard.py
