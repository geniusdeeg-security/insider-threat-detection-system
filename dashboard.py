#!/usr/bin/env python3
# ============================================
# PROJECT 1: STEP 6 - FLASK DASHBOARD
# UPGRADE 7: + MITRE / Threat Intel panels
# UPGRADE 8: + Case Management
# UPGRADE 9: + Production-quality SOC dashboard
#             (pooled connections, health/overview APIs,
#              filtering, KPIs, refresh indicator, debug off)
# ============================================
# Web interface for viewing alerts, anomalies, MITRE coverage,
# threat intelligence matches, and investigation cases.

from flask import Flask, render_template_string, jsonify, request
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
import os
import json

app = Flask(__name__)

DB_CONNECTION = (
    "postgresql://threat_user:"
    "threat_pass_2024@localhost/"
    "insider_threat_db"
)

engine = create_engine(
    DB_CONNECTION,
    pool_pre_ping=True,
    pool_recycle=1800
)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Insider Threat Detection Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 14px;
        }

        .header-status {
            text-align: right;
            font-size: 13px;
            color: #555;
        }

        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 6px;
            background: #999;
        }

        .status-dot.online {
            background: #28a745;
        }

        .status-dot.offline {
            background: #dc3545;
        }

        #last-refresh {
            font-size: 12px;
            color: #999;
            margin-top: 6px;
        }

        .filter-bar {
            background: white;
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
        }

        .filter-bar select {
            padding: 8px 12px;
            border-radius: 5px;
            border: 1px solid #ddd;
            font-size: 14px;
            color: #333;
            background: white;
        }
        
        .stats-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-card.critical .value {
            color: #dc3545;
        }
        
        .stat-card.high .value {
            color: #ff9800;
        }

        .stat-card.cases .value {
            color: #28a745;
        }
        
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        @media (max-width: 1000px) {
            .content-grid {
                grid-template-columns: 1fr;
            }

            .header-top {
                flex-direction: column;
            }

            .header-status {
                text-align: left;
            }
        }
        
        .panel {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .panel h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 18px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .alert-item {
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #dc3545;
            background: #fff5f5;
            border-radius: 4px;
        }
        
        .alert-item.high {
            border-left-color: #ff9800;
            background: #fff8f0;
        }
        
        .alert-item.medium {
            border-left-color: #ffc107;
            background: #fffbf0;
        }
        
        .alert-item.low {
            border-left-color: #28a745;
            background: #f0fff4;
        }
        
        .alert-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        
        .alert-time {
            font-size: 12px;
            color: #999;
        }
        
        .alert-details {
            font-size: 13px;
            color: #555;
            margin-top: 8px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        th {
            background: #f5f5f5;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 1px solid #ddd;
            font-size: 13px;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #eee;
            font-size: 13px;
            color: #555;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge.critical {
            background: #dc3545;
            color: white;
        }
        
        .badge.high {
            background: #ff9800;
            color: white;
        }
        
        .badge.medium {
            background: #ffc107;
            color: #333;
        }
        
        .badge.low {
            background: #28a745;
            color: white;
        }

        .badge.open {
            background: #667eea;
            color: white;
        }

        .badge.investigating {
            background: #ffc107;
            color: #333;
        }

        .badge.resolved {
            background: #28a745;
            color: white;
        }

        .badge.closed {
            background: #6c757d;
            color: white;
        }
        
        .loading {
            text-align: center;
            color: #999;
            padding: 20px;
        }
        
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        
        .refresh-btn:hover {
            background: #764ba2;
        }

        .case-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 6px 14px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 8px;
        }

        .case-btn:hover {
            background: #1e7e34;
        }
        
        .mitre-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .mitre-row:last-child {
            border-bottom: none;
        }
        
        .mitre-label {
            flex: 0 0 240px;
            font-size: 13px;
            font-weight: 600;
            color: #333;
        }
        
        .mitre-bar-track {
            flex: 1;
            height: 10px;
            background: #f0f0f0;
            border-radius: 5px;
            overflow: hidden;
        }
        
        .mitre-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 5px;
        }
        
        .mitre-count {
            flex: 0 0 30px;
            text-align: right;
            font-weight: bold;
            color: #667eea;
            font-size: 13px;
        }
        
        .threat-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .threat-row:last-child {
            border-bottom: none;
        }
        
        .threat-label {
            flex: 0 0 160px;
            font-size: 13px;
            font-weight: 600;
            color: #333;
        }
        
        .threat-bar-track {
            flex: 1;
            height: 10px;
            background: #f0f0f0;
            border-radius: 5px;
            overflow: hidden;
        }
        
        .threat-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #dc3545, #ff9800);
            border-radius: 5px;
        }
        
        .threat-count {
            flex: 0 0 30px;
            text-align: right;
            font-weight: bold;
            color: #dc3545;
            font-size: 13px;
        }

        .system-status-row {
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
            padding: 10px 0;
        }

        .system-status-item {
            display: flex;
            align-items: center;
            font-size: 13px;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-top">
                <div>
                    <h1>🛡️ Insider Threat SOC</h1>
                    <p>Real-time monitoring, detection, and investigation</p>
                </div>
                <div class="header-status">
                    <div>
                        <span class="status-dot" id="system-status-dot"></span>
                        <span id="system-status-text">Checking system...</span>
                    </div>
                    <div id="last-refresh">Last refresh: --</div>
                </div>
            </div>
        </div>

        <div class="filter-bar">
            <select id="severityFilter" onchange="applyFilters()">
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>

            <select id="statusFilter" onchange="applyFilters()">
                <option value="">All Statuses</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="closed">Closed</option>
            </select>

            <button class="refresh-btn" onclick="loadDashboard()">🔄 Refresh</button>
        </div>
        
        <div class="stats-row">
            <div class="stat-card critical">
                <h3>Critical Alerts</h3>
                <div class="value" id="critical-count">-</div>
            </div>
            <div class="stat-card high">
                <h3>High Priority Alerts</h3>
                <div class="value" id="high-count">-</div>
            </div>
            <div class="stat-card cases">
                <h3>Open Cases</h3>
                <div class="value" id="open-cases-count">-</div>
            </div>
            <div class="stat-card">
                <h3>Anomalies (24h)</h3>
                <div class="value" id="anomaly-count-kpi">-</div>
            </div>
        </div>

        <div class="content-grid">
            <div class="panel">
                <h2>Alert Trend (24h)</h2>
                <canvas id="alertTrendChart" height="100"></canvas>
            </div>

            <div class="panel">
                <h2>Severity Distribution (24h)</h2>
                <canvas id="severityChart" height="100"></canvas>
            </div>
        </div>
        
        <div class="content-grid">
            <div class="panel">
                <h2>Active Alerts</h2>
                <div id="alerts-container" class="loading">Loading alerts...</div>
            </div>
            
            <div class="panel">
                <h2>📁 Active Cases</h2>
                <button class="refresh-btn" onclick="loadCases()">🔄 Refresh Cases</button>
                <div id="cases-container" class="loading">Loading cases...</div>
            </div>
        </div>

        <div class="panel">
            <h2>MITRE ATT&CK Techniques</h2>
            <div id="mitre-container" class="loading">Loading MITRE techniques...</div>
        </div>

        <div class="panel">
            <h2>Threat Intelligence Matches</h2>
            <div id="threats-container" class="loading">Loading threat intel matches...</div>
        </div>

        <div class="panel">
            <h2>Recent Anomalies</h2>
            <div id="anomalies-container" class="loading">Loading anomalies...</div>
        </div>
        
        <div class="panel">
            <h2>Anomaly Trends (Last 24 Hours)</h2>
            <canvas id="trendChart" height="100"></canvas>
        </div>

        <div class="panel">
            <h2>System Status</h2>
            <div id="system-status-container" class="system-status-row loading">Loading system status...</div>
        </div>
    </div>
    
    <script>
        let alertTrendChart = null;
        let severityChart = null;
        let anomalyTrendChartInstance = null;

        // Load on page load, then refresh once every 30 seconds.
        // The interval is set up here, ONCE, not inside loadDashboard()
        // itself - scheduling it from inside the function it refreshes
        // is what caused the earlier request-storm bug (each tick would
        // add yet another interval on top of the ones already running).
        window.addEventListener('load', () => {
            loadDashboard();
            setInterval(loadDashboard, 30000);
        });

        async function loadDashboard() {
            await loadHealth();
            await loadOverview();
            await loadAlerts();
            await loadCases();
            await loadAlertTrends();
            await loadSeverityChart();
            await loadMitreSummary();
            await loadThreats();
            await loadAnomalies();
            await loadAnomalyTrends();
            await loadSystemStatus();
            updateRefreshTime();
        }

        function updateRefreshTime() {
            const now = new Date();
            document.getElementById('last-refresh').textContent =
                'Last refresh: ' + now.toLocaleTimeString();
        }

        async function loadHealth() {
            const dot = document.getElementById('system-status-dot');
            const text = document.getElementById('system-status-text');

            try {
                const response = await fetch('/api/health');
                const data = await response.json();

                if (data.status === 'healthy') {
                    dot.className = 'status-dot online';
                    text.textContent = 'SYSTEM ONLINE';
                } else {
                    dot.className = 'status-dot offline';
                    text.textContent = 'SYSTEM OFFLINE';
                }
            } catch (error) {
                console.error('Error loading health:', error);
                dot.className = 'status-dot offline';
                text.textContent = 'SYSTEM OFFLINE';
            }
        }

        async function loadOverview() {
            try {
                const response = await fetch('/api/overview');
                const data = await response.json();

                document.getElementById('critical-count').textContent = data.critical_alerts;
                document.getElementById('high-count').textContent = data.high_alerts;
                document.getElementById('open-cases-count').textContent = data.open_cases;
                document.getElementById('anomaly-count-kpi').textContent = data.total_anomalies_24h;
            } catch (error) {
                console.error('Error loading overview:', error);
            }
        }

        function renderAlerts(alerts) {
            const container = document.getElementById('alerts-container');

            if (!alerts || alerts.length === 0) {
                container.innerHTML = '<div class="loading">✓ No alerts match the current filters</div>';
                return;
            }

            let html = '';
            alerts.forEach(alert => {
                const statusLabel = alert.status || 'open';
                const caseTag = alert.case_id
                    ? `<span style="font-size:12px;color:#999;margin-left:8px;">In case #${alert.case_id}</span>`
                    : `<button class="case-btn" onclick="createCase(${alert.id})">📁 Create Case</button>`;

                html += `
                    <div class="alert-item ${alert.severity.toLowerCase()}">
                        <div class="alert-title">${alert.alert_type} - ${alert.user_ip}</div>
                        <div class="alert-time">${new Date(alert.timestamp).toLocaleString()}</div>
                        <div class="alert-details">${alert.description}</div>
                        <div style="margin-top: 10px;">
                            <span class="badge ${alert.severity.toLowerCase()}">${alert.severity}</span>
                            <span class="badge ${statusLabel.toLowerCase()}">${statusLabel}</span>
                            ${caseTag}
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        async function loadAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();
                renderAlerts(alerts);
            } catch (error) {
                console.error('Error loading alerts:', error);
            }
        }

        async function applyFilters() {
            const severity = document.getElementById('severityFilter').value;
            const status = document.getElementById('statusFilter').value;

            let url = '/api/alerts?';

            if (severity) {
                url += `severity=${severity}&`;
            }

            if (status) {
                url += `status=${status}&`;
            }

            try {
                const response = await fetch(url);
                const alerts = await response.json();
                renderAlerts(alerts);
            } catch (error) {
                console.error('Filter error:', error);
            }
        }
        
        async function loadAnomalies() {
            try {
                const response = await fetch('/api/anomalies');
                const data = await response.json();
                
                const container = document.getElementById('anomalies-container');
                
                if (data.length === 0) {
                    container.innerHTML = '<div class="loading">No recent anomalies</div>';
                    return;
                }
                
                let html = '<table><thead><tr><th>User IP</th><th>Type</th><th>Deviation</th><th>Severity</th></tr></thead><tbody>';
                data.slice(0, 10).forEach(anom => {
                    html += `
                        <tr>
                            <td>${anom.user_ip}</td>
                            <td>${anom.deviation_type}</td>
                            <td>${anom.deviation_percent ? anom.deviation_percent.toFixed(1) + '%' : 'N/A'}</td>
                            <td><span class="badge ${anom.severity.toLowerCase()}">${anom.severity}</span></td>
                        </tr>
                    `;
                });
                html += '</tbody></table>';
                
                container.innerHTML = html;
            } catch (error) {
                console.error('Error loading anomalies:', error);
            }
        }

        async function loadAlertTrends() {
            try {
                const response = await fetch('/api/alert-trends');
                const trends = await response.json();

                const ctx = document.getElementById('alertTrendChart').getContext('2d');

                if (alertTrendChart) {
                    alertTrendChart.destroy();
                }

                const labels = trends.map(t =>
                    new Date(t.hour).toLocaleTimeString([], { hour: '2-digit' })
                );
                const data = trends.map(t => t.alert_count);

                alertTrendChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Alerts per Hour',
                            data: data,
                            borderColor: '#dc3545',
                            backgroundColor: 'rgba(220, 53, 69, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: { legend: { display: true } },
                        scales: { y: { beginAtZero: true } }
                    }
                });
            } catch (error) {
                console.error('Error loading alert trends:', error);
            }
        }

        async function loadSeverityChart() {
            try {
                const response = await fetch('/api/alert-severity');
                const data = await response.json();

                const ctx = document.getElementById('severityChart').getContext('2d');

                if (severityChart) {
                    severityChart.destroy();
                }

                const colors = {
                    critical: '#dc3545',
                    high: '#ff9800',
                    medium: '#ffc107',
                    low: '#28a745'
                };

                const labels = data.map(d => d.severity);
                const counts = data.map(d => d.count);
                const backgroundColors = data.map(d => colors[d.severity] || '#667eea');

                severityChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Alerts (24h)',
                            data: counts,
                            backgroundColor: backgroundColors
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: { legend: { display: false } },
                        scales: { y: { beginAtZero: true } }
                    }
                });
            } catch (error) {
                console.error('Error loading severity chart:', error);
            }
        }

        async function loadAnomalyTrends() {
            try {
                const response = await fetch('/api/trends');
                const trends = await response.json();
                
                const ctx = document.getElementById('trendChart').getContext('2d');

                if (anomalyTrendChartInstance) {
                    anomalyTrendChartInstance.destroy();
                }
                
                // Group by hour
                const hours = {};
                trends.forEach(trend => {
                    const hour = new Date(trend.hour).getHours();
                    hours[hour] = (hours[hour] || 0) + trend.anomaly_count;
                });
                
                const labels = Object.keys(hours).map(h => h + ':00');
                const data = Object.values(hours);
                
                anomalyTrendChartInstance = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Anomalies per Hour',
                            data: data,
                            borderColor: '#667eea',
                            backgroundColor: 'rgba(102, 126, 234, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: {
                                display: true
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error loading anomaly trends:', error);
            }
        }
        
        async function loadMitreSummary() {
            try {
                const response = await fetch('/api/mitre-summary');
                const data = await response.json();
                
                const container = document.getElementById('mitre-container');
                
                if (data.length === 0) {
                    container.innerHTML = '<div class="loading">No MITRE-tagged alerts yet</div>';
                    return;
                }
                
                const maxTotal = Math.max(...data.map(d => d.detection_count));
                
                let html = '';
                data.forEach(d => {
                    const pct = maxTotal > 0 ? (d.detection_count / maxTotal) * 100 : 0;
                    html += `
                        <div class="mitre-row">
                            <div class="mitre-label">${d.mitre_technique_id} &middot; ${d.mitre_technique_name}</div>
                            <div class="mitre-bar-track">
                                <div class="mitre-bar-fill" style="width: ${pct}%;"></div>
                            </div>
                            <div class="mitre-count">${d.detection_count}</div>
                        </div>
                    `;
                });
                
                container.innerHTML = html;
            } catch (error) {
                console.error('Error loading MITRE summary:', error);
            }
        }
        
        async function loadThreats() {
            try {
                const response = await fetch('/api/threats');
                const data = await response.json();
                
                const container = document.getElementById('threats-container');
                
                if (data.length === 0) {
                    container.innerHTML = '<div class="loading">No threat intel matches</div>';
                    return;
                }
                
                const maxTotal = Math.max(...data.map(d => d.total_matches));
                
                let html = '';
                data.forEach(d => {
                    const pct = maxTotal > 0 ? (d.total_matches / maxTotal) * 100 : 0;
                    html += `
                        <div class="threat-row">
                            <div class="threat-label">${d.threat_type}</div>
                            <div class="threat-bar-track">
                                <div class="threat-bar-fill" style="width: ${pct}%;"></div>
                            </div>
                            <div class="threat-count">${d.total_matches}</div>
                        </div>
                    `;
                });
                
                container.innerHTML = html;
            } catch (error) {
                console.error('Error loading threat intel matches:', error);
            }
        }

        async function loadCases() {
            try {
                const response = await fetch('/api/cases');
                const cases = await response.json();

                const container = document.getElementById('cases-container');

                if (cases.length === 0) {
                    container.innerHTML = '<div class="loading">No investigation cases</div>';
                    return;
                }

                let html = `
                    <table>
                        <thead>
                            <tr>
                                <th>Case</th>
                                <th>Title</th>
                                <th>Severity</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Analyst</th>
                            </tr>
                        </thead>
                        <tbody>
                `;

                cases.forEach(caseItem => {
                    html += `
                        <tr>
                            <td><strong>${caseItem.case_number}</strong></td>
                            <td>${caseItem.title}</td>
                            <td><span class="badge ${caseItem.severity.toLowerCase()}">${caseItem.severity}</span></td>
                            <td>${caseItem.priority}</td>
                            <td><span class="badge ${caseItem.status.toLowerCase()}">${caseItem.status}</span></td>
                            <td>${caseItem.assigned_to || 'Unassigned'}</td>
                        </tr>
                    `;
                });

                html += '</tbody></table>';

                container.innerHTML = html;
            } catch (error) {
                console.error('Error loading cases:', error);
            }
        }

        async function loadSystemStatus() {
            const container = document.getElementById('system-status-container');

            try {
                const healthResp = await fetch('/api/health');
                const health = await healthResp.json();

                const sysResp = await fetch('/api/system-status');
                const sys = await sysResp.json();

                const dbOnline = health.status === 'healthy';

                const items = [
                    { label: 'Database', online: dbOnline },
                    { label: 'Traffic', online: (sys.traffic_events || 0) > 0 },
                    { label: 'Flows', online: (sys.network_flows || 0) > 0 },
                    { label: 'Detection', online: (sys.alerts || 0) > 0 },
                    { label: 'Cases', online: (sys.cases || 0) > 0 }
                ];

                let html = '';
                items.forEach(item => {
                    html += `
                        <div class="system-status-item">
                            <span class="status-dot ${item.online ? 'online' : 'offline'}"></span>
                            ${item.label}
                        </div>
                    `;
                });

                container.className = 'system-status-row';
                container.innerHTML = html;
            } catch (error) {
                console.error('Error loading system status:', error);
                container.innerHTML = '<div class="loading">System status unavailable</div>';
            }
        }

        async function createCase(alertId) {
            try {
                const response = await fetch('/api/cases/create', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ alert_id: alertId })
                });

                const data = await response.json();

                if (!response.ok) {
                    alert(data.error || 'Failed to create case');
                    return;
                }

                alert('Case created: ' + data.case_number);

                await loadAlerts();
                await loadCases();
                await loadOverview();
            } catch (error) {
                console.error('Error creating case:', error);
                alert('Unable to create case');
            }
        }
    </script>
</body>
</html>
"""

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/')
def index():
    """Main dashboard"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/health')
def api_health():
    """Check dashboard and database health"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        return jsonify({
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat()
        })

    except SQLAlchemyError as e:
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }), 500


@app.route('/api/overview')
def api_overview():
    """Return high-level SOC metrics"""
    try:
        with engine.connect() as conn:

            critical_alerts = conn.execute(text("""
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'critical'
                AND status = 'open'
            """)).scalar()

            high_alerts = conn.execute(text("""
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'high'
                AND status = 'open'
            """)).scalar()

            medium_alerts = conn.execute(text("""
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'medium'
                AND status = 'open'
            """)).scalar()

            low_alerts = conn.execute(text("""
                SELECT COUNT(*)
                FROM alerts
                WHERE severity = 'low'
                AND status = 'open'
            """)).scalar()

            total_alerts = conn.execute(text("""
                SELECT COUNT(*)
                FROM alerts
                WHERE timestamp > NOW() - INTERVAL '24 hours'
            """)).scalar()

            total_anomalies = conn.execute(text("""
                SELECT COUNT(*)
                FROM anomalies
                WHERE timestamp > NOW() - INTERVAL '24 hours'
            """)).scalar()

            open_cases = conn.execute(text("""
                SELECT COUNT(*)
                FROM cases
                WHERE status IN ('open', 'investigating')
            """)).scalar()

            resolved_cases = conn.execute(text("""
                SELECT COUNT(*)
                FROM cases
                WHERE status IN ('resolved', 'closed')
                AND updated_at > NOW() - INTERVAL '24 hours'
            """)).scalar()

            unique_users = conn.execute(text("""
                SELECT COUNT(DISTINCT user_ip)
                FROM anomalies
                WHERE timestamp > NOW() - INTERVAL '24 hours'
            """)).scalar()

            return jsonify({
                "critical_alerts": critical_alerts or 0,
                "high_alerts": high_alerts or 0,
                "medium_alerts": medium_alerts or 0,
                "low_alerts": low_alerts or 0,
                "total_alerts_24h": total_alerts or 0,
                "total_anomalies_24h": total_anomalies or 0,
                "open_cases": open_cases or 0,
                "resolved_cases_24h": resolved_cases or 0,
                "unique_users_24h": unique_users or 0
            })

    except SQLAlchemyError as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route('/api/alert-severity')
def api_alert_severity():
    """Return alert counts by severity, for the last 24 hours"""
    with engine.connect() as conn:

        result = conn.execute(text("""
            SELECT
                severity,
                COUNT(*) AS count
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """))

        return jsonify([
            dict(row._mapping)
            for row in result
        ])


@app.route('/api/alert-trends')
def api_alert_trends():
    """Return alert volume per hour, for the last 24 hours"""
    with engine.connect() as conn:

        result = conn.execute(text("""
            SELECT
                DATE_TRUNC('hour', timestamp) AS hour,
                COUNT(*) AS alert_count
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY DATE_TRUNC('hour', timestamp)
            ORDER BY hour ASC
        """))

        return jsonify([
            dict(row._mapping)
            for row in result
        ])


@app.route('/api/alerts')
def api_alerts():
    """Get alerts, optionally filtered by severity/status, most recent first"""
    severity = request.args.get('severity')
    status = request.args.get('status')
    limit = request.args.get('limit', 50, type=int)

    if limit < 1:
        limit = 50

    if limit > 200:
        limit = 200

    query = """
        SELECT
            a.id,
            a.timestamp,
            a.user_ip,
            a.alert_type,
            a.severity,
            a.description,
            a.status,
            a.case_id
        FROM alerts a
        WHERE 1=1
    """

    params = {}

    if severity:
        query += """
            AND a.severity = :severity
        """

        params["severity"] = severity

    if status:
        query += """
            AND a.status = :status
        """

        params["status"] = status

    query += """
        ORDER BY a.timestamp DESC
        LIMIT :limit
    """

    params["limit"] = limit

    with engine.connect() as conn:

        result = conn.execute(
            text(query),
            params
        )

        return jsonify([
            dict(row._mapping)
            for row in result
        ])


@app.route('/api/anomalies')
def api_anomalies():
    """Get recent anomalies"""
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT id, timestamp, user_ip, deviation_type, deviation_percent, severity
            FROM anomalies
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            ORDER BY timestamp DESC
            LIMIT 50
        """))

        anomalies = [dict(row._mapping) for row in result]

        return jsonify(anomalies)


@app.route('/api/trends')
def api_trends():
    """Get anomaly trends (kept from Step 6 - still used for the Anomaly
    Trends chart, distinct from the newer /api/alert-trends)"""
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT hour, anomaly_count
            FROM anomaly_trends
            WHERE hour > NOW() - INTERVAL '24 hours'
            ORDER BY hour DESC
        """))

        trends = [dict(row._mapping) for row in result]

        return jsonify(trends)


@app.route('/api/mitre-summary')
def api_mitre_summary():
    """Return technique-level MITRE ATT&CK detection counts, across all
    alerts (not just open ones) - this is what the dashboard's MITRE
    panel now renders from, replacing the older tactic-level /api/mitre."""
    with engine.connect() as conn:

        result = conn.execute(text("""
            SELECT
                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic,
                COUNT(*) AS detection_count
            FROM alerts
            WHERE mitre_technique_id IS NOT NULL
            GROUP BY
                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic
            ORDER BY detection_count DESC
            LIMIT 20
        """))

        return jsonify([
            dict(row._mapping)
            for row in result
        ])


@app.route('/api/mitre')
def api_mitre():
    """Get MITRE ATT&CK tactic coverage for open alerts.

    Kept for backward compatibility with Upgrade 7 - the dashboard UI
    now uses /api/mitre-summary (technique-level, all alerts) instead,
    but this endpoint is left intact since nothing in the spec asked
    for it to be removed.
    """
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT
                mitre_tactic,
                COUNT(*) AS total
            FROM alerts
            WHERE status = 'open'
            GROUP BY mitre_tactic
            ORDER BY total DESC
        """))

        mitre_stats = [dict(row._mapping) for row in result]

        return jsonify(mitre_stats)


@app.route('/api/threats')
def api_threats():
    """Get threat intelligence match summary, by threat type"""
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT
                threat_type,
                total_matches,
                avg_confidence
            FROM threat_summary
            ORDER BY total_matches DESC
        """))

        threat_stats = [dict(row._mapping) for row in result]

        return jsonify(threat_stats)


@app.route('/api/ioc/<indicator>')
def api_ioc(indicator):
    """Look up a single indicator in the threat intel feed"""
    with engine.connect() as conn:
        result = conn.execute(
            text("""
                SELECT indicator, threat_type, confidence, source
                FROM threat_intelligence
                WHERE indicator = :indicator
            """),
            {"indicator": indicator}
        ).fetchone()

        if not result:
            return jsonify({"error": "Indicator not found"}), 404

        return jsonify(dict(result._mapping))


@app.route('/api/stats')
def api_stats():
    """Original Step-6 KPI endpoint. Kept for backward compatibility -
    the dashboard UI now reads its KPI cards from /api/overview instead,
    which covers the same ground plus case/anomaly figures."""
    with engine.connect() as conn:
        critical = conn.execute(text("""
            SELECT COUNT(*) as count FROM alerts 
            WHERE severity = 'critical' AND status = 'open'
        """)).fetchone()[0]

        high = conn.execute(text("""
            SELECT COUNT(*) as count FROM alerts 
            WHERE severity = 'high' AND status = 'open'
        """)).fetchone()[0]

        anomalies = conn.execute(text("""
            SELECT COUNT(*) as count FROM anomalies 
            WHERE timestamp > NOW() - INTERVAL '24 hours'
        """)).fetchone()[0]

        users = conn.execute(text("""
            SELECT COUNT(DISTINCT user_ip) as count FROM anomalies 
            WHERE timestamp > NOW() - INTERVAL '24 hours'
        """)).fetchone()[0]

        return jsonify({
            'critical_alerts': critical or 0,
            'high_alerts': high or 0,
            'total_anomalies': anomalies or 0,
            'unique_users': users or 0
        })


# ============================================
# UPGRADE 8 - CASE MANAGEMENT API
# ============================================

@app.route('/api/cases')
def api_cases():
    """Return recent investigation cases"""
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT
                id,
                case_number,
                title,
                description,
                severity,
                status,
                priority,
                assigned_to,
                created_at,
                updated_at,
                closed_at,
                resolution
            FROM cases
            ORDER BY created_at DESC
            LIMIT 100
        """))

        cases = [dict(row._mapping) for row in result]

        return jsonify(cases)


@app.route('/api/cases/<int:case_id>')
def api_case_detail(case_id):
    """Return complete case information: case + notes + evidence + linked alerts"""
    with engine.connect() as conn:
        case = conn.execute(text("""
            SELECT
                id,
                case_number,
                title,
                description,
                severity,
                status,
                priority,
                assigned_to,
                created_at,
                updated_at,
                closed_at,
                resolution
            FROM cases
            WHERE id = :case_id
        """), {
            "case_id": case_id
        }).mappings().first()

        if not case:
            return jsonify({
                "error": "Case not found"
            }), 404

        notes = conn.execute(text("""
            SELECT
                id,
                analyst,
                note,
                created_at
            FROM case_notes
            WHERE case_id = :case_id
            ORDER BY created_at DESC
        """), {
            "case_id": case_id
        })

        evidence = conn.execute(text("""
            SELECT
                id,
                evidence_type,
                evidence_data,
                description,
                collected_by,
                created_at
            FROM case_evidence
            WHERE case_id = :case_id
            ORDER BY created_at DESC
        """), {
            "case_id": case_id
        })

        alerts = conn.execute(text("""
            SELECT
                id,
                timestamp,
                user_ip,
                alert_type,
                severity,
                description,
                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic
            FROM alerts
            WHERE case_id = :case_id
            ORDER BY timestamp DESC
        """), {
            "case_id": case_id
        })

        return jsonify({
            "case": dict(case),
            "notes": [dict(row._mapping) for row in notes],
            "evidence": [dict(row._mapping) for row in evidence],
            "alerts": [dict(row._mapping) for row in alerts]
        })


@app.route('/api/cases/create', methods=['POST'])
def api_create_case():
    """Create a new case from an existing alert, and link the alert to it."""
    data = request.get_json() or {}

    alert_id = data.get("alert_id")

    if not alert_id:
        return jsonify({
            "error": "alert_id is required"
        }), 400

    with engine.begin() as conn:

        alert = conn.execute(text("""
            SELECT
                id,
                user_ip,
                alert_type,
                severity,
                description,
                case_id
            FROM alerts
            WHERE id = :alert_id
        """), {
            "alert_id": alert_id
        }).mappings().first()

        if not alert:
            return jsonify({
                "error": "Alert not found"
            }), 404

        if alert["case_id"] is not None:
            return jsonify({
                "error": "Alert already belongs to a case",
                "case_id": alert["case_id"]
            }), 409

        count_result = conn.execute(text("""
            SELECT COUNT(*)
            FROM cases
            WHERE EXTRACT(YEAR FROM created_at) =
                  EXTRACT(YEAR FROM CURRENT_TIMESTAMP)
        """))

        count = count_result.scalar() + 1

        case_number = (
            f"CASE-{datetime.now().year}-{count:04d}"
        )

        result = conn.execute(text("""
            INSERT INTO cases
            (
                case_number,
                title,
                description,
                severity,
                priority,
                assigned_to
            )
            VALUES
            (
                :case_number,
                :title,
                :description,
                :severity,
                :priority,
                :assigned_to
            )
            RETURNING id, case_number
        """), {
            "case_number": case_number,
            "title": f"Investigation: {alert['alert_type']}",
            "description": alert["description"],
            "severity": alert["severity"],
            "priority": alert["severity"],
            "assigned_to": None
        })

        case = result.fetchone()

        conn.execute(text("""
            UPDATE alerts
            SET
                case_id = :case_id,
                status = 'investigating'
            WHERE id = :alert_id
        """), {
            "case_id": case.id,
            "alert_id": alert_id
        })

        return jsonify({
            "success": True,
            "case_id": case.id,
            "case_number": case.case_number
        }), 201


@app.route('/api/cases/<int:case_id>/status', methods=['PUT'])
def api_update_case_status(case_id):
    """Update case status; resolved/closed also stamp closed_at + resolution"""
    data = request.get_json() or {}

    status = data.get("status")
    resolution = data.get("resolution")

    allowed_statuses = [
        "open",
        "investigating",
        "resolved",
        "closed"
    ]

    if status not in allowed_statuses:
        return jsonify({
            "error": "Invalid case status"
        }), 400

    with engine.begin() as conn:

        case = conn.execute(text("""
            SELECT id
            FROM cases
            WHERE id = :case_id
        """), {
            "case_id": case_id
        }).first()

        if not case:
            return jsonify({
                "error": "Case not found"
            }), 404

        if status in ["resolved", "closed"]:

            conn.execute(text("""
                UPDATE cases
                SET
                    status = :status,
                    resolution = :resolution,
                    closed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :case_id
            """), {
                "case_id": case_id,
                "status": status,
                "resolution": resolution
            })

        else:

            conn.execute(text("""
                UPDATE cases
                SET
                    status = :status,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :case_id
            """), {
                "case_id": case_id,
                "status": status
            })

    return jsonify({
        "success": True,
        "case_id": case_id,
        "status": status
    })


@app.route('/api/cases/<int:case_id>/notes', methods=['POST'])
def api_add_case_note(case_id):
    """Add an investigation note to a case"""
    data = request.get_json() or {}

    analyst = data.get("analyst")
    note = data.get("note")

    if not analyst or not note:
        return jsonify({
            "error": "analyst and note are required"
        }), 400

    with engine.begin() as conn:

        case = conn.execute(text("""
            SELECT id
            FROM cases
            WHERE id = :case_id
        """), {
            "case_id": case_id
        }).first()

        if not case:
            return jsonify({
                "error": "Case not found"
            }), 404

        conn.execute(text("""
            INSERT INTO case_notes
            (
                case_id,
                analyst,
                note
            )
            VALUES
            (
                :case_id,
                :analyst,
                :note
            )
        """), {
            "case_id": case_id,
            "analyst": analyst,
            "note": note
        })

    return jsonify({
        "success": True
    }), 201


@app.route('/api/cases/<int:case_id>/evidence', methods=['POST'])
def api_add_case_evidence(case_id):
    """Add evidence to a case"""
    data = request.get_json() or {}

    evidence_type = data.get("evidence_type")
    evidence_data = data.get("evidence_data")
    description = data.get("description")
    collected_by = data.get("collected_by")

    if not evidence_type or not evidence_data:
        return jsonify({
            "error": "evidence_type and evidence_data are required"
        }), 400

    with engine.begin() as conn:

        case = conn.execute(text("""
            SELECT id
            FROM cases
            WHERE id = :case_id
        """), {
            "case_id": case_id
        }).first()

        if not case:
            return jsonify({
                "error": "Case not found"
            }), 404

        conn.execute(text("""
            INSERT INTO case_evidence
            (
                case_id,
                evidence_type,
                evidence_data,
                description,
                collected_by
            )
            VALUES
            (
                :case_id,
                :evidence_type,
                CAST(:evidence_data AS JSONB),
                :description,
                :collected_by
            )
        """), {
            "case_id": case_id,
            "evidence_type": evidence_type,
            "evidence_data": json.dumps(evidence_data),
            "description": description,
            "collected_by": collected_by
        })

    return jsonify({
        "success": True
    }), 201


@app.route('/api/case-stats')
def api_case_stats():
    """Return case counts by status.

    Kept alongside the newer /api/case-summary (Upgrade 9) since it
    returns a different shape (fixed open/investigating/resolved
    buckets vs. a raw per-status breakdown) - nothing in the spec asked
    for this one to be removed.
    """
    with engine.connect() as conn:

        total = conn.execute(text("""
            SELECT COUNT(*)
            FROM cases
        """)).scalar()

        open_cases = conn.execute(text("""
            SELECT COUNT(*)
            FROM cases
            WHERE status = 'open'
        """)).scalar()

        investigating = conn.execute(text("""
            SELECT COUNT(*)
            FROM cases
            WHERE status = 'investigating'
        """)).scalar()

        resolved = conn.execute(text("""
            SELECT COUNT(*)
            FROM cases
            WHERE status IN ('resolved', 'closed')
        """)).scalar()

        return jsonify({
            "total": total or 0,
            "open": open_cases or 0,
            "investigating": investigating or 0,
            "resolved": resolved or 0
        })


@app.route('/api/case-summary')
def api_case_summary():
    """Return raw case counts grouped by status"""
    with engine.connect() as conn:

        result = conn.execute(text("""
            SELECT
                status,
                COUNT(*) AS count
            FROM cases
            GROUP BY status
            ORDER BY status
        """))

        return jsonify([
            dict(row._mapping)
            for row in result
        ])


@app.route('/api/system-status')
def api_system_status():
    """Return pipeline-stage row counts, for the System Status panel"""
    try:
        with engine.connect() as conn:

            traffic_events = conn.execute(text("""
                SELECT COUNT(*)
                FROM traffic_events
            """)).scalar()

            flows = conn.execute(text("""
                SELECT COUNT(*)
                FROM network_flows
            """)).scalar()

            anomalies = conn.execute(text("""
                SELECT COUNT(*)
                FROM anomalies
            """)).scalar()

            alerts = conn.execute(text("""
                SELECT COUNT(*)
                FROM alerts
            """)).scalar()

            cases = conn.execute(text("""
                SELECT COUNT(*)
                FROM cases
            """)).scalar()

        return jsonify({
            "database": "online",
            "traffic_events": traffic_events or 0,
            "network_flows": flows or 0,
            "anomalies": anomalies or 0,
            "alerts": alerts or 0,
            "cases": cases or 0
        })

    except Exception as e:

        return jsonify({
            "database": "offline",
            "error": str(e)
        }), 500


# ============================================
# UPGRADE 10 - SIEM EXPORT API
# ============================================

@app.route('/api/siem/alerts')
def api_siem_alerts():
    """Return alerts as normalized SIEM events"""
    limit = request.args.get(
        'limit',
        100,
        type=int
    )

    if limit < 1:
        limit = 1

    if limit > 1000:
        limit = 1000

    with engine.connect() as conn:

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
            LIMIT :limit
        """), {
            "limit": limit
        })

        events = []

        for row in result:

            event = dict(
                row._mapping
            )

            evidence = event.get(
                "evidence"
            )

            if evidence is None:
                evidence = {}

            events.append({

                "event_id":
                    f"ITD-ALERT-{event['id']}",

                "event_type":
                    "security_alert",

                "event_time":
                    event["timestamp"].isoformat()
                    if event["timestamp"]
                    else None,

                "source":
                    "insider-threat-detection",

                "category":
                    "network_security",

                "severity":
                    event["severity"],

                "status":
                    event["status"],

                "user_ip":
                    str(event["user_ip"]),

                "alert_type":
                    event["alert_type"],

                "description":
                    event["description"],

                "evidence":
                    evidence
            })

        return jsonify(events)


@app.route('/api/siem/anomalies')
def api_siem_anomalies():
    """Return anomalies as normalized SIEM events"""
    limit = request.args.get(
        'limit',
        100,
        type=int
    )

    if limit < 1:
        limit = 1

    if limit > 1000:
        limit = 1000

    with engine.connect() as conn:

        result = conn.execute(text("""
            SELECT
                id,
                timestamp,
                user_ip,
                destination_ip,
                destination_port,
                protocol,
                expected_bytes,
                actual_bytes,
                deviation_percent,
                deviation_type,
                severity,
                status
            FROM anomalies
            ORDER BY timestamp DESC
            LIMIT :limit
        """), {
            "limit": limit
        })

        events = []

        for row in result:

            event = dict(
                row._mapping
            )

            events.append({

                "event_id":
                    f"ITD-ANOMALY-{event['id']}",

                "event_type":
                    "network_anomaly",

                "event_time":
                    event["timestamp"].isoformat()
                    if event["timestamp"]
                    else None,

                "source":
                    "insider-threat-detection",

                "user_ip":
                    str(event["user_ip"]),

                "destination_ip":
                    str(event["destination_ip"]),

                "destination_port":
                    event["destination_port"],

                "protocol":
                    event["protocol"],

                "expected_bytes":
                    event["expected_bytes"],

                "actual_bytes":
                    event["actual_bytes"],

                "deviation_percent":
                    event["deviation_percent"],

                "deviation_type":
                    event["deviation_type"],

                "severity":
                    event["severity"],

                "status":
                    event["status"]
            })

        return jsonify(events)


@app.route('/api/siem/cases')
def api_siem_cases():
    """Return cases, most recent first.

    Uses cases.created_at - confirmed present in the Step 8.1 schema
    (CREATE TABLE cases ... created_at TIMESTAMP DEFAULT
    CURRENT_TIMESTAMP), so no column substitution needed here.
    """
    limit = request.args.get(
        'limit',
        100,
        type=int
    )

    if limit < 1:
        limit = 1

    if limit > 1000:
        limit = 1000

    with engine.connect() as conn:

        result = conn.execute(text("""
            SELECT *
            FROM cases
            ORDER BY created_at DESC
            LIMIT :limit
        """), {
            "limit": limit
        })

        return jsonify([
            dict(row._mapping)
            for row in result
        ])


@app.route('/api/siem/events')
def api_siem_events():
    """Unified SIEM feed - alerts normalized into a single events envelope.

    NOTE: two small defensive fixes applied vs. the spec's literal code,
    both to match the guards /api/siem/alerts already uses on the exact
    same fields, since timestamp/evidence have no NOT NULL constraint
    in the schema:
      - event_time: guarded with `if event["timestamp"] else None`
        (spec called .isoformat() unguarded here, which would throw
        AttributeError on a NULL timestamp)
      - evidence: falls back to {} on NULL (spec passed it through
        directly here, unlike the /api/siem/alerts version above)
    """
    limit = request.args.get(
        'limit',
        100,
        type=int
    )

    if limit < 1:
        limit = 1

    if limit > 1000:
        limit = 1000

    with engine.connect() as conn:

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
            LIMIT :limit
        """), {
            "limit": limit
        })

        events = []

        for row in result:

            data = dict(
                row._mapping
            )

            evidence = data.get("evidence")

            if evidence is None:
                evidence = {}

            events.append({

                "event_id":
                    f"ITD-ALERT-{data['id']}",

                "event_type":
                    "security_alert",

                "event_time":
                    data["timestamp"].isoformat()
                    if data["timestamp"]
                    else None,

                "source":
                    "insider-threat-detection",

                "severity":
                    data["severity"],

                "status":
                    data["status"],

                "user_ip":
                    str(data["user_ip"]),

                "alert_type":
                    data["alert_type"],

                "description":
                    data["description"],

                "evidence":
                    evidence
            })

        return jsonify({
            "source":
                "insider-threat-detection",

            "event_count":
                len(events),

            "events":
                events
        })


if __name__ == '__main__':
    print("\n" + "="*50)
    print("FLASK DASHBOARD - INSIDER THREAT DETECTION")
    print("="*50)
    print("\n[*] Starting Flask server...")
    print("[*] Open your browser to: http://localhost:5000")
    print("[*] Press Ctrl+C to stop\n")

    app.run(debug=False, host='0.0.0.0', port=5000)
