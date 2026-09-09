#!/usr/bin/env python3
# ============================================
# PROJECT 1: STEP 4 - TRAFFIC PARSER
# ============================================
# Parses captured packets and loads into database

import json
import sys
from datetime import datetime
from sqlalchemy import create_engine, text
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
import os

class TrafficParser:
    def __init__(self, db_connection_string):
        """Initialize database connection"""
        self.engine = create_engine(db_connection_string)
        print("[✓] Connected to PostgreSQL database")
    
    def parse_pcap_file(self, pcap_file):
        """Parse PCAP file using Scapy"""
        print(f"[*] Parsing PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            traffic_events = []
            
            for packet in packets:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = packet[IP].proto
                    packet_length = len(packet)
                    
                    # Extract port and protocol info
                    dst_port = None
                    proto_name = 'Other'
                    
                    if TCP in packet:
                        dst_port = packet[TCP].dport
                        proto_name = 'TCP'
                    elif UDP in packet:
                        dst_port = packet[UDP].dport
                        proto_name = 'UDP'
                    
                    event = {
                        'timestamp': datetime.now(),
                        'user_ip': src_ip,
                        'destination_ip': dst_ip,
                        'destination_port': dst_port,
                        'protocol': proto_name,
                        'bytes_transferred': packet_length,
                        'packet_count': 1
                    }
                    traffic_events.append(event)
            
            print(f"[✓] Extracted {len(traffic_events)} traffic events from PCAP")
            return traffic_events
        
        except FileNotFoundError:
            print(f"[!] PCAP file not found: {pcap_file}")
            return []
    
    def parse_json_traffic(self, json_file):
        """Parse JSON traffic file (for testing)"""
        print(f"[*] Parsing JSON traffic file: {json_file}")
        
        try:
            with open(json_file, 'r') as f:
                events = json.load(f)
            
            # Normalize timestamp format
            for event in events:
                if isinstance(event['timestamp'], str):
                    event['timestamp'] = datetime.fromisoformat(event['timestamp'])
            
            print(f"[✓] Loaded {len(events)} traffic events from JSON")
            return events
        
        except FileNotFoundError:
            print(f"[!] JSON file not found: {json_file}")
            return []
    
    def store_traffic_in_db(self, traffic_events):
        """Store traffic events in PostgreSQL"""
        if not traffic_events:
            print("[!] No traffic events to store")
            return
        
        print(f"[*] Storing {len(traffic_events)} traffic events in database...")
        
        try:
            df = pd.DataFrame(traffic_events)
            
            # Convert timestamp to proper format
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Write to database
            df.to_sql('traffic_events', self.engine, if_exists='append', index=False)
            
            print(f"[✓] Successfully stored {len(traffic_events)} events in database")
            
            # Print summary
            print("\n[*] Database Summary:")
            with self.engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT 
                        COUNT(*) as total_events,
                        COUNT(DISTINCT user_ip) as unique_users,
                        COUNT(DISTINCT destination_ip) as unique_destinations
                    FROM traffic_events
                """))
                row = result.fetchone()
                print(f"    Total events: {row[0]}")
                print(f"    Unique users: {row[1]}")
                print(f"    Unique destinations: {row[2]}")
        
        except Exception as e:
            print(f"[!] Error storing data: {str(e)}")
    
    def create_baseline(self):
        """Create baseline of normal behavior from historical data"""
        print("[*] Creating baseline of normal behavior...")
        
        try:
            with self.engine.connect() as conn:
                # Baseline rows are per (user_ip, destination_ip,
                # destination_port, protocol) - that's port_stats below,
                # and it's also what avg/max/std_bytes_per_hour are scoped to.
                #
                # normal_ports and unique_destinations need a WIDER scope
                # than that, or they collapse to a single trivial value:
                # if you aggregate "distinct ports" inside a group that's
                # already grouped by destination_port, there's only ever
                # one port in the group to aggregate. So:
                #   - dest_ports scopes to (user_ip, destination_ip, protocol)
                #     -> the full set of ports this user normally uses
                #        against this destination
                #   - user_reach scopes to (user_ip) only
                #     -> how many distinct destinations this user normally
                #        talks to at all
                # Both are joined back onto every port-level baseline row
                # for that user/destination/protocol.
                query = """
                    WITH port_stats AS (
                        SELECT
                            user_ip,
                            destination_ip,
                            destination_port,
                            protocol,
                            CAST(AVG(bytes_transferred) AS BIGINT) AS avg_bytes_per_hour,
                            CAST(MAX(bytes_transferred) AS BIGINT) AS max_bytes_per_hour,
                            STDDEV(bytes_transferred) AS std_bytes_per_hour
                        FROM traffic_events
                        WHERE timestamp > NOW() - INTERVAL '7 days'
                        GROUP BY user_ip, destination_ip, destination_port, protocol
                    ),
                    dest_ports AS (
                        SELECT
                            user_ip,
                            destination_ip,
                            protocol,
                            STRING_AGG(DISTINCT destination_port::TEXT, ',') AS normal_ports
                        FROM traffic_events
                        WHERE timestamp > NOW() - INTERVAL '7 days'
                        GROUP BY user_ip, destination_ip, protocol
                    ),
                    user_reach AS (
                        SELECT
                            user_ip,
                            COUNT(DISTINCT destination_ip) AS unique_destinations
                        FROM traffic_events
                        WHERE timestamp > NOW() - INTERVAL '7 days'
                        GROUP BY user_ip
                    )
                    INSERT INTO baselines
                    (
                        user_ip,
                        destination_ip,
                        destination_port,
                        protocol,
                        avg_bytes_per_hour,
                        max_bytes_per_hour,
                        std_bytes_per_hour,
                        typical_hours,
                        normal_ports,
                        unique_destinations
                    )
                    SELECT
                        ps.user_ip,
                        ps.destination_ip,
                        ps.destination_port,
                        ps.protocol,
                        ps.avg_bytes_per_hour,
                        ps.max_bytes_per_hour,
                        ps.std_bytes_per_hour,
                        '9-17',
                        dp.normal_ports,
                        ur.unique_destinations
                    FROM port_stats ps
                    JOIN dest_ports dp
                        ON ps.user_ip = dp.user_ip
                        AND ps.destination_ip = dp.destination_ip
                        AND ps.protocol = dp.protocol
                    JOIN user_reach ur
                        ON ps.user_ip = ur.user_ip
                    ON CONFLICT (user_ip, destination_ip, destination_port, protocol)
                    DO UPDATE SET
                        avg_bytes_per_hour = EXCLUDED.avg_bytes_per_hour,
                        max_bytes_per_hour = EXCLUDED.max_bytes_per_hour,
                        std_bytes_per_hour = EXCLUDED.std_bytes_per_hour,
                        normal_ports = EXCLUDED.normal_ports,
                        unique_destinations = EXCLUDED.unique_destinations,
                        updated_at = CURRENT_TIMESTAMP
                """
                conn.execute(text(query))
                conn.commit()
                
                print("[✓] Baseline created successfully")
        
        except Exception as e:
            print(f"[!] Error creating baseline: {str(e)}")

if __name__ == '__main__':
    # Database connection string
    DB_CONNECTION = "postgresql://threat_user:threat_pass_2024@localhost/insider_threat_db"
    
    parser = TrafficParser(DB_CONNECTION)
    
    # Check if PCAP file exists, otherwise use JSON
    if os.path.exists('data/traffic_capture.pcap'):
        events = parser.parse_pcap_file('data/traffic_capture.pcap')
    else:
        # Use generated sample data
        if not os.path.exists('data/sample_traffic.pcap'):
            print("[!] No traffic data found. Run: python3 data_collector.py --simulate")
            sys.exit(1)
        events = parser.parse_json_traffic('data/sample_traffic.pcap')
    
    # Store in database
    parser.store_traffic_in_db(events)
    
    # Create baseline
    parser.create_baseline()
    
    print("\n[✓] Traffic parsing complete!")
