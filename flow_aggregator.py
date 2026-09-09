#!/usr/bin/env python3

from sqlalchemy import create_engine, text
from datetime import datetime

DB_CONNECTION = (
    "postgresql://threat_user:"
    "threat_pass_2024@localhost/"
    "insider_threat_db"
)

engine = create_engine(DB_CONNECTION)


class FlowAggregator:

    def aggregate_flows(self):

        print("[*] Building network flows...")

        query = """
        INSERT INTO network_flows
        (
            start_time,
            end_time,
            source_ip,
            destination_ip,
            destination_port,
            protocol,
            total_packets,
            total_bytes,
            duration_seconds
        )

        SELECT
            MIN(timestamp) as start_time,
            MAX(timestamp) as end_time,
            user_ip,
            destination_ip,
            destination_port,
            protocol,
            COUNT(*) as total_packets,
            SUM(bytes_transferred) as total_bytes,

            EXTRACT(
                EPOCH FROM
                MAX(timestamp) - MIN(timestamp)
            ) as duration_seconds

        FROM traffic_events

        GROUP BY
            user_ip,
            destination_ip,
            destination_port,
            protocol;
        """

        with engine.connect() as conn:

            conn.execute(text("DELETE FROM network_flows"))

            conn.execute(text(query))

            conn.commit()

        print("[✓] Flow aggregation complete")


if __name__ == "__main__":

    FlowAggregator().aggregate_flows()
