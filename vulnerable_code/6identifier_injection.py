"""
Example 6 – Identifier (table/column) SQL injection (Multi-tenant analytics)

This Flask endpoint lets an admin query different tenant metrics tables.
It is vulnerable because the `dataset` parameter is used directly as a table
name, allowing injection of arbitrary identifiers and SQL.
"""

import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/metrics")
def get_metrics():
    """Fetch aggregated metrics from a dynamically chosen table.

    SQL injection vulnerability:
    - `dataset` is interpolated into the FROM clause as a table name.
    - Attackers can choose arbitrary tables or inject further SQL.
    """
    dataset = request.args.get("dataset", "visits")

    conn = psycopg2.connect(
        dbname="analytics",
        user="analytics_user",
        password="secret",
        host="localhost",
    )
    try:
        cur = conn.cursor()

        # VULNERABLE: dataset used directly as identifier
        query = (
            f"SELECT date, total_users, active_users "
            f"FROM tenant_{dataset}_daily_summary "
            f"ORDER BY date DESC LIMIT 30"
        )

        cur.execute(query)
        rows = cur.fetchall()
        return jsonify(
            [
                {
                    "date": str(r[0]),
                    "total_users": r[1],
                    "active_users": r[2],
                }
                for r in rows
            ]
        )
    finally:
        conn.close()
