"""
Example 14 – Platform-specific function SQL injection (Log export tool)

This script uses PostgreSQL's COPY command to export query results.
It is vulnerable because the filter value is embedded directly into a
WHERE clause, which is then passed to COPY.
"""

import psycopg2


def export_logs(level: str):
    """Export application logs with a given level to a CSV file.

    SQL injection vulnerability:
    - `level` is concatenated into a WHERE clause in the COPY query.
    - Attackers can inject arbitrary SQL into the COPY statement.
    """
    conn = psycopg2.connect(
        dbname="logs_db", user="logs_user", password="logs_pass", host="localhost"
    )
    try:
        cur = conn.cursor()

        # VULNERABLE: `level` directly in WHERE clause
        query = (
            "COPY ("
            "SELECT timestamp, level, message "
            "FROM app_logs WHERE level = '" + level + "'"
            ") TO STDOUT WITH CSV HEADER"
        )

        with open("logs_export.csv", "w", encoding="utf-8") as f:
            cur.copy_expert(query, f)
        print("Logs exported.")
    finally:
        conn.close()


if __name__ == "__main__":
    lvl = input("Enter log level to export (e.g. INFO, ERROR): ")
    export_logs(lvl)
