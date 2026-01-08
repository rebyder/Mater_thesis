"""
Example 4 – ORDER BY SQL injection (Crowdsourcing taxi app)

This FastAPI endpoint lists nearby drivers sorted by criteria.
It is vulnerable because the `sort` parameter is interpolated into the ORDER BY
clause, allowing attackers to inject arbitrary SQL fragments.
"""

from fastapi import FastAPI, Query
import mysql.connector

app = FastAPI()


@app.get("/drivers")
def list_drivers(sort: str = Query("rating")):
    """List available drivers sorted by the requested field.

    SQL injection vulnerability:
    - `sort` is used directly in an ORDER BY clause via string formatting.
    - Attackers can inject expressions like `rating DESC; DROP TABLE drivers`.
    """
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="taxi_app",
    )
    try:
        cur = conn.cursor(dictionary=True)

        base = "SELECT id, name, rating, completed_trips FROM drivers WHERE online = 1"

        # VULNERABLE: ORDER BY field fully controlled by client
        query = f"{base} ORDER BY {sort}"
        cur.execute(query)
        rows = cur.fetchall()
        return rows
    finally:
        conn.close()
