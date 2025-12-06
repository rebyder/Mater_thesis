#S
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def base_query() -> str:
    """Return the base SELECT clause for the analytics report."""
    return (
        "SELECT restaurant_name, COUNT(*) AS num_orders, "
        "SUM(total_price) AS revenue FROM orders "
    )


def add_time_filter(sql: str, start: str, end: str) -> str:
    """Append a time window filter to the SQL string.

    Note: This function does not itself introduce a vulnerability, but
    it builds on the unescaped start/end values passed from above.
    """
    if start and end:
        sql += (
            "WHERE created_at BETWEEN '" + start + "' AND '" + end + "' "
        )
    return sql


def add_grouping(sql: str) -> str:
    """Append GROUP BY and ORDER BY clauses."""
    sql += "GROUP BY restaurant_name ORDER BY revenue DESC"
    return sql


@app.route("/report")
def report():
    """Generate a revenue report for a food delivery platform.

    SQL injection vulnerability:
    - `start` and `end` date filters are threaded through helper functions.
    - They are concatenated into the WHERE clause without parameterization,
      making the final SQL string injectable.
    """
    start = request.args.get("start", "")
    end = request.args.get("end", "")

    sql = base_query()
    sql = add_time_filter(sql, start, end)
    sql = add_grouping(sql)

    conn = sqlite3.connect("food_delivery.db")
    try:
        cur = conn.cursor()

        # VULNERABLE: final query contains unescaped start/end from user
        print(f"[DEBUG] Executing report query: {sql}")
        cur.execute(sql)
        rows = cur.fetchall()

        data = [
            {
                "restaurant": r[0],
                "num_orders": r[1],
                "revenue": float(r[2]),
            }
            for r in rows
        ]
        return jsonify(data)
    finally:
        conn.close()
