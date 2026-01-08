"""
Example 3 – UNION-based SQL injection (E-commerce product search)

This Flask endpoint allows users to search products by keyword.
It is vulnerable because the search term is interpolated into the SQL query,
enabling UNION-based attacks to extract other data from the database.
"""

import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/search")
def search_products():
    """Search for products by keyword.

    SQL injection vulnerability:
    - `q` is injected into a LIKE clause using f-strings.
    - An attacker can close the string and append a UNION SELECT payload.
    """
    q = request.args.get("q", "")

    conn = psycopg2.connect(
        dbname="shop",
        user="shop_user",
        password="shop_pass",
        host="localhost",
        port=5432,
    )
    try:
        cur = conn.cursor()

        # VULNERABLE: unescaped `q` directly in f-string
        query = (
            f"SELECT id, name, price FROM products "
            f"WHERE name ILIKE '%{q}%' AND is_active = TRUE"
        )
        cur.execute(query)
        rows = cur.fetchall()

        results = [
            {"id": r[0], "name": r[1], "price": float(r[2])}
            for r in rows
        ]
        return jsonify(results)
    finally:
        conn.close()
