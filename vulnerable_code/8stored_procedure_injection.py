"""
Example 8 – Stored procedure SQL injection (Banking transaction history)

This Flask endpoint calls a stored procedure to fetch a customer's
transaction history. It is vulnerable because the account number is
inserted into a dynamic CALL statement.
"""

import mysql.connector
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/transactions")
def transactions():
    """Return transaction history for a given bank account.

    SQL injection vulnerability:
    - `account` is interpolated into a CALL statement using string formatting.
    - Attackers can inject extra arguments or terminate the call and append SQL.
    """
    account = request.args.get("account", "")

    conn = mysql.connector.connect(
        host="localhost",
        user="bank_user",
        password="bank_pass",
        database="banking",
    )
    try:
        cur = conn.cursor(dictionary=True)

        # VULNERABLE: dynamic stored procedure call
        call_sql = "CALL get_transactions_for_account('%s')" % account
        cur.execute(call_sql)
        rows = cur.fetchall()

        return jsonify(rows)
    finally:
        conn.close()
