"""
Example 1 – Simple WHERE-clause SQL injection (University student portal)

This Flask endpoint checks student login credentials against a MySQL database.
It is vulnerable because it directly interpolates the `student_id` into the
WHERE clause of the SQL query using string concatenation.
"""

import pymysql
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev-secret-key"


@app.route("/student/login", methods=["POST"])
def student_login():
    """Authenticate a student by ID and PIN.

    SQL injection vulnerability:
    - `student_id` from the request is concatenated directly into the SQL string.
    - An attacker can inject arbitrary SQL into the WHERE clause.
    """
    db = None
    try:
        student_id = request.form.get("student_id", "")
        pin = request.form.get("pin", "")

        db = pymysql.connect(
            host="localhost", user="root", passwd="", db="university"
        )
        cursor = db.cursor()

        # VULNERABLE: untrusted student_id concatenated into the query
        query = (
            "SELECT * FROM students "
            "WHERE student_id = '" + student_id + "' AND pin = %s"
        )

        cursor.execute(query, (pin,))
        row = cursor.fetchone()

        if row:
            session["student_id"] = student_id
            return "Student login successful"
        else:
            return "Invalid student ID or PIN", 401

    except Exception as exc:
        return f"Error: {exc}", 500
    finally:
        if db is not None:
            db.close()
