#S
import psycopg2
from flask import Flask, request, Response

app = Flask(__name__)


@app.route("/export_applicants")
def export_applicants():
    """Export applicants whose IDs are provided as a CSV list.

    SQL injection vulnerability:
    - `ids` string is interpolated directly into an IN (...) clause.
    - Attackers can inject arbitrary subqueries or modify the WHERE clause.
    """
    ids = request.args.get("ids", "")  # e.g. "1,2,3"

    conn = psycopg2.connect(
        dbname="hr_portal", user="hr_user", password="hr_pass", host="localhost"
    )
    try:
        cur = conn.cursor()

        # VULNERABLE: `ids` pasted directly into IN list
        query = (
            "SELECT id, full_name, email, status "
            "FROM applicants WHERE id IN (" + ids + ")"
        )
        cur.execute(query)
        rows = cur.fetchall()

        lines = ["id,full_name,email,status"]
        for r in rows:
            lines.append(f"{r[0]},{r[1]},{r[2]},{r[3]}")
        csv_data = "\n".join(lines)

        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=applicants.csv"},
        )
    finally:
        conn.close()
