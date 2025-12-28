#S
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/feed")
def get_feed():
    """Return a page of posts for the current user.

    SQL injection vulnerability:
    - `page` and `page_size` are concatenated directly into LIMIT/OFFSET.
    - Attackers can inject extra clauses or large values to disrupt queries.
    """
    page = request.args.get("page", "1")
    page_size = request.args.get("page_size", "20")

    conn = sqlite3.connect("social.db")
    try:
        cur = conn.cursor()

        # VULNERABLE: numeric parameters concatenated into SQL
        offset = (int(page) - 1) * int(page_size)
        query = (
            "SELECT id, author, content FROM posts "
            "WHERE is_deleted = 0 "
            "ORDER BY created_at DESC "
            "LIMIT " + page_size + " OFFSET " + str(offset)
        )

        cur.execute(query)
        rows = cur.fetchall()
        posts = [
            {"id": r[0], "author": r[1], "content": r[2]}
            for r in rows
        ]
        return jsonify(posts)
    finally:
        conn.close()
