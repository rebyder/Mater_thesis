"""
Example 12 – Second-order SQL injection (Bug tracker comments)

This script first stores user comments, then later uses stored comments
to build a dynamic query for moderation. Unsafe data is used in a later
query, demonstrating second-order SQL injection.
"""

import sqlite3


def store_comment(issue_id: int, raw_comment: str) -> None:
    """Store a user comment as-is in the database."""
    conn = sqlite3.connect("bugs.db")
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO comments (issue_id, raw_text) VALUES (?, ?)",
            (issue_id, raw_comment),
        )
        conn.commit()
    finally:
        conn.close()


def moderate_comments(pattern: str) -> None:
    """Search previously stored comments using a dynamically built query.

    SQL injection vulnerability (second-order):
    - A malicious pattern might have been stored earlier via store_comment.
    - Here, `pattern` is concatenated into the WHERE clause, enabling injection
      when that pattern was user-controlled at insertion time.
    """
    conn = sqlite3.connect("bugs.db")
    try:
        cur = conn.cursor()

        # VULNERABLE: `pattern` used directly in LIKE; may have been stored from user input
        query = (
            "SELECT id, issue_id, raw_text FROM comments "
            "WHERE raw_text LIKE '%" + pattern + "%'"
        )
        print(f"[DEBUG] Executing: {query}")
        cur.execute(query)

        for row in cur.fetchall():
            print(row)
    finally:
        conn.close()


if __name__ == "__main__":
    # Example usage for demonstration, not secure.
    store_comment(1, input("Enter a comment for issue #1: "))
    search = input("Enter pattern for moderation search: ")
    moderate_comments(search)
