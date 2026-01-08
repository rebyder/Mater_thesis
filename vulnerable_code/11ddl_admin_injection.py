"""
Example 11 – DDL/admin SQL injection (CMS maintenance console)

This administrative script allows dropping or truncating content tables
from a CMS. It is vulnerable because the table name is taken from user
input and concatenated directly into a DDL statement.
"""

import sqlite3


def drop_or_truncate(table_name: str, mode: str) -> None:
    """Drop or truncate a table in the CMS database.

    SQL injection vulnerability:
    - `table_name` is used directly in DDL statements.
    - Attackers can inject additional DDL or target arbitrary tables.
    """
    conn = sqlite3.connect("cms.db")
    try:
        cur = conn.cursor()

        if mode == "drop":
            # VULNERABLE: unvalidated table name in DROP statement
            sql = "DROP TABLE " + table_name
        else:
            # VULNERABLE: unvalidated table name in DELETE statement
            sql = "DELETE FROM " + table_name

        print(f"[DEBUG] Executing: {sql}")
        cur.execute(sql)
        conn.commit()
        print("Operation completed.")
    finally:
        conn.close()


if __name__ == "__main__":
    name = input("Enter table name to manage: ")
    action = input("Enter 'drop' or 'truncate': ")
    drop_or_truncate(name, action)
