"""
Example 7 – Stacked query SQL injection (Inventory admin tool)

This CLI tool allows an admin to adjust product stock levels.
It is vulnerable because the `product_id` is concatenated into the WHERE clause
inside a driver that permits multiple statements, enabling stacked queries.
"""

import pymysql


def adjust_stock(product_id: str, delta: int) -> None:
    """Adjust stock for a product by a positive or negative delta.

    SQL injection vulnerability:
    - `product_id` is interpolated directly into the statement.
    - On drivers that allow multi-statements, attackers can append `; DROP TABLE` etc.
    """
    conn = pymysql.connect(
        host="localhost",
        user="root",
        password="",
        db="inventory",
        client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS,
    )
    try:
        cur = conn.cursor()

        # VULNERABLE: product_id directly concatenated, allowing stacked queries
        query = (
            "UPDATE products SET stock = stock + %s WHERE id = "
            + product_id
        )
        cur.execute(query, (delta,))
        conn.commit()
        print("Stock updated.")
    finally:
        conn.close()


if __name__ == "__main__":
    pid = input("Product ID to adjust: ")
    diff = int(input("Change in stock (e.g. -5, 10): "))
    adjust_stock(pid, diff)
