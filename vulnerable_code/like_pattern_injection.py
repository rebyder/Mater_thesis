#S
from django.http import JsonResponse
from django.db import connection


def search_books(request):
    """Search books by free-text query.

    SQL injection vulnerability:
    - `q` is concatenated into a LIKE clause inside raw SQL.
    - An attacker can break out of the string or control wildcards.
    """
    q = request.GET.get("q", "")

    with connection.cursor() as cursor:
        # VULNERABLE: unescaped search term in LIKE pattern
        sql = (
            "SELECT id, title, author FROM books "
            "WHERE title LIKE '%" + q + "%' "
            "   OR author LIKE '%" + q + "%' "
            "ORDER BY title ASC"
        )
        cursor.execute(sql)
        rows = cursor.fetchall()

    data = [{"id": r[0], "title": r[1], "author": r[2]} for r in rows]
    return JsonResponse(data, safe=False)
