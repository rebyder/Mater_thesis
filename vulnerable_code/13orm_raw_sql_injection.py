"""
Example 13 – ORM raw SQL injection (Event ticket booking system)

This Django view uses the ORM infrastructure but drops down to raw SQL
for a complex query. It is vulnerable because it concatenates user input
into the raw SQL string.
"""

from django.http import JsonResponse
from django.db import connection
from django.views.decorators.http import require_GET


@require_GET
def search_bookings(request):
    """Search event bookings by free-text reference.

    SQL injection vulnerability:
    - `ref` is concatenated into a raw SQL query.
    - Using Django's `connection.cursor()` and raw SQL circumvents ORM protections.
    """
    ref = request.GET.get("ref", "")

    with connection.cursor() as cursor:
        # VULNERABLE: unescaped ref parameter in raw SQL
        sql = (
            "SELECT id, user_email, event_name, status "
            "FROM ticket_bookings "
            "WHERE booking_reference LIKE '%" + ref + "%'"
        )
        cursor.execute(sql)
        rows = cursor.fetchall()

    data = [
        {"id": r[0], "user_email": r[1], "event_name": r[2], "status": r[3]}
        for r in rows
    ]
    return JsonResponse(data, safe=False)
