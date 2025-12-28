#X
from flask import Flask, request, g
import sqlite3
app = Flask(__name__)

DB = 'taxi.db'
def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        db.execute('CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, driver_id TEXT, review TEXT)')
    return db

@app.route('/review', methods=['POST'])
def post_review():
    driver = request.form.get('driver')
    review = request.form.get('review',
    '')
    db = get_db()
    db.execute('INSERT INTO reviews(driver_id, review) VALUES(?, ?)',
    (driver, review))
    db.commit()
    return 'Thanks'


@app.route('/driver/<driver>')
def show_driver(driver):
    db = get_db()
    rows = db.execute('SELECT review FROM reviews WHERE driver_id=?',
    (driver,)).fetchall()
    html = f'<h1>Driver {driver}</h1>\n'
    for (review,) in rows:
        # INSECURE: placing raw review text into page
        html += '<p class="review">' + review + '</p>\n'
    return html

if __name__ == '__main__':
    app.run()