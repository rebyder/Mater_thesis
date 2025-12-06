#X
from flask import Flask, request, g
import sqlite3
app = Flask(__name__)

DB = 'ecom.db'
def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        db.execute('CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, description TEXT)')
    return db

@app.route('/add_product', methods=['POST'])
def add_product():
    name = request.form.get('name')
    desc = request.form.get('desc',
    '')
    db = get_db()
    db.execute('INSERT INTO products(name, description) VALUES(?, ?)', (name,
    desc))
    db.commit()
    return 'Product added'


@app.route('/product/<int:pid>')
def product_page(pid):
    db = get_db()
    row = db.execute('SELECT name, description FROM products WHERE id=?', (pid,)).fetchone()
    if not row:
        return 'Not found', 404
    name, desc = row
    # INSECURE: description added to HTML directly (may contain HTML/JS)
    return f'<h1>{name}</h1><div class="desc">' + desc + '</div>'

if __name__ == '__main__':
    app.run()