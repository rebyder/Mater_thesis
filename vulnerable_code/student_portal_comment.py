#X
from flask import Flask, request, g

import sqlite3
app = Flask(__name__)
DB = 'students.db'

def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        db.execute('CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY, text TEXT)')
        return db
    

@app.route('/announce', methods=['POST'])
def post_announcement():
    text = request.form.get('text',
    '')
    db = get_db()
    db.execute('INSERT INTO announcements(text) VALUES(?)', (text,))
    db.commit()
    return 'Posted', 201


@app.route('/announcements')
def show_announcements():
    db = get_db()
    rows = db.execute('SELECT id, text FROM announcements').fetchall()
    # INSECURE: directly concatenate announcement text into HTML
    html = '<h1>Announcements</h1>\n'
    for r in rows:
        html += f"<div class=announcement id=ann{r[0]}>" + r[1] + "</div>\n"
    return html

if __name__ == '__main__':
    app.run(debug=True)