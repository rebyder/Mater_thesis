#X
from flask import Flask, request, g
import sqlite3
app = Flask(__name__)

DB = 'hospital.db'
def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        db.execute('CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, patient_id TEXT, note TEXT)')
    return db

@app.route('/add_note', methods=['POST'])
def add_note():
    pid = request.form.get('patient_id')
    note = request.form.get('note',
    '')
    db = get_db()
    db.execute('INSERT INTO notes(patient_id, note) VALUES(?, ?)', (pid, note))
    db.commit()
    return 'OK'

@app.route('/patient/<pid>')
def view_patient(pid):
    db = get_db()
    rows = db.execute('SELECT note FROM notes WHERE patient_id=?', (pid,)).fetchall()
    html = f'<h2>Patient {pid} Notes</h2>\n'
    for (note,) in rows:
    # INSECURE: no escaping of note text
        html += '<div class="note">' + note + '</div>\n'
    return html

if __name__ == '__main__':
   app.run()