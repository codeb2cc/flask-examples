# -*- coding:utf-8 -*-
"""
    Flaskr (MongoDB Version)
    ~~~~~~~~~~~~~~~~~~~~~~~~

    A microblog example application written as Flask tutorial with
    Flask, MongDB and MongoEngine.
"""

from contextlib import closing
from flask import Flask, request, session, g, redirect, url_for, abort, \
        render_template, flash
import mongoengine

from models import Entry

# Configuration
USERNAME = 'admin'
PASSWORD = 'admin'
SECRET_KEY = 'flaskr secret key'    # Session requirement

# Create application
app = Flask(__name__)
app.config.from_object(__name__)
#app.config.from_envvar('FLASKR_SETTINGS', silent=True)

def connect_db(db_name='flaskr'):
    """Connect to MongoDB"""
    mongoengine.connect(db_name,
            host = '127.0.0.1',
            port = 27017,
            username = None,
            password = None
        )

@app.route('/')
def show_entries():
    entries = [dict(title=entry.title, text=entry.text) \
            for entry in Entry.objects]
    return render_template('show_entries.html', entries=entries)

@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)

    entry = Entry(
            title = request.form['title'],
            text = request.form['text']
        )
    entry.save()

    flash('New entry was successfully posted')

    return redirect(url_for('show_entries'))

@app.route('/login', methods=['GET', 'POST', ])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid Username'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid Password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('show_entries'))

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('show_entries'))

if __name__ == '__main__':
    connect_db()
    app.run()
