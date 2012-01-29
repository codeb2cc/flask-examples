# -*- coding:utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~

    A microblogging application written with Flask and MongoDB.
"""

from hashlib import md5
from datetime import datetime

from flask import Flask, request, session, url_for, redirect, \
        render_template, abort, g, flash
from werkzeug import check_password_hash, generate_password_hash
import mongoengine

from models import User, Message

# Configuration
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'minitwit secret key'

# Create application
app = Flask(__name__)
app.config.from_object(__name__)
#app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

def connect_db(db_name='minitwit'):
    """Connect to MongoDB"""
    mongoengine.connect(db_name,
            host = '127.0.0.1',
            port = 27017,
            username = None,
            password = None
        )

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return timestamp.strftime('%Y-%m-%d @ %H:%M')

def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
            (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

@app.before_request
def before_request():
    """Look up the current user"""
    g.user = None
    if 'user_id' in session:
        g.user = User.objects.with_id(session['user_id'])

@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline. This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    users = [u.username for u in g.user.followers] or []
    users.append(g.user.username)
    messages = Message.objects.filter(author__in=users)\
            .order_by('-pub_date').limit(PER_PAGE)
    return render_template('timeline.html', messages=messages)

@app.route('/public')
def public_timeline():
    """Display the latest messages of all users."""
    messages = Message.objects.limit(PER_PAGE)
    return render_template('timeline.html', messages=messages)

@app.route('/<username>')
def user_timeline(username):
    """Display a users tweets."""
    try:
        profile_user = User.objects.filter(username__exact=username).get()
    except User.DoesNotExist:
        abort(404)

    followed = False
    if g.user:
        followed = profile_user in g.user.followers or None
    messages = Message.objects.filter(author__exact=username)\
        .order_by('-pub_date').limit(PER_PAGE)
    return render_template('timeline.html',
            messages = messages,
            followed = followed,
            profile_user = profile_user
        )

@app.route('/<username>/follow')
def follow_user(username):
    """Add the current user as follower of the given user."""
    if not g.user:
        abort(401)
    if not len(User.objects.filter(username__exact=username)):
        abort(404)

    # Update relation
    user = User.objects.filter(username__exact=username).get()
    User.objects.filter(username__exact=username).\
            update_one(add_to_set__followees=g.user)
    User.objects.filter(username__exact=g.user.username).\
            update_one(add_to_set__followers=user)

    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))

@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Remove the current as follower of the given user."""
    if not g.user:
        abort(401)
    if not len(User.objects.filter(username__exact=username)):
        abort(404)

    # Update relation
    user = User.objects.filter(username__exact=username).get()
    User.objects.filter(username__exact=username).\
            update_one(pull__followees=g.user)
    User.objects.filter(username__exact=g.user.username).\
            update_one(pull__followers=user)

    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))

@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        # Save message
        message = Message(
                author = g.user.username,
                text = request.form['text'],
                pub_date = datetime.now()
            )
        message.save()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))

@app.route('/login', methods=['GET', 'POST', ])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        try:
            user = User.objects.filter(username__exact=request.form['username']).get()
            if not check_password_hash(user.pw_hash, request.form['password']):
                error = 'Invalid Password'
            else:
                flash('You were logged in')
                session['user_id'] = user.id
                return redirect(url_for('timeline'))
        except User.DoesNotExist:
            error = 'Invalid Username'

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Log the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))

@app.route('/register', methods=['GET', 'POST', ])
def register():
    """Register the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif len(User.objects.filter(username__exact=request.form['username'])):
            error = 'The username is already taken'
        else:
            # Register user
            user = User(
                    username = request.form['username'],
                    email = request.form['email'],
                    pw_hash = generate_password_hash(request.form['password']),
                )
            user.save()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

# Add filters
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

if __name__ == '__main__':
    connect_db()
    app.run()
    app.run()
    app.run()
