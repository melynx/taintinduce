import functools

from flask import Blueprint, flash, redirect, render_template, request, session, url_for, g

from worker_client import get_worker

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    worker = get_worker()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'

        uid = worker.create_user(username, password)
        if error is None and uid:
            return redirect(url_for('auth.login'))
        flash(error)
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    worker = get_worker()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        session_id = worker.login_user(username, password)
        if session_id:
            session.clear
            session['user_session_id'] = session_id
            return redirect(url_for('index'))

        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    worker = get_worker()
    user_id = session.get('user_session_id')
    username = 'czl'

    if user_id is None:
        g.user = None
    else:
        g.user = username

@bp.route('/logout')
def logout():
    worker = get_worker()
    user_id = session.get('user_session_id')
    worker.logout_user(user_id)
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view
