from flask import Flask, render_template, request, redirect
from flask import flash, session, url_for
from flask_login import current_user, LoginManager, UserMixin
from flask_login import login_user, logout_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from forms import LoginForm, RegisterForm
from bson import ObjectId

from models import User
import functools
import os


app = Flask(__name__)
app.config.from_object('config')
# app.config['MONGO_DBNAME'] = ''
# app.config['MONGO_URI'] = ''
app.config['SECRET_KEY'] = 'secret!'

mongo = PyMongo(app)
socketio = SocketIO(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)


def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        # print '*' * 20, current_user
        if not current_user.is_authenticated:
            print 'not authenticated_only'
            return redirect(url_for('login'))
        else:
            return f(*args, **kwargs)
    return wrapped


@login_manager.user_loader
def load_user(user_id):
    u = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not u:
        return None
    return User(u['_id'])


def ack():
    print 'message was received!'


@app.route('/')
@authenticated_only
def index():
    if 'username' in session:
        username = session['username']
    else:
        username = None
    return render_template('index.html', username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        session.pop('user', None)
        users = mongo.db.users
        user = users.find_one({'name': form.username.data})

        if user:
            if bcrypt.check_password_hash(user['password'],
                                          form.password.data):
                # session['username'] = form.username.data
                user_obj = User(str(user['_id']))
                print user_obj
                login_user(user_obj)
                flash('Login Successful')
                return redirect(url_for('index'))
            else:
                flash('Wrong Username or Password')
                return render_template('login.html', form=form)

        flash('Username not found!')
        return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if form.validate_on_submit():
        print form.username.data
        users = mongo.db.users
        existing_user_name = users.find_one({'name': form.username.data})
        if existing_user_name is None:
            hashpass = bcrypt.generate_password_hash(form.password.data)
            users.insert({'name': form.username.data,
                          'password': hashpass})
            session['username'] = form.username.data
            return redirect(url_for('index'))
        flash('Username already exists')

        return render_template('register.html', form=form)
    return render_template('register.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/success')
def success():
    return 'Success'


@socketio.on('connect')
def test_connect():
    emit('my response', {'data': 'Connected'}, callback=ack)


@socketio.on('message')
def handle_message(message):
    print('received message: ' + message)


@socketio.on('my event')
def my_event(message):
    print('Connected to', request.sid)
    print('received message from event: ', message)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
