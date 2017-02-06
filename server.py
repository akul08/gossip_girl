from gevent import monkey
monkey.patch_all()

import datetime
import time
from threading import Thread
import functools
import os
from bson import ObjectId

from flask import Flask, render_template, request, redirect
from flask import flash, session, url_for
from flask_login import current_user, LoginManager
from flask_login import login_user, logout_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_pymongo import PyMongo, pymongo
from flask_bcrypt import Bcrypt
from forms import LoginForm, RegisterForm, UpdateForm
from models import User

app = Flask(__name__)
app.config.from_object('config')

url = os.getenv('MONGOLAB_URI', 'mongodb://localhost:27017')
app.config['MONGO_URI'] = url

mongo = PyMongo(app)
socketio = SocketIO(app, async_mode='gevent')
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

thread = None
# list of rooms
all_rooms = ['suits', 'flash', 'game_of_thrones',
             'impractical_jokers', 'gossip_girl', 'sherlock']


def authenticated_only(f):
    # decorator to allow authenticated user only
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
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


@app.route('/')
@authenticated_only
def index():
    username = mongo.db.users.find_one(
        {'_id': ObjectId(current_user.get_id())})['name']
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
                user_obj = User(str(user['_id']))
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
        users = mongo.db.users
        existing_user_name = users.find_one({'name': form.username.data})
        if existing_user_name is None:
            hashpass = bcrypt.generate_password_hash(form.password.data)
            users.insert({'name': form.username.data,
                          'password': hashpass,
                          'rooms': []})
            session['username'] = form.username.data
            return redirect(url_for('index'))

        flash('Username already exists')
        return render_template('register.html', form=form)
    return render_template('register.html', form=form)


@app.route('/logout')
@authenticated_only
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/rooms')
@authenticated_only
def rooms():
    # get the list of rooms that user is following and render on rooms.html
    user_rooms = mongo.db.users.find_one(
        {'_id': ObjectId(current_user.get_id())})['rooms']
    all_rooms_dict = {k: 1 if k in user_rooms else 0 for k in all_rooms}
    return render_template('rooms.html', all_rooms_dict=all_rooms_dict)


@app.route('/follow/<room>/<goto_rooms>')
@authenticated_only
def follow(room, goto_rooms=False):
    # update the db rooms and include the specified room
    mongo.db.users.update({'_id': ObjectId(current_user.get_id())},
                          {'$addToSet': {'rooms': room}})
    if goto_rooms:
        # goto_rooms is set True if the link is open from header url
        flash('Started following: ' + room)
        return redirect(url_for('rooms'))
    return 'Success'


@app.route('/unfollow/<room>/<goto_rooms>')
@authenticated_only
def unfollow(room, goto_rooms=False):
    # update the db rooms and exclude the specified room
    mongo.db.users.update({'_id': ObjectId(current_user.get_id())},
                          {'$pull': {'rooms': room}})
    if goto_rooms:
        # goto_rooms is set True if the link is open from header url
        flash('Unfollowing: ' + room)
        return redirect(url_for('rooms'))
    return 'Success'


@app.route('/notifs')
@authenticated_only
def notifs():
    start_notifs()
    return render_template('notifs.html')


@app.route('/allnotifs')
@authenticated_only
def allnotifs():
    start_notifs()
    return render_template('allnotifs.html')


@app.route('/updatedb', methods=['GET', 'POST'])
@authenticated_only
def updatedb():
    # form to send notifications and update db
    form = UpdateForm()
    form.room.choices = zip(all_rooms, all_rooms)
    if form.validate_on_submit():
        mongo.db.rooms.insert({'room': form.room.data,
                               'update': form.update.data,
                               'ts': datetime.datetime.now()})
        flash('Message sent!')
        return redirect(url_for('updatedb'))
    return render_template('updatedb.html', form=form)


def start_notifs():
    # create a capped db and start tailing it for any updates in the background
    global thread
    try:
        mongo.db.create_collection('rooms', capped=True, size=100000)
        mongo.db.rooms.insert({'room': 'test',
                               'update': 'test',
                               'ts': datetime.datetime.now()})
    except pymongo.errors.CollectionInvalid, e:
        pass
    last_id = mongo.db.rooms.find().sort('$natural', -1).limit(1).next()
    if thread is None:
        # create a thread to work in background
        thread = Thread(target=background_task, args=[last_id])
        thread.start()
        socketio.emit('my_response',
                      {'data': 'Started Notifications'},
                      namespace='/notifs')


def background_task(last_id):
    ts = last_id['ts']
    # find the last added entry and tail each new entry being updated
    with app.app_context():
        cursor = mongo.db.rooms.find({'ts': {'$gt': ts}},
                                     cursor_type=pymongo.
                                     CursorType.TAILABLE_AWAIT,
                                     oplog_replay=True)
        cursor = cursor.hint([('$natural', 1)])
        while cursor.alive:
            try:
                # on new entry send the data to notifications
                record = cursor.next()
                str_record = '''<span class="notification-msg">
                                    <span class="bold">%s</span>:
                                    %s <span class="ts">[%s]</span>
                                </span>'''
                response = str_record % (record['room'], record['update'],
                                         record['ts']
                                         .strftime("%Y-%m-%d %H:%M:%S"))
                socketio.emit('my_response',
                              {'data': response}, namespace='/notifs',
                              room=record['room'])
                socketio.emit('my_response',
                              {'data': response}, namespace='/allnotifs')
            except StopIteration:
                socketio.sleep(1)


@socketio.on('connect', namespace='/notifs')
def test_connect():
    # send subscribed notifications
    print 'Connected'
    emit('my_response', {'data': 'Connected'})


@socketio.on('joined', namespace='/notifs')
def joined(message):
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.get_id())})
    # use socketio room feature to send notifications to those who are
    # following the specified room
    for room in user['rooms']:
        join_room(room)
        emit('my_response',
             {'data': '<span class="username-join">' + user['name'] +
              '</span>' + ' Joined ' + room},
             room=room)


@socketio.on('left', namespace='/notifs')
def left(message):
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.get_id())})
    # use socketio room feature to send notifications to those who are
    # following the specified room
    for room in user['rooms']:
        leave_room(room)
        emit('my_response',
             {'data': '<span class="username-left">' + user['name'] +
              '</span>' + ' Left ' + room},
             room=room)


@socketio.on('connect', namespace='/allnotifs')
def test_connect():
    # send all notifications
    print 'Connected'
    emit('my_response', {'data': 'Connected'})


@socketio.on('joined', namespace='/allnotifs')
def joined(message):
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.get_id())})
    emit('my_response',
         {'data': '<span class="username-join">' + user['name'] +
          '</span>' + ' Joined'})


@socketio.on('left', namespace='/allnotifs')
def left(message):
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.get_id())})
    emit('my_response',
         {'data': '<span class="username-left">' + user['name'] +
          '</span>' + ' Left'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
