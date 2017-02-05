from flask import Flask, render_template, request, redirect
from flask import flash, session, url_for
from flask_login import current_user, LoginManager, UserMixin
from flask_login import login_user, logout_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_pymongo import PyMongo, pymongo
from flask_bcrypt import Bcrypt
from forms import LoginForm, RegisterForm, UpdateForm
from bson import ObjectId
import datetime
import time
from threading import Thread
from models import User
import functools
import os
from gevent import monkey
monkey.patch_all(thread=False)


app = Flask(__name__)
app.config.from_object('config')
# app.config['MONGO_DBNAME'] = ''
# app.config['MONGO_URI'] = ''
app.config['SECRET_KEY'] = 'secret!'

mongo = PyMongo(app)
socketio = SocketIO(app, async_mode='gevent')
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

thread = None
all_rooms = ['suits', 'flash', 'game_of_thrones',
             'impractical_jokers', 'gossip_girl', 'sherlock']


def background_check(last_id):
    print '*' * 20
    ts = last_id['ts']
    with app.app_context():
        mongo.db.new.insert({'x': 'yayaya', 'ts': datetime.datetime.now()})
        cursor = mongo.db.new.find({'ts': {'$gt': ts}},
                                   cursor_type=pymongo.
                                   CursorType.TAILABLE_AWAIT,
                                   oplog_replay=True)
        cursor = cursor.hint([('$natural', 1)])
        while cursor.alive:
            try:
                record = cursor.next()
                print record
                socketio.emit(
                    'my_response', {'data': str(record)}, namespace='/notifs')
            except StopIteration:
                print 'waiting'
                # socketio.emit(
                #     'my_response', {'data': 'waiting'}, namespace='/notifs')
                socketio.sleep(1)
    print '*' * 20
    print 'Thread finished'


def authenticated_only(f):
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
    user_rooms = mongo.db.users.find_one(
        {'_id': ObjectId(current_user.get_id())})['rooms']
    all_rooms_dict = {k: 1 if k in user_rooms else 0 for k in all_rooms}
    # return 'hi'
    return render_template('rooms.html', all_rooms_dict=all_rooms_dict)


@app.route('/follow/<room>/<goto_rooms>')
@authenticated_only
def follow(room, goto_rooms=False):
    mongo.db.users.update({'_id': ObjectId(current_user.get_id())},
                          {'$addToSet': {'rooms': room}})

    print mongo.db.users.find_one(
        {'_id': ObjectId(current_user.get_id())})['rooms']
    if goto_rooms:
        flash('Started following: ' + room)
        return redirect(url_for('rooms'))
    return 'Success'


@app.route('/unfollow/<room>/<goto_rooms>')
@authenticated_only
def unfollow(room, goto_rooms=False):
    mongo.db.users.update({'_id': ObjectId(current_user.get_id())},
                          {'$pull': {'rooms': room}})
    print mongo.db.users.find_one(
        {'_id': ObjectId(current_user.get_id())})['rooms']
    if goto_rooms:
        flash('Unfollowing: ' + room)
        return redirect(url_for('rooms'))
    return 'Success'


@app.route('/inroom/<room>')
@authenticated_only
def inroom(room):
    if mongo.db.users.find({'_id': ObjectId(current_user.get_id()),
                            'rooms': room}).count():
        return 'yes in room: ' + room
    return 'Not in room: ' + room


@app.route('/notifs')
def notifs():
    return render_template('notifs.html')


@app.route('/updatedb', methods=['GET', 'POST'])
@authenticated_only
def updatedb():
    form = UpdateForm()
    if form.validate_on_submit():
        # rooms = mongo.db.rooms
        # room = rooms.find_one({'name': form.room.data})
        # if room:
        #     room_id = str(room['_id'])
        #     rooms.update({'_id': ObjectId(room_id)},
        #                  {'$addToSet':
        #                   {'status': {'status_update': form.update.data,
        #                               'timestamp': datetime.datetime.now()}}})
        #     flash('Message sent!')
        # else:
        #     # mongo.db.create_collection(rooms)

            # rooms.insert({'name': form.room.data,
            #               'status': [{'status_update': form.update.data,
            #                           'timestamp': datetime.datetime.now()}]})
            # # flash('Room doesn\'t exists\nCreated Room & sent mssg')
        mongo.db.new.insert(
            {'x': form.room.data, 'ts': datetime.datetime.now()})
        return render_template('updatedb.html', form=form)
    return render_template('updatedb.html', form=form)


@app.route('/create')
@authenticated_only
def create():
    global thread
    try:
        mongo.db.create_collection('new', capped=True, size=100000)
    except pymongo.errors.CollectionInvalid, e:
        print 'Error is this: ', e
    last_id = mongo.db.new.find().sort('$natural', -1).limit(1).next()

    if thread is None:
        thread = Thread(target=background_check, args=[last_id])
        thread.start()
        socketio.emit(
            'my_response', {'data': 'this func finished'}, namespace='/notifs')

    return 'success'


@socketio.on('connect', namespace='/notifs')
def test_connect():
    print '*' * 20
    print 'Connected'
    emit('my_response', {'data': 'Connected'})


@socketio.on('joined', namespace='/notifs')
def joined(message):
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.get_id())})

    for room in user['rooms']:
        join_room(room)
        # emit('my_response', {'data': 'Joined ' + room})
        emit('my_response',
             {'data': user['name'] + ' Joined ' + room},
             room=room)


@socketio.on('left', namespace='/notifs')
def left(message):
    user = mongo.db.users.find_one({'_id': ObjectId(current_user.get_id())})
    for room in user['rooms']:
        leave_room(room)
        emit('my_response',
             {'data': user['name'] + ' Left ' + room},
             room=room)


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
