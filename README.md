# Gossip Girl
## A Real Time notification system task for SocialCops

#### Problem Task: Create a real time notification system to notify subscribers about the changes in the MongoDB database.
[Link](https://drive.google.com/file/d/0B2wvr5gjqmj3U2Q0ZXhHS0JUMkk/view?usp=sharing) to complete task.

#### Solution:
Due to lack of knowledge about Gossip Girl and their characters, I have updated the task to notify us about the updates of various TV shows instead of characters of Gossip Girl.

#### Tech Stack: Web app = Flask + Heroku + SocketIO + MongoDB/MongoLab

#### Steps to run app:

 - Clone the repo and `cd` into it

 - Setup virtualenv: `virtualenv venv`

 - Activate virtualenv: `source venv/bin/activate`

 - Install required libraries: `pip install -r requirements.txt`

 - Run the MongoDB server: `mongod`

 - Run the flask server: `python server.py`


#### Screenshots and how to use it:

![login](static/img/1.png?raw=true)
- First Register and Login:
    username: `akul`
    password: `1234`

![index](static/img/2.png?raw=true)

- Then Goto `/Rooms` and subscribe to your favourite TV Shows
![rooms](static/img/3.png?raw=true)

- Goto `/Notification` for real time subscribed Notifications, notifications of not subscribed TV shows are not shown here.
![notifs](static/img/4.png?raw=true)

- Goto `/All Notifs` for real time Notifications for all TV shows
![all notifs](static/img/5.png?raw=true)

- Open `/Update DB` in new tab and send an update for a TV show to MongoDB. This is inserted in the MongoDB db and a notification is sent to `/Notifications` if subscribed and `/All Notifs` in real time via SocketIO.
![updatedb](static/img/6.png?raw=true)

- Notification about update on Flash TV show is sent to both `/Notifications` and `/All Notifs`.
![notifs & all notifs](static/img/7.png?raw=true)

- Again sending Notification about `Game of Thrones` which is not subscribed by `akul`
![updatedb again](static/img/8.png?raw=true)

- On Sending notification about `Game of Thrones`, only `/All Notifs` will receive as `akul` is not following `Game of Thrones` and hence no notification in `/Notifications`
![notifs & all notifs again](static/img/9.png?raw=true)

- `Logout` and Exit the program

#### Resources:

- [The Mega Flask tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)

- [SocketIO for Flask for Real time connection and exchange of Data](flask-socketio.readthedocs.io)

- [Pub/Sub pattern & notification on MongoDB updates](http://blog.pythonisito.com/2013/04/mongodb-pubsub-with-capped-collections.html)
