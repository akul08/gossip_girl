from flask import Flask
from flask_socketio import SocketIO

app = Flask(__name__)
app.config.from_object('config')


from app import views, models, forms

socketio = SocketIO(app)

# login_manager = LoginManager()
# login_manager.init_app(app)
