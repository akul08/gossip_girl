from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, PasswordField
from wtforms.validators import Required


class LoginForm(FlaskForm):
    username = StringField('UserName', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('UserName', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Register')


class UpdateForm(FlaskForm):
    room = StringField('Room', validators=[Required()])
    update = StringField('update', validators=[Required()])
    submit = SubmitField('Register')

