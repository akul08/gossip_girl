from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms import PasswordField, SelectField, TextAreaField
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
    room = SelectField('Room', validators=[Required()], choices=[])
    update = TextAreaField('update', validators=[Required()])
    submit = SubmitField('Register')

