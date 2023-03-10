from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
from passlib.hash import pbkdf2_sha256

from my_app.chat.models import User


class RegistrationForm(FlaskForm):
    """ Registration form"""

    username = StringField('username', validators=[InputRequired(message="Username required"), Length(min=4, max=25,
                                                                                                      message="Username must be between 4 and 25 characters")])
    password = PasswordField('password', validators=[InputRequired(message="Password required"), Length(min=4, max=25,
                                                                                                        message="Password must be between 4 and 25 characters")])
    confirm_pswd = PasswordField('confirm_pswd', validators=[InputRequired(message="Password required"),
                                                             EqualTo('password', message="Passwords must match")])
    request = StringField('request')
    def validate_username(self, username):
        user_object = User.query.filter_by(username=username.data).first()
        if user_object:
            raise ValidationError("Username already exists. Select a different username.")


class LoginForm(FlaskForm):
    """ Login form """
    username = StringField('username', validators=[InputRequired(message="Username required")])
    password = PasswordField('password', validators=[InputRequired(message="Password required")])
    submit_button = SubmitField('login')