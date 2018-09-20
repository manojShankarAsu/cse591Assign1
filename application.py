from flask import Flask
from flask import request
from flask import render_template, flash, redirect, url_for
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_required
from flask_login import current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import UserMixin
import sqlite3
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField,TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
from hashlib import md5
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask import make_response


application = Flask(__name__)
application.config.from_object(Config)
db = SQLAlchemy(application)
migrate = Migrate(application, db)
login = LoginManager(application)
login.login_view = 'login'
bootstrap = Bootstrap(application)
moment = Moment(application)

action_type={"up vote":1,"down vote":"2","submit-button":3,"scroll":4,"doubleclick":5,"askQuestion":6,"questionClicked":7}


class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    logins = db.relationship('LoginHistory',backref='user',lazy='dynamic')
    actionlogs = db.relationship('ActionLogs',backref='user',lazy='dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')

class LoginHistory(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    timestamp = db.Column(db.DateTime,index=True,default=datetime.utcnow)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Loginss {}>'.format(self.timestamp)

class ActionLogs(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    clicktype=db.Column(db.Integer,index=True)
    timestamp=db.Column(db.DateTime,index=True,default=datetime.utcnow)
    context = db.Column(db.String(140))
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)



user = {'username': 'Manoj'}
# EB looks for an 'application' callable by default.

def create_tables():
    db.create_all()


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@application.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

# add a rule for the index page.

@application.route('/')
@application.route('/index')
@login_required
def index():
    return render_template('index.html', title='Home', user=user)

@application.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        log_entry=LoginHistory(timestamp=datetime.utcnow(),user_id=user.id)
        db.session.add(log_entry)
        db.session.commit()
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        resp = make_response(render_template('index.html', title='Home', user=user))
        resp.set_cookie('adaptive_user', user.username)
        return resp
    return render_template('login.html', title='Sign In', form=form)

@application.route('/logout')
def logout():
    logout_user()
    redir = redirect(url_for('index'))
    resp = make_response(redir)
    resp.set_cookie('adaptive_user','',expires=0)
    return resp

@application.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@application.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('user.html', user=user, posts=posts)

@application.route('/history/<username>')
@login_required
def history(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user is not None:
        logs = user.logins.order_by(LoginHistory.timestamp.desc()).offset(1)
    return render_template('user.html', user=user, logs=logs)

@application.route('/dataviz')
@login_required
def dataviz():
    if current_user.is_authenticated:
        return render_template('dataviz.html')
    return redirect(url_for('login'))


@application.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)
@application.route('/trackevents',methods=['POST'])
def trackevents():
    if current_user.is_authenticated:
        data = request.data
        data_str = data.decode("utf-8")
        params = data_str.split(';')
        clicktype = action_type.get(params[0],"click")
        contextval = params[0]
        if len(params) > 1:
            contextval = params[1]
        timeentry = datetime.utcnow()
        behav_log = ActionLogs(clicktype = clicktype,timestamp = timeentry, user_id=current_user.id,context=contextval)
        db.session.add(behav_log)
        db.session.commit()
        return "SUCCESS"

# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    application.debug = True
    create_tables()
    application.run()