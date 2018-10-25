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
import json
import os
from os import listdir
import sys
import logging
from logging import Formatter,FileHandler
from elasticsearch import Elasticsearch
import pandas as pd
from pandas import DataFrame

application = Flask(__name__)
application.config.from_object(Config)
db = SQLAlchemy(application)
migrate = Migrate(application, db)
login = LoginManager(application)
login.login_view = 'login'
bootstrap = Bootstrap(application)
moment = Moment(application)
application.elasticsearch = Elasticsearch([application.config['ELASTICSEARCH_URL']]) \
        if application.config['ELASTICSEARCH_URL'] else None

action_type={"up vote":1,"down vote":"2","submit-button":3,"scroll":4,"doubleclick":5,"askQuestion":6,"questionClicked":7}
application.err_count = 0

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

class IndexedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))

    def __repr__(self):
        return '<File {}>'.format(self.name)


class JavaPost():
    def __init__(self, content , code,recommendation_list=[]):
        self.content = content
        self.code = code
        self.reclist = recommendation_list

user = {'username': 'Manoj'}
# EB looks for an 'application' callable by default.

def create_tables():
    db.create_all()

def getNoOfRows(user,click_type):
    rows=  user.actionlogs.filter_by(clicktype=click_type)
    if rows is not None:
        return rows.count()
    return 0

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
def index():
    java_posts = read_queries()
    return render_template('index.html', title='Home', posts =  java_posts)

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
    val = 'display'
    return render_template('user.html', user=user, value = val)

@application.route('/history/<username>')
@login_required
def history(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user is not None:
        logs = user.logins.order_by(LoginHistory.timestamp.desc()).offset(1)
    return render_template('user.html', user=user, logs=logs)

@application.route('/belogs/<username>')
@login_required
def belogs(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user is not None:
        logs = user.actionlogs.order_by(ActionLogs.timestamp.desc())
    return render_template('user.html', user=user, actions=logs)


@application.route('/dataviz')
@login_required
def dataviz():
    if current_user.is_authenticated:
        return render_template('dataviz.html')
    return redirect(url_for('login'))

@application.route('/socialviz')
@login_required
def socialviz():
    if current_user.is_authenticated:
        return render_template('socialviz.html')
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


@application.route('/getActionCounts',methods=['GET'])
def getActionCounts():
    if current_user.is_authenticated:
        data={}
        data['upvotes']=getNoOfRows(current_user,1)
        data['downvotes']=getNoOfRows(current_user,2)
        data['answers_posted']=getNoOfRows(current_user,3)
        data['pages']=getNoOfRows(current_user,4)
        data['ques_asked']=getNoOfRows(current_user,6)
        data['ques_clicked']=getNoOfRows(current_user,7)
        json_data = json.dumps(data)
        return json_data

@application.route('/getSocialCounts',methods=['GET'])
def getSocialCounts():
    if current_user.is_authenticated:
        data={}
        ukey=current_user.username+'_ques_clicked'
        ukey_asked=current_user.username+'_ques_asked'
        data[ukey]=getNoOfRows(current_user,7)
        data[ukey_asked]=getNoOfRows(current_user,6)
        others = User.query.filter(User.id != current_user.id).all()
        for u in others:
            key_asked = u.username+"_ques_asked"
            key2 = u.username+"_ques_clicked"
            data[key_asked]= getNoOfRows(u,6)
            data[key2]= getNoOfRows(u,7)
        json_data = json.dumps(data)
        return json_data


def crawl_files():
    pass

def add_file_to_index(files, directory, index_name):
    application.logger.info('Adding files to index')
    for file in files:
        filename = ''
        if "Oracle" in file:
            filename = 'oracle'
        else:
            filename = 'wikibooks'
        filename = filename + "_"+ file
        file_path = os.path.join(directory,file)
        file_obj = open(file_path,"r",encoding='utf-8')
        file_db = IndexedFile(name=file)
        db.session.add(file_db)
        db.session.commit()
        add_to_index(index_name,file_db.id,filename,file_obj)

def index_files():
    code_dir = os.path.join(os.getcwd(),"dataScrapped")
    application.logger.info(code_dir)
    files = os.listdir(code_dir)
    application.logger.info('Started FIle indexing  ')
    application.logger.info(code_dir)
    add_file_to_index(files , code_dir,'java2')
    application.logger.info('FIle indexing done ')
    application.logger.error('no of files not indexed ')
    application.logger.error(application.err_count)

# run the app.

def add_to_index(index, obj_id,filename,file_obj):
    if not application.elasticsearch:
        return    
    payload = {}
    settings = {}
    my_analyzer = {}
    my_analyzer['type'] = 'standard'
    my_analyzer['stopwords'] = '_english_'
    analysis = {}
    analysis['analyzer']=my_analyzer
    settings['analysis'] = analyzer
    #content = content.encode('utf-8')
    try:
        payload['text']=file_obj.read()
        payload['name']=filename
        application.elasticsearch.index(index=index, doc_type=index, id=obj_id,
                                    body=payload,settings=settings)
    except Exception as detail:
        application.logger.error('cannot index')
        application.logger.error(filename)
        application.logger.error(detail)
        application.err_count = application.err_count + 1
        pass

def remove_from_index(index, obj_id):
    if not application.elasticsearch:
        return
    application.elasticsearch.delete(index=index, doc_type=index, id=obj_id)

def query_index(index, query, page, per_page):
    if not application.elasticsearch:
        return [], 0
    search = application.elasticsearch.search(
        index=index, doc_type=index,
        body={'query': {'multi_match': {'query': query, 'fields': ['*']}},
              'from': (page - 1) * per_page, 'size': per_page})
    ids = [int(hit['_id']) for hit in search['hits']['hits']]
    return search

def read_queries():
    application.logger.info('Reading excel file ')
    query_dir = os.path.join(os.getcwd(),"queries")    
    files = os.listdir(query_dir)
    java_posts = []
    for excel in files:
        file_path = os.path.join(query_dir,excel)
        xl = pd.read_excel(file_path)
        xl['text'] = xl['text'].fillna('')
        xl['code'] = xl['code'].fillna('')
        for index, row in xl.iterrows():            
            java_post = JavaPost(row['text'],row['code'],[])
            java_posts.append(java_post)
            # print('Text')
            # print(row['text'])
            # print("Search result")
            # print(query_index('java2',row['text'],1,10))
            # print('Code')
            # print(row['code'])
            # print("Search result")
            # print(query_index('java2',row['code'],1,10))
    return java_posts

if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    application.debug = True
    #create_tables()
    file_handler = FileHandler('info.log')
    handler = logging.StreamHandler()
    file_handler.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
     ))
    handler.setFormatter(Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
     ))
    application.logger.addHandler(handler)
    application.logger.addHandler(file_handler)
    crawl_files()
    #index_files()
    #read_queries()
    application.run(debug=True)
