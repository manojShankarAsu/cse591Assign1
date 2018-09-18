from flask import Flask
from flask import render_template
import sqlite3

sqlite_file = 'my_first_db.sqlite' 
table_name1 = 'table1'
col1 = 'col1'
ftype = 'TEXT'

conn = sqlite3.connect(sqlite_file)
c = conn.cursor()

# print a nice greeting.
def say_hello(username = "World"):
    return '<p>Hello %s!</p>\n' % username

# some bits of text for the page.
header_text = '''
    <html>\n<head> <title>EB Flask Test</title> </head>\n<body>'''
instructions = '''
    <p><em>Hint</em>: This is a MADE CHANGES RESTful web service! Append a username
    to the URL (for example: <code>/Thelonious</code>) to say hello to
    someone specific.</p>\n'''
home_link = '<p><a href="/">Back</a></p>\n'
footer_text = '</body>\n</html>'

user = {'username': 'Miguel'}

# EB looks for an 'application' callable by default.
application = Flask(__name__)

# add a rule for the index page.
application.add_url_rule('/', 'index', (lambda: render_template('index.html', title='Home', user=user)))

# add a rule when the page is accessed with a name appended to the site
# URL.
application.add_url_rule('/<username>', 'hello', (lambda username:
    header_text + say_hello(username) + home_link + footer_text))

# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    application.debug = True
    c.execute('CREATE TABLE {tn} ({nf} {ft})'.format(tn=table_name1, nf=col1, ft=ftype))
    conn.commit()
    try:
    c.execute("INSERT INTO {tn} ({cn}) VALUES ('test')".format(tn=table_name, cn=col1))
    except sqlite3.IntegrityError:
    print('ERROR: ID already exists in PRIMARY KEY column {}'.format(id_column))

    application.run()