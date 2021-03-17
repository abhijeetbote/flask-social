#LOGIN PAGE USING FACEBOOK AND GOOGLE AUTHENTICATION

#Modules
import os
import json
import flask
import requests_oauthlib
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
from flask import Flask, session, redirect, url_for, escape, request,render_template, flash
from flask_mysqldb import MySQL
from authlib.integrations.flask_client import OAuth


#initializing app as a flask app
app = Flask(__name__,template_folder='template')

#secret key for authentication
app.secret_key = "abhijeet"

#importing data from .json file
db_config_file = open(r'db.json')
jsondata = db_config_file.read()
obj = json.loads(jsondata)

#storing dictionary key values in variable which is extracted from .json file db.json
MySQL_host = (str(obj['mysql_host']))
MySQL_user = (str(obj['mysql_user']))
MySQL_password = (str(obj['mysql_password']))
MySQL_db = (str(obj['mysql_db']))

# Config db
app.config['MYSQL_HOST'] = MySQL_host
app.config['MYSQL_USER'] = MySQL_user
app.config['MYSQL_PASSWORD'] = MySQL_password
app.config['MYSQL_DB'] = MySQL_db

mysql = MySQL(app)

#home page for our app
@app.route('/')
def home():
    return render_template('home.html')

#login page for our app
@app.route("/login", methods = ['POST','GET'])
def login():
    return render_template('login.html')

#signup page for our app
@app.route("/signup", methods = ['POST','GET'])
def signup():
    return render_template('signup.html')

#login function for our app
@app.route('/success',methods = ['POST'])
def success():
    if request.method == 'POST':
        user = request.form['nm']
        password = request.form['am']
        mycursor = mysql.connection.cursor()
        print(user)
        print(password)
        mycursor.execute("select * from userdata where user_email = '" + user + "' and user_password = '" + password + "'")
        
        data = mycursor.fetchone()
        print(data)
        mysql.connection.commit()
        if data is None:
            return render_template('home.html')
        else:
            session['user'] = user
            return redirect(url_for('user'))   
        #return render_template('success.html')
    else:
        return render_template('login.html')

#signup function for our app
@app.route('/signupsuccess',methods = ['POST'])
def signupsuccess():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['pwd']
        mycursor = mysql.connection.cursor()
        mycursor.execute("insert into userdata (user_name,user_email,user_password)values(%s,%s,%s)", (name,email,password))
        mysql.connection.commit()
        print("success")
        session['user'] = email
        return redirect(url_for('login'))   
        #return render_template('success.html')
    else:
        return render_template('login.html')

#profile page for our app
@app.route("/profile",methods = ['POST','GET'])
def user():
    if "user" in session:
       user = session['user']
       return render_template('profile.html', content = user)
    else:
       return render_template('login.html')

#logout function for our app
@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        #flash("you have been loged out!","info")
        return redirect(url_for('login'))   
    elif "email" in session:
        #session.pop(key)
        session.pop("email", None)
        session.pop("userinfo", None)
        for key in list(session.keys()):
            session.pop(key)
        return redirect(url_for('home'))
    else:
        return '<p>User already logged out</p>'


#-----------------------------------------google signin-------------------------------------------------------

#Google Authentication required parameters
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="945356047879-u5q9gm37vgrfum4eehvs05jt25t6b8vk.apps.googleusercontent.com",
    client_secret="qufv-0TKYRqsCM5Fif1xFwvs",
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)

# Google Login route page    
@app.route('/google_login')
def google_login():
    if "email" not in session:
        google = oauth.create_client('google')
        redirect_uri = url_for('authorize', _external=True)
        return google.authorize_redirect(redirect_uri)
    else:
        return render_template('/home.html')

#google authrization function
@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    google_user_name = user_info["name"]
    # print(google_user_name)
    google_user_email = user_info["email"]
    # print(google_user_email)
    mycursor = mysql.connection.cursor()
    mycursor.execute("insert into userdata (user_name,user_email)values(%s,%s)", (google_user_name,google_user_email,))
    mysql.connection.commit()
    session["email"] = user_info['email'] 
    # do something with the token and profile
    return redirect('/google_homepage')


#Google home page
@app.route('/google_homepage')
def google_homepage():
    if "email" in session:
        email = dict(session).get('email', None)
        #return f'Hello, {email}!'
        return render_template("profile.html", content = email)
    else :
        return redirect(url_for('home'))


# @app.route('/google_logout')
# def google_logout():
#     if "email" in session:
#         #session.pop(key)
#         session.pop("email", None)
#         session.pop("userinfo", None)
#         for key in list(session.keys()):
#             session.pop(key)
#         return redirect(url_for('home.html'))
    

#-----------------------------------------facebook login------------------------------------------



# Your ngrok url, obtained after running "ngrok http 5000"
# URL = "https://679e4c83.ngrok.io"
URL = "https://flask-demo-social.herokuapp.com"

FB_CLIENT_ID = "1163520467436459"
FB_CLIENT_SECRET = "7633675af0971a60de63e0a5e0b961fc"

FB_AUTHORIZATION_BASE_URL = "https://www.facebook.com/dialog/oauth"
FB_TOKEN_URL = "https://graph.facebook.com/oauth/access_token"

FB_SCOPE = ["email"]

# This allows us to use a plain HTTP callback
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# facebook Login route page    
# @app.route('/facebook_login')
# def facebook_login():
#     return redirect(url_for("/fb_login"))

@app.route("/fb-login")
def fb_login():
    facebook = requests_oauthlib.OAuth2Session(
        FB_CLIENT_ID, redirect_uri=URL + "/fb-callback", scope=FB_SCOPE
    )
    authorization_url, _ = facebook.authorization_url(FB_AUTHORIZATION_BASE_URL)

    return flask.redirect(authorization_url)


@app.route("/fb-callback")
def callback():
    facebook = requests_oauthlib.OAuth2Session(
        FB_CLIENT_ID, scope=FB_SCOPE, redirect_uri=URL + "/fb-callback"
    )

    # we need to apply a fix for Facebook here
    facebook = facebook_compliance_fix(facebook)

    facebook.fetch_token(
        FB_TOKEN_URL,
        client_secret=FB_CLIENT_SECRET,
        authorization_response=flask.request.url,
    )

    # Fetch a protected resource, i.e. user profile, via Graph API

    facebook_user_data = facebook.get(
        "https://graph.facebook.com/me?fields=id,name,email,picture{url}"
    ).json()

    # Fb user data 
    email = facebook_user_data["email"]
    name = facebook_user_data["name"]
    picture_url = facebook_user_data.get("picture", {}).get("data", {}).get("url")
    # facebook user name and email store in db
    mycursor = mysql.connection.cursor()
    mycursor.execute("insert into userdata (user_name,user_email)values(%s,%s)", (name,email,))
    mysql.connection.commit()

    #login details
    return f"""
    User information: <br>
    Name: {name} <br>
    Email: {email} <br>
    Avatar <img src="{picture_url}"> <br>
    <a href="/">Home</a>
    """
if __name__ == '__main__':
    app.run(debug = True)