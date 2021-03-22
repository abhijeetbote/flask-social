#LOGIN PAGE USING FACEBOOK AND GOOGLE AUTHENTICATION

#Modules
import os
import json
import flask
import requests_oauthlib
import pandas as pd
import json
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
from flask import Flask, session, redirect, url_for, escape, request,render_template, flash,send_file
from flask_mysqldb import MySQL
from authlib.integrations.flask_client import OAuth

user_name = []
user_email = []
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

# return all unique user name
def get_user():
    a = set()
    data = pd.read_csv("users.csv")
    for i in data['email']:
        a.add(i)
    return a

# return password for login authentication
def get_pass(email):
    data = pd.read_csv("users.csv")
    pwd = data["password"].loc[data["email"] == email].iloc[0]
    print("password from get_pass",pwd)
    return pwd

# return user name for login authentication
def get_username(username):
    data = pd.read_csv("users.csv")
    username = data["username"].loc[data["email"] == username].iloc[0]
    print("username from get_pass",username)
    return username



#login function for our app login
@app.route('/success',methods = ['POST'])
def success():
    global user_name
    if request.method == 'POST':
        user = request.form['nm']
        pwd = request.form['am']
        user_data = get_user()
        if user in user_data:
            password = get_pass(user)
            
            # print(user_name)
        # print("password from login",str(password))
        # print("password from user", str(pwd))
            if pwd == password:
                session['user'] = user
                return redirect(url_for('user'))
            else:
                return render_template('login.html')
        else:return render_template('login.html')
    else:
        return render_template('login.html')

#signup function for our app signup
@app.route('/signupsuccess',methods = ['POST'])
def signupsuccess():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['pwd']
        get_user_email = get_user()
        print(get_user_email)
        if email in get_user_email:
            email = True
            return render_template("email_exist.html")
        else:
            data = pd.read_csv("users.csv")
            data1 = data.append({"username":name, "email":email,"password":password}, ignore_index=True)
            data1.to_csv("users.csv", index=False)
            email=email
            return render_template("/login.html",email=email)


    else:
        return render_template('login.html')

#profile page for our app
@app.route("/profile",methods = ['POST','GET'])
def user():
    global user_name
    if "user" in session:
       user = session['user']
       user_name = get_username(user)
    #    user_name = user_name
       return render_template('profile.html', content = user, user_name = user_name)
    else:
       return render_template('login.html')

def json_loads(dictionary,json_mode):
    json_object = json.dumps(dictionary, indent = 10)
    with open("sample.json", json_mode) as outfile: 
        outfile.write(json_object)

@app.route('/profile_json',methods = ['POST'])
def profile_json():
    global user_name
    user = session['user']
    user_name = get_username(user)

    if request.method == 'POST':
        dictionary ={ 
            "Name" : user_name, 
            "Email" : user, 
        } 
        print("dict2", dictionary)
        name = request.form.to_dict()
        print(name["altcontact"])
        if name["altcontact"] == "":
            name.pop("altcontact") #requesting form data from html profile form user details
        main_dict = {**dictionary, **name}
        json_mode = "w"
        json_loads(main_dict,json_mode)#calling function to dump data in json file
        # return render_template("education.html")
        return redirect(url_for('json_download_link')) 

       

@app.route("/json_download_link")
def json_download_link():
    p = "sample.json"
    return send_file(p,as_attachment = True)


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
    # google_picture_url = resp.get("picture", {}).get("data", {}).get("url")

    # print(google_user_email)
    # mycursor = mysql.connection.cursor()
    # mycursor.execute("insert into userdata (user_name,user_email)values(%s,%s)", (google_user_name,google_user_email,))
    # mysql.connection.commit()
    session["email"] = google_user_email
    session["name"] = google_user_name
    # do something with the token and profile
    return f"""
        User information: <br>
        Name: {google_user_name} <br>
        Email: {google_user_email} <br>
        <a href="/">Home</a>
        """


# #Google home page
# @app.route('/google_homepage')
# def google_homepage():
#     if "email" in session:
#         email = dict(session).get('email', None)
#         print(email)
#         g_name = dict(session).get('name', None)
#         print(g_name)
#         picture_url = facebook_user_data.get("picture", {}).get("data", {}).get("url")
#         #return f'Hello, {email}!'
#         return f"""
#         User information: <br>
#         Name: {name} <br>
#         Email: {email} <br>
#         Avatar <img src="{picture_url}"> <br>
#         <a href="/">Home</a>
#         """
#     else :
#         return redirect(url_for('home'))


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
    # mycursor = mysql.connection.cursor()
    # mycursor.execute("insert into userdata (user_name,user_email)values(%s,%s)", (name,email,))
    # mysql.connection.commit()

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