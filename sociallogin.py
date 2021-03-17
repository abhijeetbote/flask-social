from flask import Flask, session, redirect, url_for, escape, request,render_template
from authlib.integrations.flask_client import OAuth

app = Flask(__name__,template_folder='template')
app.secret_key = "socialflask"
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="945356047879-5qdriqohgoo72dlasd1eao3g8tqa2pa0.apps.googleusercontent.com",
    client_secret="C5Qj62BrYVvAhRMVFVOI-eXH",
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/')
def hello_world():
    email = dict(session).get('email', None)
    return f'Hello, {email}!'
    
@app.route('/login')
def login():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    session["email"] = user_info['email'] 
    # do something with the token and profile
    return redirect('/')

@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
        return redirect('/')   


if __name__ == '__main__':
    app.run('127.0.0.1' , '8080', debug = True)