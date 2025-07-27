from flask import Flask, redirect, request
import secrets
import urllib.parse
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)

# Configuration - move these to environment variables in production!
CLIENT_ID = os.getenv("CLIENT_ID")
REDIRECT_URI = 'http://127.0.0.1:5000/callback'

@app.route('/')
def home():
    return '''
    <h1>Spotify Auth Example</h1>
    <a href="/login">Login with Spotify</a>
    '''

@app.route('/login')
def login():
    state = secrets.token_urlsafe(16)
    scope = 'user-read-private user-read-email'
    
    auth_url = 'https://accounts.spotify.com/authorize?' + urllib.parse.urlencode({
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'scope': scope,
        'redirect_uri': REDIRECT_URI,
        'state': state
    })
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    error = request.args.get('error')
    code = request.args.get('code')
    state = request.args.get('state')
    
    if error:
        return f"Authorization failed: {error}"
    
    # This is where you'd exchange the code for a token
    return f'''
    <h1>Success!</h1>
    <p>Authorization code: {code}</p>
    <p>State: {state}</p>
    '''

if __name__ == '__main__':
    app.run(port=5000)