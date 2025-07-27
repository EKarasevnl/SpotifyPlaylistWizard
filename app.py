from flask import Flask, redirect, request, session
from flask_session import Session
import secrets
import urllib.parse
from dotenv import load_dotenv
import os
from base64 import b64encode
import requests

load_dotenv()
app = Flask(__name__)

app.secret_key = secrets.token_hex(32)  # Required for session security
app.config['SESSION_TYPE'] = 'filesystem'  # Stores sessions on server
Session(app)

# Configuration - move these to environment variables in production!
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
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
    scope = 'user-read-private user-read-email playlist-modify-public playlist-modify-private'
    
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
    
    token_url = 'https://accounts.spotify.com/api/token'
    auth_header = b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI
    }

    token_response = requests.post(token_url, headers=headers, data=data)
    token_data = token_response.json()

    access_token = token_data["access_token"]
    
    # Save token to session
    session['access_token'] = access_token

    # Fetch user profile data
    user_url = "https://api.spotify.com/v1/me"
    user_headers = {
        "Authorization": f"Bearer {access_token}"
    }

    user_response = requests.get(user_url, headers=user_headers)
    user_data = user_response.json()

    # Store user ID in session too (you need it in /create_playlist)
    session['user_id'] = user_data.get('id')

    return '''
    <h1>Success!</h1>
    <p>Logged in as {}</p>
    <a href="/create_playlist">Create Playlist</a>
    '''.format(user_data.get('display_name'))


@app.route('/create_playlist')
def create_playlist():
    access_token = session.get('access_token')
    user_id = session.get('user_id')

    if not access_token or not user_id:
        return "Missing access token or user ID. Please log in again."

    user_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    data = {
        "name": "Test Playlist",
        "description": "New playlist description",
        "public": False
    }

    response = requests.post(f"https://api.spotify.com/v1/users/{user_id}/playlists", headers=user_headers, json=data)

    if response.status_code == 201:
        return "Playlist created successfully!"
    else:
        return f"Failed to create playlist: {response.json()}"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(port=5000)