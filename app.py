import os
import secrets
import urllib.parse
from base64 import b64encode
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import requests
from dotenv import load_dotenv
from flask import Flask, redirect, render_template_string, request, session

from flask_session import Session
from llm_search import get_song_recommendations_from_llm


@dataclass
class OAuthConfig:
    """Configuration for OAuth provider"""

    client_id: str
    client_secret: str
    auth_url: str
    token_url: str
    user_info_url: str
    redirect_uri: str
    scopes: List[str]
    provider_name: str = "OAuth Provider"


class OAuthFlaskApp:
    """Generic OAuth Flask application"""

    def __init__(self, oauth_config: OAuthConfig, app_name: str = "OAuth App"):
        load_dotenv()

        self.config = oauth_config
        self.app = Flask(app_name)
        self.app.secret_key = secrets.token_hex(32)
        self.app.config["SESSION_TYPE"] = "filesystem"
        Session(self.app)

        # Storage for custom callbacks
        self.post_auth_callbacks: List[Callable] = []
        self.custom_routes: Dict[str, Callable] = {}

        self._setup_routes()

    def _setup_routes(self):
        """Setup default OAuth routes"""
        self.app.add_url_rule("/", "home", self.home)
        self.app.add_url_rule("/login", "login", self.login)
        self.app.add_url_rule("/callback", "callback", self.callback)
        self.app.add_url_rule("/logout", "logout", self.logout)

    def home(self):
        """Home page with login link"""
        template = """
        <h1>{{ app_name }}</h1>
        <p>Connect with {{ provider_name }}</p>
        <a href="/login">Login with {{ provider_name }}</a>
        {% if custom_links %}
            <h3>Available Actions:</h3>
            <ul>
            {% for link_text, route in custom_links %}
                <li><a href="{{ route }}">{{ link_text }}</a></li>
            {% endfor %}
            </ul>
        {% endif %}
        """

        custom_links = [(text, route) for route, text in self.custom_routes.items()]

        return render_template_string(template, app_name="OAuth Application", provider_name=self.config.provider_name, custom_links=custom_links)

    def login(self):
        """Initiate OAuth login flow"""
        state = secrets.token_urlsafe(16)
        session["oauth_state"] = state

        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "scope": " ".join(self.config.scopes),
            "redirect_uri": self.config.redirect_uri,
            "state": state,
        }

        auth_url = f"{self.config.auth_url}?{urllib.parse.urlencode(params)}"
        return redirect(auth_url)

    def callback(self):
        """Handle OAuth callback"""
        error = request.args.get("error")
        code = request.args.get("code")
        state = request.args.get("state")

        # Verify state parameter
        if state != session.get("oauth_state"):
            return "Invalid state parameter", 400

        if error:
            return f"Authorization failed: {error}", 400

        if not code:
            return "No authorization code received", 400

        # Exchange code for token
        try:
            token_data = self._exchange_code_for_token(code)
            access_token = token_data["access_token"]

            # Store token in session
            session["access_token"] = access_token
            session["token_data"] = token_data

            # Get user info
            user_data = self._get_user_info(access_token)
            session["user_data"] = user_data

            # Run post-auth callbacks
            for callback in self.post_auth_callbacks:
                callback(access_token, user_data)

            return self._success_page(user_data)

        except Exception as e:
            return f"Authentication error: {str(e)}", 500

    def _exchange_code_for_token(self, code: str) -> Dict[str, Any]:
        """Exchange authorization code for access token"""
        auth_header = b64encode(f"{self.config.client_id}:{self.config.client_secret}".encode()).decode()

        headers = {"Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"}

        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.config.redirect_uri}

        response = requests.post(self.config.token_url, headers=headers, data=data)
        response.raise_for_status()
        return response.json()

    def _get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from OAuth provider"""
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(self.config.user_info_url, headers=headers)
        response.raise_for_status()
        return response.json()

    def _success_page(self, user_data: Dict[str, Any]) -> str:
        """Generate success page after authentication"""
        template = """
        <h1>Success!</h1>
        <p>Logged in as {{ user_display_name }}</p>
        <a href="/">Home</a> | <a href="/logout">Logout</a>
        {% if custom_links %}
            <h3>Available Actions:</h3>
            <ul>
            {% for link_text, route in custom_links %}
                <li><a href="{{ route }}">{{ link_text }}</a></li>
            {% endfor %}
            </ul>
        {% endif %}
        """

        # Try common display name fields
        display_name = user_data.get("display_name") or user_data.get("name") or user_data.get("username") or user_data.get("email", "Unknown User")

        custom_links = [(text, route) for route, text in self.custom_routes.items()]

        return render_template_string(template, user_display_name=display_name, custom_links=custom_links)

    def logout(self):
        """Clear session and logout"""
        session.clear()
        return redirect("/")

    def add_post_auth_callback(self, callback: Callable):
        """Add a callback to run after successful authentication"""
        self.post_auth_callbacks.append(callback)

    def add_custom_route(self, route: str, handler: Callable, link_text: str = None):
        """Add a custom route to the application"""
        self.app.add_url_rule(route, route.replace("/", "_"), handler)
        if link_text:
            self.custom_routes[route] = link_text

    def require_auth(self, f):
        """Decorator to require authentication for a route"""

        def wrapper(*args, **kwargs):
            if not session.get("access_token"):
                return redirect("/login")
            return f(*args, **kwargs)

        wrapper.__name__ = f.__name__
        return wrapper

    def get_api_headers(self) -> Optional[Dict[str, str]]:
        """Get headers for API requests"""
        access_token = session.get("access_token")
        if not access_token:
            return None
        return {"Authorization": f"Bearer {access_token}"}

    def make_api_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        """Make an authenticated API request"""
        headers = self.get_api_headers()
        if not headers:
            raise Exception("Not authenticated")

        if "headers" in kwargs:
            kwargs["headers"].update(headers)
        else:
            kwargs["headers"] = headers

        return requests.request(method, url, **kwargs)

    def run(self, **kwargs):
        """Run the Flask application"""
        self.app.run(**kwargs)


# Spotify-specific implementation
def create_spotify_app() -> OAuthFlaskApp:
    """Create a Spotify OAuth application"""
    spotify_config = OAuthConfig(
        client_id=os.getenv("CLIENT_ID"),
        client_secret=os.getenv("CLIENT_SECRET"),
        auth_url="https://accounts.spotify.com/authorize",
        token_url="https://accounts.spotify.com/api/token",
        user_info_url="https://api.spotify.com/v1/me",
        redirect_uri=os.getenv("REDIRECT_URI", "http://127.0.0.1:5000/callback"),
        scopes=["user-read-private", "user-read-email", "playlist-modify-public", "playlist-modify-private"],
        provider_name="Spotify",
    )

    app = OAuthFlaskApp(spotify_config, "Spotify OAuth App")

    @app.require_auth
    def create_playlist():
        """Create a playlist with form input"""
        if request.method == "GET":
            # Show the form
            user_data = session.get("user_data", {})
            user_id = user_data.get("id")

            return f"""
            <h2>Create a New Playlist</h2>
            <p><strong>Creating playlist for user:</strong> {user_data.get('display_name', 'Unknown')} (ID: {user_id})</p>
            <form method="POST">
                <p>
                    <label for="name">Playlist Name:</label><br>
                    <input type="text" id="name" name="name" required>
                </p>
                <p>
                    <label for="description">Description (optional):</label><br>
                    <textarea id="description" name="description" rows="3" cols="50"></textarea>
                </p>
                <p>
                    <label for="public">Playlist Visibility:</label><br>
                    <input type="radio" id="private" name="public" value="false" checked>
                    <label for="private">Private</label><br>
                    <input type="radio" id="public" name="public" value="true">
                    <label for="public">Public</label>
                </p>
                <p>
                    <input type="submit" value="Create Playlist">
                </p>
            </form>
            <a href="/">Back to Home</a>
            """

        # Handle POST request (form submission)
        name_playlist = request.form.get("name")
        description = request.form.get("description", "")
        is_public = request.form.get("public", "false") == "true"

        if not name_playlist:
            return "Playlist name is required!"

        user_data = session.get("user_data", {})
        user_id = user_data.get("id")

        if not user_id:
            return "User ID not found. Please log in again."

        # Create playlist data
        playlist_data = {"name": name_playlist, "description": description, "public": is_public}

        try:
            response = app.make_api_request(f"https://api.spotify.com/v1/users/{user_id}/playlists", method="POST", json=playlist_data)

            if response.status_code == 201:
                playlist_info = response.json()

                # Verify ownership
                created_owner_id = playlist_info.get("owner", {}).get("id")
                ownership_status = "✅ OWNED BY YOU" if created_owner_id == user_id else f"❌ OWNED BY: {created_owner_id}"

                return f"""
                <h2>Success!</h2>
                <p>Playlist "{name_playlist}" created successfully!</p>
                <p><strong>Ownership Status:</strong> {ownership_status}</p>
                <p><strong>Playlist ID:</strong> {playlist_info.get('id')}</p>
                <p><strong>Visibility:</strong> {'Public' if playlist_info.get('public') else 'Private'}</p>
                <p><a href="{playlist_info.get('external_urls', {}).get('spotify', '#')}" target="_blank">Open in Spotify</a></p>
                
                <h3>Debug Info:</h3>
                <details>
                    <summary>Click to see full API response</summary>
                    <pre style="background-color: #f0f0f0; padding: 10px; overflow-x: auto;">
    {response.text}
                    </pre>
                </details>
                
                <br>
                <a href="/create_playlist">Create Another</a> | 
                <a href="/debug_playlists">Check All Playlists</a> | 
                <a href="/add_song_to_playlist">Add Songs to This Playlist</a> | 
                <a href="/">Home</a>
                """
            else:
                return f"""
                <h2>Failed to create playlist</h2>
                <p><strong>Status Code:</strong> {response.status_code}</p>
                <p><strong>Error:</strong> {response.text}</p>
                <p><strong>Your User ID:</strong> {user_id}</p>
                <a href="/create_playlist">Try Again</a> | <a href="/">Home</a>
                """

        except Exception as e:
            return f"""
            <h2>Error creating playlist</h2>
            <p><strong>Error:</strong> {str(e)}</p>
            <p><strong>Your User ID:</strong> {user_id}</p>
            <a href="/create_playlist">Try Again</a> | <a href="/">Home</a>
            """

    @app.require_auth
    def add_song_to_playlist():
        """Search for a song and add it to a selected playlist"""

        user_data = session.get("user_data", {})
        user_id = user_data.get("id")
        # Get user's playlists first
        try:
            playlists_response = app.make_api_request(f"https://api.spotify.com/v1/users/{user_id}/playlists")
            if playlists_response.status_code != 200:
                return "Failed to load playlists"

            user_playlists = playlists_response.json().get("items", [])
            # Filter to only show playlists the user owns (can modify)

            owned_playlists = [p for p in user_playlists]

        except Exception as e:
            return f"Error loading playlists: {str(e)}"

        # Get form parameters
        song_query = request.form.get("song_query") or request.args.get("q", "")
        selected_playlist = request.form.get("playlist_id")
        selected_track = request.form.get("track_uri")

        # Step 1: Show search form if no query
        if not song_query:
            playlist_options = ""
            for playlist in owned_playlists:
                playlist_options += f'<option value="{playlist["id"]}">{playlist["name"]}</option>'

            return f"""
            <h2>Add Song to Playlist</h2>
            <form method="POST">
                <p>
                    <label for="song_query">Search for a song:</label><br>
                    <input type="text" id="song_query" name="song_query" placeholder="Enter song name or artist" required>
                </p>
                <p>
                    <label for="playlist_id">Select playlist:</label><br>
                    <select id="playlist_id" name="playlist_id" required>
                        <option value="">Choose a playlist...</option>
                        {playlist_options}
                    </select>
                </p>
                <p>
                    <input type="submit" value="Search Songs">
                </p>
            </form>
            <a href="/">Back to Home</a>
            """

        # Step 2: If we have a track selected, add it to the playlist
        if selected_track and selected_playlist:
            try:
                add_response = app.make_api_request(
                    f"https://api.spotify.com/v1/playlists/{selected_playlist}/tracks",
                    method="POST",
                    json={"uris": [selected_track]},
                    headers={"Content-Type": "application/json"},
                )

                if add_response.status_code == 201:
                    # Get playlist name for confirmation
                    playlist_name = next((p["name"] for p in owned_playlists if p["id"] == selected_playlist), "Unknown")
                    return f"""
                    <h2>Success!</h2>
                    <p>Song added to playlist "{playlist_name}" successfully!</p>
                    <a href="/add_song_to_playlist">Add Another Song</a> | <a href="/">Home</a>
                    """
                else:
                    return f"Failed to add song to playlist: {add_response.json()}"

            except Exception as e:
                return f"Error adding song to playlist: {str(e)}"

        # Step 3: Show search results with add buttons
        if song_query and selected_playlist:
            try:
                search_params = {"q": song_query, "type": "track", "limit": 15}

                response = app.make_api_request("https://api.spotify.com/v1/search", method="GET", params=search_params)

                if response.status_code == 200:
                    search_results = response.json()
                    tracks = search_results.get("tracks", {}).get("items", [])

                    if not tracks:
                        return f"""
                        <h2>No Results Found</h2>
                        <p>No songs found for "{song_query}"</p>
                        <a href="/add_song_to_playlist">Search Again</a> | <a href="/">Home</a>
                        """

                    # Get selected playlist name
                    playlist_name = next((p["name"] for p in owned_playlists if p["id"] == selected_playlist), "Unknown")

                    # Format results with add buttons
                    results_html = f"""
                    <h2>Search Results for '{song_query}'</h2>
                    <h3>Adding to playlist: {playlist_name}</h3>
                    <div style="margin-bottom: 20px;">
                    """

                    for track in tracks:
                        artist_names = ", ".join([artist["name"] for artist in track["artists"]])
                        album_name = track["album"]["name"]
                        track_name = track["name"]
                        track_uri = track["uri"]
                        spotify_url = track["external_urls"]["spotify"]

                        results_html += f"""
                        <div style="border: 1px solid #ccc; margin: 10px 0; padding: 10px;">
                            <strong>{track_name}</strong> by {artist_names}<br>
                            Album: {album_name}<br>
                            <a href="{spotify_url}" target="_blank">Preview in Spotify</a><br><br>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="song_query" value="{song_query}">
                                <input type="hidden" name="playlist_id" value="{selected_playlist}">
                                <input type="hidden" name="track_uri" value="{track_uri}">
                                <button type="submit" style="background-color: #1DB954; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                                    Add to Playlist
                                </button>
                            </form>
                        </div>
                        """

                    results_html += """
                    </div>
                    <a href="/add_song_to_playlist">New Search</a> | <a href="/">Home</a>
                    """

                    return results_html
                else:
                    return f"Failed to search songs: {response.json()}"

            except Exception as e:
                return f"Error searching for songs: {str(e)}"

    @app.require_auth
    def compile_songs_to_playlist():
        """Compile songs using LLM and add to a playlist."""
        if request.method == "GET":
            # Show the form for playlist generation
            return """
            <h2>Generate Playlist with AI</h2>
            <form method="POST">
                <p>
                    <label for="prompt">Describe your playlist:</label><br>
                    <textarea id="prompt" name="prompt" rows="3" cols="50" required 
                        placeholder="e.g., 'Upbeat workout songs from the 2000s' or 'Chill jazz for studying'"></textarea>
                </p>
                <p>
                    <label for="playlist_name">Playlist Name:</label><br>
                    <input type="text" id="playlist_name" name="playlist_name" required>
                </p>
                <p>
                    <label for="num_songs">Number of Songs (5-50):</label><br>
                    <input type="number" id="num_songs" name="num_songs" min="5" max="50" value="15">
                </p>
                <p>
                    <input type="submit" value="Generate Playlist">
                </p>
            </form>
            <a href="/">Back to Home</a>
            """

        # Handle POST request
        prompt = request.form.get("prompt")
        playlist_name = request.form.get("playlist_name")
        num_songs = int(request.form.get("num_songs", 15))
        user_data = session.get("user_data", {})
        user_id = user_data.get("id")

        if not all([prompt, playlist_name, user_id]):
            return "Missing required parameters", 400

        try:
            # Step 1: Get song recommendations from LLM
            songs = get_song_recommendations_from_llm(model="gemma3:4b", prompt=prompt, num_songs=num_songs)

            if not songs:
                return "Failed to get song recommendations from AI", 500

            # Step 2: Search for each song on Spotify
            track_uris = []
            not_found = []

            for song in songs:
                track_uri = search_spotify_track(app, song)
                if track_uri:
                    track_uris.append(track_uri)
                else:
                    not_found.append(song)

            if not track_uris:
                return "None of the recommended songs were found on Spotify", 404

            # Step 3: Create the playlist
            playlist_data = {"name": playlist_name, "description": f"AI-generated playlist based on: '{prompt}'", "public": True}

            playlist_response = app.make_api_request(f"https://api.spotify.com/v1/users/{user_id}/playlists", method="POST", json=playlist_data)

            if playlist_response.status_code != 201:
                return f"Failed to create playlist: {playlist_response.text}", 500

            playlist_id = playlist_response.json().get("id")

            # Step 4: Add tracks to playlist
            add_response = app.make_api_request(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", method="POST", json={"uris": track_uris})

            if add_response.status_code != 201:
                return f"Playlist created but failed to add songs: {add_response.text}", 500

            # Success response
            playlist_info = playlist_response.json()
            success_html = f"""
            <h2>Playlist Created Successfully!</h2>
            <p><strong>Name:</strong> {playlist_name}</p>
            <p><strong>Based on:</strong> "{prompt}"</p>
            <p><strong>Songs added:</strong> {len(track_uris)}/{len(songs)}</p>
            """

            if not_found:
                success_html += f"""
                <details>
                    <summary>Songs not found on Spotify ({len(not_found)})</summary>
                    <ul>
                        {"".join(f"<li>{song}</li>" for song in not_found)}
                    </ul>
                </details>
                """

            success_html += f"""
            <p><a href="{playlist_info.get('external_urls', {}).get('spotify', '#')}" target="_blank">
                Open Playlist in Spotify
            </a></p>
            <a href="/compile_songs_to_playlist">Create Another</a> | <a href="/">Home</a>
            """

            return success_html

        except Exception as e:
            return f"Error generating playlist: {str(e)}", 500

    def search_spotify_track(app: OAuthFlaskApp, song_query: str) -> Optional[str]:
        """Search for a track on Spotify and return its URI"""
        try:
            search_params = {"q": song_query, "type": "track", "limit": 1}

            response = app.make_api_request("https://api.spotify.com/v1/search", method="GET", params=search_params)

            if response.status_code == 200:
                tracks = response.json().get("tracks", {}).get("items", [])
                if tracks:
                    return tracks[0].get("uri")
            return None

        except Exception:
            return None

    # Register the custom routes with support for both GET and POST methods
    app.app.add_url_rule("/create_playlist", "create_playlist", create_playlist, methods=["GET", "POST"])
    app.custom_routes["/create_playlist"] = "Create Playlist"

    app.app.add_url_rule("/add_song_to_playlist", "add_song_to_playlist", add_song_to_playlist, methods=["GET", "POST"])
    app.custom_routes["/add_song_to_playlist"] = "Add Song to Playlist"

    # Register the new route
    app.app.add_url_rule("/compile_playlist", "compile_songs_to_playlist", compile_songs_to_playlist, methods=["GET", "POST"])
    app.custom_routes["/compile_playlist"] = "Generate AI Playlist"

    return app


# Example usage for other OAuth providers
def create_github_app() -> OAuthFlaskApp:
    """Create a GitHub OAuth application example"""
    github_config = OAuthConfig(
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        auth_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        user_info_url="https://api.github.com/user",
        redirect_uri=os.getenv("GITHUB_REDIRECT_URI", "http://127.0.0.1:5000/callback"),
        scopes=["user:email", "repo"],
        provider_name="GitHub",
    )

    return OAuthFlaskApp(github_config, "GitHub OAuth App")


if __name__ == "__main__":
    # Create and run Spotify app
    spotify_app = create_spotify_app()
    spotify_app.run(port=5000, debug=True)
