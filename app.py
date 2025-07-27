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

        return render_template_string(
            template, app_name="OAuth Application", provider_name=self.config.provider_name, custom_links=custom_links
        )

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
        display_name = (
            user_data.get("display_name")
            or user_data.get("name")
            or user_data.get("username")
            or user_data.get("email", "Unknown User")
        )

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

    # Add Spotify-specific functionality
    @app.require_auth
    def create_playlist():
        user_data = session.get("user_data", {})
        user_id = user_data.get("id")

        if not user_id:
            return "User ID not found. Please log in again."

        playlist_data = {"name": "Test Playlist", "description": "New playlist description", "public": False}

        try:
            response = app.make_api_request(
                f"https://api.spotify.com/v1/users/{user_id}/playlists",
                method="POST",
                json=playlist_data,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 201:
                return "Playlist created successfully!"
            else:
                return f"Failed to create playlist: {response.json()}"

        except Exception as e:
            return f"Error creating playlist: {str(e)}"

    # Register the custom route
    app.add_custom_route("/create_playlist", create_playlist, "Create Playlist")

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
